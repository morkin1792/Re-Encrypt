package reencrypt;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * JSON serialization for patterns and settings.
 *
 * <p>
 * Used for two things: the on-disk export/import files, and Re:Encrypt's own persistence. Keeping
 * both on one format means the exchange code is exercised on every save instead of only when someone
 * clicks Export, and it keeps Java serialization (and its serialVersionUID fragility) out of the
 * extension entirely.
 * </p>
 */
public class ConfigJson {

    public static final int FORMAT_VERSION = 1;

    private static final String VERSION_KEY = "reencrypt";
    /**
     * Files are read and edited by hand (and by agents), so they are written indented. Persistence
     * stays compact - it is a blob in Burp's project file that nobody reads. Parsing does not care
     * either way, so a hand-minified file imports fine.
     */
    private static final Gson PRETTY = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
    /**
     * engineParams entries blanked when exporting with "strip secrets". Matched by exact name: a
     * substring match would also blank keyFormat/ivFormat/keySource, which are settings rather than
     * secrets, and an import would silently fall back to their defaults.
     */
    private static final Set<String> SECRET_PARAMS = Set.of("key", "iv", "privateKey", "jweEncryptedKey");

    /** A pattern plus the list it belongs to. The list is implicit in persistence, explicit in a file. */
    public static class ImportedPattern {
        public final CapturePattern pattern;
        public final boolean isRequest;

        public ImportedPattern(CapturePattern pattern, boolean isRequest) {
            this.pattern = pattern;
            this.isRequest = isRequest;
        }
    }

    public static class ImportResult {
        public final List<ImportedPattern> patterns = new ArrayList<>();
        public final Map<String, Object> settings = new LinkedHashMap<>();
        /** Per-pattern problems. A bad entry is skipped; the rest of the file still imports. */
        public final List<String> errors = new ArrayList<>();
        public boolean hasPatterns;
        public boolean hasSettings;
    }

    // ---------------------------------------------------------------- persistence

    /** Serialize one pattern list. Used for persistence, where the request/response split is the key. */
    public static String listToJson(List<CapturePattern> patterns) {
        JsonArray array = new JsonArray();
        for (CapturePattern pattern : patterns) {
            array.add(toNode(pattern, false, false));
        }
        return array.toString();
    }

    /** Parse one pattern list. Throws if the text is not a JSON array; skips individual bad entries. */
    public static ArrayList<CapturePattern> listFromJson(String json) {
        ArrayList<CapturePattern> result = new ArrayList<>();
        JsonArray array = JsonParser.parseString(json).getAsJsonArray();
        for (JsonElement node : array) {
            CapturePattern pattern = fromNode(node.getAsJsonObject(), new ArrayList<>());
            if (pattern != null) {
                result.add(pattern);
            }
        }
        return result;
    }

    // ---------------------------------------------------------------- exchange files

    /**
     * Build an export file.
     *
     * @param settings     the settings block, or null for a patterns-only export
     * @param stripSecrets blank engineParams values that look like key material
     */
    public static String toFile(List<ImportedPattern> items, Map<String, Object> settings, boolean stripSecrets) {
        JsonObject root = new JsonObject();
        root.addProperty(VERSION_KEY, FORMAT_VERSION);
        root.addProperty("exported", java.time.Instant.now().toString());

        JsonArray array = new JsonArray();
        for (ImportedPattern item : items) {
            JsonObject node = toNode(item.pattern, true, stripSecrets);
            addBoolean(node, "isRequest", item.isRequest);
            array.add(node);
        }
        root.add("patterns", array);

        if (settings != null) {
            JsonObject settingsNode = new JsonObject();
            for (Map.Entry<String, Object> entry : settings.entrySet()) {
                putValue(settingsNode, entry.getKey(), entry.getValue());
            }
            root.add("settings", settingsNode);
        }
        return PRETTY.toJson(root);
    }

    /** Parse an export file. Throws only when the file is unusable as a whole. */
    public static ImportResult fromFile(String json) {
        ImportResult result = new ImportResult();
        JsonObject root = JsonParser.parseString(json).getAsJsonObject();

        if (!root.has(VERSION_KEY)) {
            throw new IllegalArgumentException("Not a Re:Encrypt file (missing \"" + VERSION_KEY + "\" key).");
        }
        long version = root.get(VERSION_KEY).getAsLong();
        if (version > FORMAT_VERSION) {
            throw new IllegalArgumentException("File format version " + version
                    + " is newer than this version of Re:Encrypt supports (" + FORMAT_VERSION + ").");
        }

        if (root.has("patterns")) {
            result.hasPatterns = true;
            for (JsonElement node : root.getAsJsonArray("patterns")) {
                JsonObject object = node.getAsJsonObject();
                CapturePattern pattern = fromNode(object, result.errors);
                if (pattern != null) {
                    boolean isRequest = bool(object, "isRequest", true);
                    result.patterns.add(new ImportedPattern(pattern, isRequest));
                }
            }
        }

        if (root.has("settings")) {
            result.hasSettings = true;
            JsonObject settingsNode = root.getAsJsonObject("settings");
            for (Map.Entry<String, JsonElement> entry : settingsNode.entrySet()) {
                JsonElement value = entry.getValue();
                if (!value.isJsonPrimitive()) {
                    continue; // unknown shape: ignore, same as an unknown key
                }
                com.google.gson.JsonPrimitive primitive = value.getAsJsonPrimitive();
                if (primitive.isBoolean()) {
                    result.settings.put(entry.getKey(), primitive.getAsBoolean());
                } else if (primitive.isNumber()) {
                    result.settings.put(entry.getKey(), primitive.getAsInt());
                } else {
                    result.settings.put(entry.getKey(), primitive.getAsString());
                }
                // anything else is ignored, same as an unknown key
            }
        }
        return result;
    }

    // ---------------------------------------------------------------- mapping

    private static JsonObject toNode(CapturePattern pattern, boolean forExport, boolean stripSecrets) {
        JsonObject node = new JsonObject();
        addString(node, "name", nullToEmpty(pattern.name));
        if (!forExport) {
            // In a file the enabled state is the importer's decision ("Enable imported patterns"),
            // so an exchange file carries no opinion about it. Persistence still needs it.
            addBoolean(node, "enabled", pattern.enabled);
        }
        addBoolean(node, "patchProxy", pattern.patchProxy);
        addString(node, "patternType",
                pattern.patternType == null ? PatternType.CUSTOM_REGEX.name() : pattern.patternType.name());
        addString(node, "patternInput", nullToEmpty(pattern.patternInput));
        addString(node, "captureRegex", nullToEmpty(pattern.captureRegex));
        addString(node, "decCommand", nullToEmpty(pattern.decCommand));
        addString(node, "encCommand", nullToEmpty(pattern.encCommand));
        addBoolean(node, "useCacheSystem", pattern.useCacheSystem);
        addBoolean(node, "saveToLog", pattern.saveToLog);
        addBoolean(node, "detectGarbage", pattern.detectGarbage);

        // "Project In-Scope" resolves against the receiving Burp project's Target scope, which a file
        // cannot carry - the same export would mean something different for every recipient. Export it
        // as "Everything" instead, so the behaviour is at least predictable and visible.
        if (forExport && pattern.useProjectScope) {
            addBoolean(node, "useProjectScope", false);
            addString(node, "urlTargetRegex", "");
        } else {
            addBoolean(node, "useProjectScope", pattern.useProjectScope);
            addString(node, "urlTargetRegex", nullToEmpty(pattern.urlTargetRegex));
        }

        if (pattern.engineId != null) {
            addString(node, "engineId", pattern.engineId);
        }
        if (pattern.engineParams != null) {
            JsonObject params = new JsonObject();
            for (Map.Entry<String, String> entry : pattern.engineParams.entrySet()) {
                boolean secret = stripSecrets && SECRET_PARAMS.contains(entry.getKey());
                addString(params, entry.getKey(), secret ? "" : nullToEmpty(entry.getValue()));
            }
            node.add("engineParams", params);
            if (stripSecrets) {
                addBoolean(node, "secretsStripped", true);
            }
        }
        return node;
    }

    /** @return null when the entry is unusable; the reason is appended to {@code errors}. */
    private static CapturePattern fromNode(JsonObject node, List<String> errors) {
        String name = string(node, "name", "");
        PatternType patternType;
        try {
            patternType = PatternType.valueOf(string(node, "patternType", PatternType.CUSTOM_REGEX.name()));
        } catch (IllegalArgumentException e) {
            errors.add("Pattern \"" + name + "\": unknown patternType \"" + string(node, "patternType", "") + "\".");
            return null;
        }

        CapturePattern pattern = new CapturePattern(
                name,
                string(node, "captureRegex", ""),
                string(node, "urlTargetRegex", ""),
                string(node, "decCommand", ""),
                string(node, "encCommand", ""),
                // Absent in exchange files: the import dialog overrides this with its checkbox, and
                // auto-load has no prompt, so a file dropped in by a producer takes effect.
                bool(node, "enabled", true),
                bool(node, "patchProxy", false),
                bool(node, "useCacheSystem", false),
                bool(node, "saveToLog", false),
                bool(node, "useProjectScope", false),
                patternType,
                string(node, "patternInput", ""));

        pattern.engineId = string(node, "engineId", null);
        if (node.has("engineParams") && node.get("engineParams").isJsonObject()) {
            HashMap<String, String> params = new HashMap<>();
            for (Map.Entry<String, JsonElement> entry : node.getAsJsonObject("engineParams").entrySet()) {
                params.put(entry.getKey(), entry.getValue().isJsonPrimitive() ? entry.getValue().getAsString() : "");
            }
            pattern.engineParams = params;
        }
        pattern.detectGarbage = bool(node, "detectGarbage", true);
        return pattern;
    }

    private static void putValue(JsonObject node, String key, Object value) {
        if (value instanceof Boolean) {
            addBoolean(node, key, (Boolean) value);
        } else if (value instanceof Number) {
            node.addProperty(key, (Number) value);
        } else if (value != null) {
            addString(node, key, value.toString());
        }
    }

    private static void addString(JsonObject node, String key, String value) {
        node.addProperty(key, value);
    }

    private static void addBoolean(JsonObject node, String key, boolean value) {
        node.addProperty(key, value);
    }

    private static String string(JsonObject node, String key, String defaultValue) {
        if (!node.has(key) || !node.get(key).isJsonPrimitive()) {
            return defaultValue;
        }
        return node.get(key).getAsString();
    }

    private static boolean bool(JsonObject node, String key, boolean defaultValue) {
        JsonElement value = node.get(key);
        if (value == null || !value.isJsonPrimitive() || !value.getAsJsonPrimitive().isBoolean()) {
            return defaultValue;
        }
        return value.getAsBoolean();
    }

    private static String nullToEmpty(String value) {
        return value == null ? "" : value;
    }
}
