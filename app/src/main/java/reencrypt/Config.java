package reencrypt;

import java.awt.Color;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Date;

import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.persistence.Persistence;

public class Config {
    public static final String fileMarker = "{FILE}";
    public static final String dataMarker = "{DATA}";
    private static final String PATTERNS_KEY = "patterns";

    /**
     * Every pattern, request and response together, in the order the settings table shows them.
     * Order is the user's, so it is kept exactly as-is through save, export and import; which half of
     * the exchange a pattern applies to is {@link CapturePattern#isRequest()}.
     */
    ArrayList<CapturePattern> patterns;
    /** Non-fatal problems hit while loading persisted data, reported by App once the API is available. */
    private final ArrayList<String> loadErrors = new ArrayList<>();
    File logFile;
    BufferedWriter logWriter;
    String logFilePath;
    boolean enableRequestPrintEditor, enableResponsePrintEditor, escapeRequestDoubleQuotes, escapeResponseDoubleQuotes,
            highlightRequestPrintEditor, highlightResponsePrintEditor, reloadRequestEditors, reloadResponseEditors;
    Color reqPrintEditorHighlightColor, resPrintEditorHighlightColor;
    PersistedObject persisted;
    DecryptionCache decryptionCache;
    // Intruder settings
    boolean enableIntruderResponseDecrypt, enableIntruderRequestEncrypt, enableIntruderPayloadProcessor;
    String intruderEncryptCommand;
    // Repeater settings
    boolean repeaterEncryptOnlyOnModification;
    // Auto-load: keep patterns in sync with a JSON file maintained outside Burp
    boolean autoLoadEnabled;
    String autoLoadPath;
    int autoLoadIntervalSeconds;

    public Config(Persistence persistence) {
        this.persisted = persistence.extensionData();
        this.logFilePath = getPreference("logFilePath", defaultLogFilePath());
        this.logFile = new File(logFilePath);
        this.patterns = loadPatterns();
        this.enableRequestPrintEditor = getPreference("enableRequestPrintEditor", true);
        this.enableResponsePrintEditor = getPreference("enableResponsePrintEditor", true);
        this.escapeRequestDoubleQuotes = getPreference("escapeRequestDoubleQuotes", false);
        this.escapeResponseDoubleQuotes = getPreference("escapeResponseDoubleQuotes", false);
        this.highlightRequestPrintEditor = getPreference("highlightRequestPrintEditor", true);
        this.highlightResponsePrintEditor = getPreference("highlightResponsePrintEditor", true);
        this.reqPrintEditorHighlightColor = new Color(
                getPreference("reqPrintEditorHighlightColor", Color.YELLOW.getRGB()), true);
        this.resPrintEditorHighlightColor = new Color(
                getPreference("resPrintEditorHighlightColor", Color.YELLOW.getRGB()), true);
        this.reloadRequestEditors = true;
        this.reloadResponseEditors = true;
        this.decryptionCache = new DecryptionCache(persisted);
        // Intruder settings
        this.enableIntruderResponseDecrypt = getPreference("enableIntruderResponseDecrypt", true);
        this.enableIntruderRequestEncrypt = getPreference("enableIntruderRequestEncrypt", true);
        this.enableIntruderPayloadProcessor = getPreference("enableIntruderPayloadProcessor", false);
        this.intruderEncryptCommand = getPreference("intruderEncryptCommand", "");
        // Repeater settings
        this.repeaterEncryptOnlyOnModification = getPreference("repeaterEncryptOnlyOnModification", true);
        // Auto-load
        this.autoLoadEnabled = getPreference("autoLoadEnabled", false);
        this.autoLoadPath = getPreference("autoLoadPath", "");
        this.autoLoadIntervalSeconds = getPreference("autoLoadIntervalSeconds", 5);
    }

    public boolean isAutoLoadEnabled() {
        return autoLoadEnabled;
    }

    public String getAutoLoadPath() {
        return autoLoadPath;
    }

    public int getAutoLoadIntervalSeconds() {
        return autoLoadIntervalSeconds;
    }

    public void setAutoLoad(boolean enabled, String path, int intervalSeconds) {
        this.autoLoadEnabled = enabled;
        this.autoLoadPath = path;
        this.autoLoadIntervalSeconds = intervalSeconds;
        this.persisted.setBoolean("autoLoadEnabled", enabled);
        this.persisted.setString("autoLoadPath", path);
        this.persisted.setInteger("autoLoadIntervalSeconds", intervalSeconds);
    }

    /**
     * The factory value of every key {@link #exportSettings()} handles. Export omits whatever still
     * matches these and import restores them for keys a file leaves out, so a config file carries
     * only what its author actually changed.
     *
     * <p>
     * {@code logFilePath}'s default depends on the machine it runs on, which is exactly why this
     * matters: exporting it unchanged would carry one user's home directory onto someone else's box.
     * </p>
     */
    public static Map<String, Object> defaultSettings() {
        Map<String, Object> defaults = new LinkedHashMap<>();
        defaults.put("logFilePath", defaultLogFilePath());
        defaults.put("enableRequestPrintEditor", true);
        defaults.put("enableResponsePrintEditor", true);
        defaults.put("escapeRequestDoubleQuotes", false);
        defaults.put("escapeResponseDoubleQuotes", false);
        defaults.put("highlightRequestPrintEditor", true);
        defaults.put("highlightResponsePrintEditor", true);
        defaults.put("reqPrintEditorHighlightColor", Color.YELLOW.getRGB());
        defaults.put("resPrintEditorHighlightColor", Color.YELLOW.getRGB());
        defaults.put("enableIntruderResponseDecrypt", true);
        defaults.put("enableIntruderRequestEncrypt", true);
        defaults.put("enableIntruderPayloadProcessor", false);
        defaults.put("intruderEncryptCommand", "");
        defaults.put("repeaterEncryptOnlyOnModification", true);
        defaults.put("autoLoadEnabled", false);
        defaults.put("autoLoadPath", "");
        defaults.put("autoLoadIntervalSeconds", 5);
        return defaults;
    }

    static String defaultLogFilePath() {
        return System.getProperty("user.home") + File.separator + "reencrypt.log";
    }

    /** Only the preferences that differ from {@link #defaultSettings()}, for "Export all". */
    public Map<String, Object> exportSettings() {
        Map<String, Object> defaults = defaultSettings();
        Map<String, Object> changed = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : currentSettings().entrySet()) {
            if (!java.util.Objects.equals(defaults.get(entry.getKey()), entry.getValue())) {
                changed.put(entry.getKey(), entry.getValue());
            }
        }
        return changed;
    }

    /** Every scalar preference at its current value. */
    private Map<String, Object> currentSettings() {
        Map<String, Object> settings = new LinkedHashMap<>();
        settings.put("logFilePath", logFilePath);
        settings.put("enableRequestPrintEditor", enableRequestPrintEditor);
        settings.put("enableResponsePrintEditor", enableResponsePrintEditor);
        settings.put("escapeRequestDoubleQuotes", escapeRequestDoubleQuotes);
        settings.put("escapeResponseDoubleQuotes", escapeResponseDoubleQuotes);
        settings.put("highlightRequestPrintEditor", highlightRequestPrintEditor);
        settings.put("highlightResponsePrintEditor", highlightResponsePrintEditor);
        settings.put("reqPrintEditorHighlightColor", reqPrintEditorHighlightColor.getRGB());
        settings.put("resPrintEditorHighlightColor", resPrintEditorHighlightColor.getRGB());
        settings.put("enableIntruderResponseDecrypt", enableIntruderResponseDecrypt);
        settings.put("enableIntruderRequestEncrypt", enableIntruderRequestEncrypt);
        settings.put("enableIntruderPayloadProcessor", enableIntruderPayloadProcessor);
        settings.put("intruderEncryptCommand", intruderEncryptCommand);
        settings.put("repeaterEncryptOnlyOnModification", repeaterEncryptOnlyOnModification);
        settings.put("autoLoadEnabled", autoLoadEnabled);
        settings.put("autoLoadPath", autoLoadPath);
        settings.put("autoLoadIntervalSeconds", autoLoadIntervalSeconds);
        return settings;
    }

    /**
     * Apply an imported settings block. The block is authoritative: a key it omits goes back to its
     * default, so importing a config leaves this install matching the one that exported it. Keys
     * already at the incoming value are skipped, which keeps the import idempotent (and avoids the
     * log file being probed when its path is not actually changing).
     */
    public void importSettings(Map<String, Object> settings) throws IOException {
        Map<String, Object> incoming = defaultSettings();
        incoming.putAll(settings);
        Map<String, Object> current = currentSettings();
        for (Map.Entry<String, Object> entry : incoming.entrySet()) {
            Object v = entry.getValue();
            if (java.util.Objects.equals(current.get(entry.getKey()), v)) {
                continue;
            }
            switch (entry.getKey()) {
                case "logFilePath" -> updateLogFilePath((String) v);
                case "enableRequestPrintEditor" -> updateShowPrintEditor((Boolean) v, true);
                case "enableResponsePrintEditor" -> updateShowPrintEditor((Boolean) v, false);
                case "escapeRequestDoubleQuotes" -> updateShouldEscapeDoubleQuotes((Boolean) v, true);
                case "escapeResponseDoubleQuotes" -> updateShouldEscapeDoubleQuotes((Boolean) v, false);
                case "highlightRequestPrintEditor" -> updateHighlightPrintEditor((Boolean) v, true);
                case "highlightResponsePrintEditor" -> updateHighlightPrintEditor((Boolean) v, false);
                case "reqPrintEditorHighlightColor" -> updatePrintEditorHighlightColor(new Color((Integer) v, true), true);
                case "resPrintEditorHighlightColor" -> updatePrintEditorHighlightColor(new Color((Integer) v, true), false);
                case "enableIntruderResponseDecrypt" -> setIntruderResponseDecrypt((Boolean) v);
                case "enableIntruderRequestEncrypt" -> setIntruderRequestEncrypt((Boolean) v);
                case "enableIntruderPayloadProcessor" -> setIntruderPayloadProcessor((Boolean) v);
                case "intruderEncryptCommand" -> setIntruderEncryptCommand((String) v);
                case "repeaterEncryptOnlyOnModification" -> setRepeaterEncryptOnlyOnModification((Boolean) v);
                // The three auto-load keys arrive separately; setAutoLoad takes all three, so each one
                // re-applies the other two from their current (already updated) values.
                case "autoLoadEnabled" -> setAutoLoad((Boolean) v, autoLoadPath, autoLoadIntervalSeconds);
                case "autoLoadPath" -> setAutoLoad(autoLoadEnabled, (String) v, autoLoadIntervalSeconds);
                case "autoLoadIntervalSeconds" -> setAutoLoad(autoLoadEnabled, autoLoadPath, (Integer) v);
                default -> {
                    // unknown key: ignore, so a newer file still imports what this build understands
                }
            }
        }
    }

    public DecryptionCache getDecryptionCache() {
        return decryptionCache;
    }

    public String getLogFilePath() {
        return logFilePath;
    }

    public void updateLogFilePath(String logFilePath) throws IOException {
        if (logWriter != null) {
            logWriter.close();
        }
        this.logFile = new File(logFilePath);
        if (!logFile.exists()) {
            logFile.createNewFile();
            logFile.delete();
        } else if (!logFile.canWrite()) {
            throw new IOException("file is not writable");
        }
        this.logFilePath = logFilePath;
        this.persisted.setString("logFilePath", logFilePath);
    }

    public void writeLog(LogData logData) throws IOException {
        if (logWriter == null) {
            this.logWriter = new BufferedWriter(new FileWriter(logFile, true));
        }
        logWriter.append("Date  : " + new Date().toString() + "\n");
        logWriter.append("Where1: " + logData.toolSource + " - " + (logData.isRequest ? "Request" : "Response") + "\n");
        logWriter.append("Where2: " + logData.method + " " + logData.url + "\n");
        logWriter.append("What  : " + logData.cipherOperation + " - " + logData.patternName + "\n");
        if (logData.cipherOperation.toUpperCase().equals("ENCRYPT")) {
            logWriter.append("Plain : " + logData.plainText + "\n");
            logWriter.append("Cipher: " + logData.cipherText + "\n");
        } else {
            logWriter.append("Cipher: " + logData.cipherText + "\n");
            logWriter.append("Plain : " + logData.plainText + "\n");
        }
        logWriter.append("\n");
        logWriter.flush();
    }

    public CapturePattern[] getActivePatterns(boolean isRequest) {
        ArrayList<CapturePattern> result = new ArrayList<>();
        for (var pattern : patterns) {
            if (pattern.isRequest() == isRequest && pattern.isEnabled()) {
                result.add(pattern);
            }
        }
        return result.toArray(new CapturePattern[0]);
    }

    private int getPreference(String key, int defaultValue) {
        Integer preference = persisted.getInteger(key);
        if (preference == null) {
            persisted.setInteger(key, defaultValue);
            preference = defaultValue;
        }
        return preference;
    }

    private boolean getPreference(String key, boolean defaultValue) {
        Boolean preference = persisted.getBoolean(key);
        if (preference == null) {
            persisted.setBoolean(key, defaultValue);
            preference = defaultValue;
        }
        return preference;
    }

    private String getPreference(String key, String defaultValue) {
        String preference = persisted.getString(key);
        if (preference == null) {
            persisted.setString(key, defaultValue);
            preference = defaultValue;
        }
        return preference;
    }

    private ArrayList<CapturePattern> loadPatterns() {
        String stored = persisted.getString(PATTERNS_KEY);
        if (stored == null) {
            return migrateSplitLists();
        }
        if (stored.isEmpty()) {
            return new ArrayList<>();
        }
        try {
            return ConfigJson.listFromJson(stored);
        } catch (Exception e) {
            // Don't fail silently: unreadable storage means the user's saved patterns are gone, and
            // an empty table with no explanation looks like the extension lost them for no reason.
            loadErrors.add("Could not load '" + PATTERNS_KEY + "' (" + e.getClass().getSimpleName()
                    + "). Saved entries were discarded and the list starts empty.");
            // Overwrite the unreadable value, otherwise it fails again on every load and the error
            // repeats forever - savePatterns() only runs when the user edits something.
            persisted.setString(PATTERNS_KEY, ConfigJson.listToJson(new ArrayList<>()));
            return new ArrayList<>();
        }
    }

    /**
     * Read the pre-2.0 storage, which kept request and response patterns under separate keys, and
     * fold it into the single ordered list (requests first, as the old table showed them). Runs once:
     * the merged list is written under the new key and the old ones are dropped.
     */
    private ArrayList<CapturePattern> migrateSplitLists() {
        ArrayList<CapturePattern> merged = new ArrayList<>();
        for (String key : new String[] { "requestPatterns", "responsePatterns" }) {
            String stored = persisted.getString(key);
            if (stored == null || stored.isEmpty()) {
                continue;
            }
            try {
                for (CapturePattern pattern : ConfigJson.listFromJson(stored)) {
                    pattern.setRequest(key.startsWith("request"));
                    merged.add(pattern);
                }
            } catch (Exception e) {
                loadErrors.add("Could not load '" + key + "' (" + e.getClass().getSimpleName()
                        + "). Saved entries were discarded and the list starts empty.");
            }
            persisted.deleteString(key);
        }
        persisted.setString(PATTERNS_KEY, ConfigJson.listToJson(merged));
        return merged;
    }

    /** Problems hit while loading persisted data. Empty on a clean start. */
    public ArrayList<String> getLoadErrors() {
        return loadErrors;
    }

    private void updatePreference(String key, ArrayList<CapturePattern> value) {
        this.persisted.setString(key, ConfigJson.listToJson(value));
    }

    private void savePatterns() {
        try {
            updatePreference(PATTERNS_KEY, patterns);
        } catch (Exception e) {
            System.out.println("Failed to save patterns: " + e.getMessage());
        }
    }

    public void updateShowPrintEditor(boolean enablePrintEditor, boolean isRequest) {
        if (isRequest) {
            this.enableRequestPrintEditor = enablePrintEditor;
            this.persisted.setBoolean("enableRequestPrintEditor", enablePrintEditor);
        } else {
            this.enableResponsePrintEditor = enablePrintEditor;
            this.persisted.setBoolean("enableResponsePrintEditor", enablePrintEditor);
        }
    }

    public boolean isPrintEditorEnabled(boolean isRequest) {
        return isRequest ? enableRequestPrintEditor : enableResponsePrintEditor;
    }

    public void updateShouldEscapeDoubleQuotes(boolean escapeDoubleQuotes, boolean isRequest) {
        if (isRequest) {
            this.escapeRequestDoubleQuotes = escapeDoubleQuotes;
            this.persisted.setBoolean("escapeRequestDoubleQuotes", escapeDoubleQuotes);
        } else {
            this.escapeResponseDoubleQuotes = escapeDoubleQuotes;
            this.persisted.setBoolean("escapeResponseDoubleQuotes", escapeDoubleQuotes);
        }
    }

    public void updateHighlightPrintEditor(boolean highlightPrintEditor, boolean isRequest) {
        if (isRequest) {
            this.highlightRequestPrintEditor = highlightPrintEditor;
            this.persisted.setBoolean("highlightRequestPrintEditor", highlightPrintEditor);
        } else {
            this.highlightResponsePrintEditor = highlightPrintEditor;
            this.persisted.setBoolean("highlightResponsePrintEditor", highlightPrintEditor);
        }
    }

    public void updatePrintEditorHighlightColor(Color color, boolean isRequest) {
        if (isRequest) {
            this.reqPrintEditorHighlightColor = color;
            this.persisted.setInteger("reqPrintEditorHighlightColor", color.getRGB());
        } else {
            this.resPrintEditorHighlightColor = color;
            this.persisted.setInteger("resPrintEditorHighlightColor", color.getRGB());
        }
    }

    public boolean isEscapingDoubleQuotes(boolean isRequest) {
        return isRequest ? escapeRequestDoubleQuotes : escapeResponseDoubleQuotes;
    }

    public boolean isHighlightingPrintEditor(boolean isRequest) {
        return isRequest ? highlightRequestPrintEditor : highlightResponsePrintEditor;
    }

    public Color getPrintEditorHighlightColor(boolean isRequest) {
        return isRequest ? reqPrintEditorHighlightColor : resPrintEditorHighlightColor;
    }

    /**
     * One list means an edit can change either direction (a pattern can be flipped, or reordered past
     * one of the other kind), so both sets of editors are told to rebuild.
     */
    void setReloadEditors() {
        this.reloadRequestEditors = true;
        this.reloadResponseEditors = true;
    }

    // Intruder settings getters and setters
    public boolean isIntruderResponseDecryptEnabled() {
        return enableIntruderResponseDecrypt;
    }

    public void setIntruderResponseDecrypt(boolean enabled) {
        this.enableIntruderResponseDecrypt = enabled;
        this.persisted.setBoolean("enableIntruderResponseDecrypt", enabled);
    }

    public boolean isIntruderRequestEncryptEnabled() {
        return enableIntruderRequestEncrypt;
    }

    public void setIntruderRequestEncrypt(boolean enabled) {
        this.enableIntruderRequestEncrypt = enabled;
        this.persisted.setBoolean("enableIntruderRequestEncrypt", enabled);
    }

    public boolean isIntruderPayloadProcessorEnabled() {
        return enableIntruderPayloadProcessor;
    }

    public void setIntruderPayloadProcessor(boolean enabled) {
        this.enableIntruderPayloadProcessor = enabled;
        this.persisted.setBoolean("enableIntruderPayloadProcessor", enabled);
    }

    public String getIntruderEncryptCommand() {
        return intruderEncryptCommand;
    }

    public void setIntruderEncryptCommand(String command) {
        this.intruderEncryptCommand = command;
        this.persisted.setString("intruderEncryptCommand", command);
    }

    // Repeater settings getters and setters
    public boolean isRepeaterEncryptOnlyOnModification() {
        return repeaterEncryptOnlyOnModification;
    }

    public void setRepeaterEncryptOnlyOnModification(boolean enabled) {
        this.repeaterEncryptOnlyOnModification = enabled;
        this.persisted.setBoolean("repeaterEncryptOnlyOnModification", enabled);
    }

    public void addPattern(CapturePattern newPattern) {
        patterns.add(newPattern);
        setReloadEditors();
        savePatterns();
    }

    public void clonePattern(int index) {
        CapturePattern newPattern = patterns.get(index).clone();
        newPattern.setName(generateUniqueName());
        // Next to the original rather than at the end: a clone is an edit of what the user is looking at.
        patterns.add(index + 1, newPattern);
        setReloadEditors();
        savePatterns();
    }

    /**
     * Generate a unique name for a new pattern like "Pattern N".
     */
    public String generateUniqueName() {
        return generateUniqueName("Pattern");
    }

    /** Generate a name like "{base} N", skipping numbers already taken. */
    public String generateUniqueName(String base) {
        for (int n = patterns.size() + 1;; n++) {
            String candidate = base + " " + n;
            if (!hasPatternNamed(candidate)) {
                return candidate;
            }
        }
    }

    private boolean hasPatternNamed(String name) {
        return indexOfName(name) >= 0;
    }

    public void editPattern(int index, CapturePattern newPattern) {
        patterns.set(index, newPattern);
        setReloadEditors();
        savePatterns();
    }

    public void movePattern(int currentIndex, int newIndex) {
        if (newIndex < 0 || newIndex > patterns.size() - 1) {
            return;
        }
        patterns.add(newIndex, patterns.remove(currentIndex));
        setReloadEditors();
        savePatterns();
    }

    public void removePattern(int index) {
        patterns.remove(index);
        setReloadEditors();
        savePatterns();
    }

    /** Swap the whole list at once. */
    public void replaceAllPatterns(List<CapturePattern> newPatterns) {
        patterns.clear();
        patterns.addAll(newPatterns);
        setReloadEditors();
        savePatterns();
    }

    /** What a merge actually did, so a caller polling on a timer can stay quiet when nothing moved. */
    public static class MergeResult {
        public final int replaced;
        public final int added;
        public final boolean changed;

        MergeResult(int replaced, int added, boolean changed) {
            this.replaced = replaced;
            this.added = added;
            this.changed = changed;
        }
    }

    /**
     * Take in a set of patterns by name: a name that already exists is replaced where it sits, the
     * rest are appended. Patterns not named in {@code incoming} are untouched.
     *
     * <p>
     * Incoming patterns are taken as they are, enabled state included; the caller decides what that
     * should be (auto-load forces it on).
     * </p>
     */
    public MergeResult mergePatternsByName(List<CapturePattern> incoming) {
        String before = ConfigJson.listToJson(patterns);
        int replaced = 0;
        for (CapturePattern pattern : incoming) {
            int existing = indexOfName(pattern.getName());
            if (existing >= 0) {
                patterns.set(existing, pattern);
                replaced++;
            } else {
                patterns.add(pattern);
            }
        }
        boolean changed = !before.equals(ConfigJson.listToJson(patterns));
        if (changed) {
            setReloadEditors();
            savePatterns();
        }
        return new MergeResult(replaced, incoming.size() - replaced, changed);
    }

    /** Index of this exact pattern object, or -1 when it is no longer in the list. */
    public int indexOf(CapturePattern pattern) {
        for (int i = 0; i < patterns.size(); i++) {
            if (patterns.get(i) == pattern) {
                return i;
            }
        }
        return -1;
    }

    /** Index of the pattern with this name, or -1. Names are unique across the whole list. */
    public int indexOfName(String name) {
        for (int i = 0; i < patterns.size(); i++) {
            if (patterns.get(i).getName().equals(name)) {
                return i;
            }
        }
        return -1;
    }

    /** Every pattern, in the user's order. Live list: edits go through the methods above. */
    public ArrayList<CapturePattern> getPatterns() {
        return patterns;
    }

    /** Only the patterns for one direction, keeping their relative order. */
    public ArrayList<CapturePattern> getPatterns(boolean isRequest) {
        ArrayList<CapturePattern> result = new ArrayList<>();
        for (CapturePattern pattern : patterns) {
            if (pattern.isRequest() == isRequest) {
                result.add(pattern);
            }
        }
        return result;
    }

    public boolean checkReloadEditors(boolean isRequest) {
        if (isRequest) {
            boolean result = reloadRequestEditors;
            reloadRequestEditors = false;
            return result;
        } else {
            boolean result = reloadResponseEditors;
            reloadResponseEditors = false;
            return result;
        }
    }

}
