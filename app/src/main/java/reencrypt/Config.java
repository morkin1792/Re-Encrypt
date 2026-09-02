package reencrypt;

import java.awt.Color;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Date;

import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.persistence.Persistence;

public class Config implements Serializable {
    public static final String fileMarker = "{FILE}";
    public static final String dataMarker = "{DATA}";

    ArrayList<CapturePattern> requestPatterns, responsePatterns;
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

    public Config(Persistence persistence) {
        this.persisted = persistence.extensionData();
        this.logFilePath = getPreference("logFilePath",
                System.getProperty("user.home") + File.separator + "reencrypt.log");
        this.logFile = new File(logFilePath);
        this.responsePatterns = getPreference("responsePatterns", new ArrayList<CapturePattern>());
        this.requestPatterns = getPreference("requestPatterns", new ArrayList<CapturePattern>());
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
        var patterns = isRequest ? requestPatterns : responsePatterns;
        for (var pattern : patterns) {
            if (pattern.isEnabled())
                result.add(pattern);
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

    private <T extends Serializable> ArrayList<T> getPreference(String key, ArrayList<T> defaultValue) {
        try {
            String serialized = Utils.serialize(defaultValue);
            String preference = getPreference(key, serialized);
            return Utils.deserialize(preference);
        } catch (Exception e) {
            // Don't fail silently: an unreadable blob means the user's saved patterns are gone, and
            // an empty table with no explanation looks like the extension lost them for no reason.
            loadErrors.add("Could not load '" + key + "' (" + e.getClass().getSimpleName()
                    + "). Saved entries were discarded and the list starts empty.");
            return defaultValue;
        }
    }

    /** Problems hit while loading persisted data. Empty on a clean start. */
    public ArrayList<String> getLoadErrors() {
        return loadErrors;
    }

    private <T extends Serializable> void updatePreference(String key, ArrayList<T> value) throws IOException {
        this.persisted.setString(key, Utils.serialize(value));
    }

    private void savePatterns(boolean isRequest) {
        try {
            if (isRequest) {
                updatePreference("requestPatterns", requestPatterns);
            } else {
                updatePreference("responsePatterns", responsePatterns);
            }
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

    void setReloadEditors(boolean isRequest) {
        if (isRequest) {
            this.reloadRequestEditors = true;
        } else {
            this.reloadResponseEditors = true;
        }
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

    public void addPattern(CapturePattern newPattern, boolean isRequest) {
        getPatterns(isRequest).add(newPattern);
        setReloadEditors(isRequest);
        savePatterns(isRequest);
    }

    public void clonePattern(int index, boolean isRequest) {
        CapturePattern pattern = getPatterns(isRequest).get(index);
        CapturePattern newPattern = pattern.clone();
        newPattern.setName(generateUniqueName(isRequest));
        addPattern(newPattern, isRequest);
        setReloadEditors(isRequest);
        savePatterns(isRequest);
    }

    /**
     * Generate a unique name for a new pattern like "Pattern N".
     */
    public String generateUniqueName(boolean isRequest) {
        return generateUniqueName("Pattern", isRequest);
    }

    /** Generate a name like "{base} N" sized to the current pattern list. */
    public String generateUniqueName(String base, boolean isRequest) {
        return base + " " + (getPatterns(isRequest).size() + 1);
    }

    public void editPattern(int index, CapturePattern newPattern, boolean isRequest) {
        getPatterns(isRequest).set(index, newPattern);
        setReloadEditors(isRequest);
        savePatterns(isRequest);
    }

    public void movePattern(int currentIndex, int newIndex, boolean isRequest) {
        if (newIndex < 0 || newIndex > getPatterns(isRequest).size() - 1)
            return;
        CapturePattern newValue = getPatterns(isRequest).get(newIndex);
        CapturePattern currentValue = getPatterns(isRequest).get(currentIndex);
        editPattern(newIndex, currentValue, isRequest);
        editPattern(currentIndex, newValue, isRequest);
        setReloadEditors(isRequest);
        savePatterns(isRequest);
    }

    public void removePattern(int index, boolean isRequest) {
        getPatterns(isRequest).remove(index);
        setReloadEditors(isRequest);
        savePatterns(isRequest);
    }

    public ArrayList<CapturePattern> getPatterns(boolean isRequest) {
        var patterns = requestPatterns;
        if (!isRequest) {
            patterns = responsePatterns;
        }
        return patterns;
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
