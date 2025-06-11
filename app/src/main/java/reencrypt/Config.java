package reencrypt;

import java.io.Serializable;
import java.util.ArrayList;

import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.persistence.Persistence;

public class Config implements Serializable {
    public static final String fileMarker = "{FILE}";
    public static final String dataMarker = "{DATA}";
    private static final String cmdKeyPrefix = "sh/";
    
    ArrayList<CapturePattern> requestPatterns, responsePatterns; 
    String decodeCommand, encodeCommand;
    String targetPattern;
    boolean shouldPatchProxy, shouldSaveCommands, reloadRequestEditors, reloadResponseEditors;
    PersistedObject persisted;

    public Config(Persistence persistence) {
        this.persisted = persistence.extensionData();
        this.responsePatterns = new ArrayList<>();
        this.requestPatterns = new ArrayList<>();
        // this.requestPatterns = getPreference("requestPattern", (Object)(new ArrayList<>()));
        // this.responsePatterns = getPreference("responsePattern", "data\":\"(.*?)\"");
        // this.decodeCommand = getPreference("decodeCommand", "node /tmp/crypt/rsaEncrypt.js selfDecrypt --file " + fileMarker);
        // this.encodeCommand = getPreference("encodeCommand", "node /tmp/crypt/rsaEncrypt.js publicEncrypt " + dataMarker);
        this.targetPattern = getPreference("targetPattern", "/v1/graphql");
        this.shouldPatchProxy = getBoolean("shouldPatchProxy", false);
        this.shouldSaveCommands = getBoolean("shouldSaveCommands", true);
        this.reloadRequestEditors = true;
        this.reloadResponseEditors = true;
    }

    public CapturePattern[] getActivePatterns(boolean isRequest) {
        ArrayList<CapturePattern> result = new ArrayList<>();
        var patterns = isRequest ? requestPatterns 
            : responsePatterns;
        for (var pattern : patterns) {
            if (pattern.isEnabled())
                result.add(pattern);
        }
        return result.toArray(new CapturePattern[0]);
    }

    private boolean getBoolean(String key, boolean defaultValue) {
        Boolean result = persisted.getBoolean(key);
        if (result == null) {
            persisted.setBoolean(key, defaultValue);
            result = defaultValue;
        }
        return result;
    }

    private String getPreference(String key, String defaultValue) {
        String preference = persisted.getString(key);
        if (preference == null) {
            persisted.setString(key, defaultValue);
            preference = defaultValue;
        }
        return preference;
    }

    // private Object getPreferenceArrayList(String key, ArrayList defaultValue) {
    //     Object preference = persisted.getChildObject(key);
    //     if (preference == null) {
    //         persisted.setChildObject(key, (PersistedObject) defaultValue);
    //         preference = defaultValue;
    //     }
    //     return preference;
    // }

    // public void updateFields(String requestPattern, String responsePattern, String decodeCommand, String encodeCommand, String targetPattern) {
    //     // this.requestPattern = requestPattern;
    //     this.persisted.setString("requestPattern", requestPattern);
    //     // this.responsePattern = responsePattern;
    //     this.persisted.setString("responsePattern", responsePattern);
    //     // this.decodeCommand = decodeCommand;
    //     this.persisted.setString("decodeCommand", decodeCommand);
    //     // this.encodeCommand = encodeCommand;
    //     this.persisted.setString("encodeCommand", encodeCommand);
    //     this.targetPattern = targetPattern;
    //     this.persisted.setString("targetPattern", targetPattern);

    // }

    public void updatePatchProxy(boolean shouldPatchProxy) {
        this.shouldPatchProxy = shouldPatchProxy;
        this.persisted.setBoolean("shouldPatchProxy", shouldPatchProxy);
    }

    public void updateSaveCommands(boolean shouldSaveCommands) {
        this.shouldSaveCommands = shouldSaveCommands;
        this.persisted.setBoolean("shouldSaveCommands", shouldSaveCommands);
    }

    void setReloadEditors(boolean isRequest) {
        if (isRequest) {
            this.reloadRequestEditors = true;
        }
        else {
            this.reloadResponseEditors = true;
        }
    }

    public void addPattern(CapturePattern newPattern, boolean isRequest) {
        getPatterns(isRequest).add(newPattern);
        setReloadEditors(isRequest);
    }

    public void clonePattern(int index, boolean isRequest) {
        CapturePattern pattern = getPatterns(isRequest).get(index);
        CapturePattern newPattern = new CapturePattern(pattern.getName(), pattern.getRegex(), pattern.getDecCommand(), pattern.getEncCommand(), pattern.isEnabled());
        addPattern(newPattern, isRequest);
        setReloadEditors(isRequest);
    }

    public void editPattern(int index, CapturePattern newPattern, boolean isRequest) {
        getPatterns(isRequest).set(index, newPattern);
        setReloadEditors(isRequest);
    }

    public void movePattern(int currentIndex, int newIndex, boolean isRequest) {
        if (newIndex < 0 || newIndex > getPatterns(isRequest).size() - 1) return;
        CapturePattern newValue = getPatterns(isRequest).get(newIndex);
        CapturePattern currentValue = getPatterns(isRequest).get(currentIndex);
        editPattern(newIndex, currentValue, isRequest);
        editPattern(currentIndex, newValue, isRequest);
        setReloadEditors(isRequest);
    }

    public void removePattern(int index, boolean isRequest) {
        getPatterns(isRequest).remove(index);
        setReloadEditors(isRequest);
    }

    public ArrayList<CapturePattern> getPatterns(boolean isRequest) {
        var patterns = requestPatterns;
        if (!isRequest) {
            patterns = responsePatterns;
        }
        return patterns;
    }

    public String getTargetPattern() {
        return targetPattern;
    }
		
    public boolean shouldPatchProxy() {
        return shouldPatchProxy;
    }

    public boolean shouldSaveCommands() {
        return shouldSaveCommands;
    }
    
    public String getCommand(String cipherText, String defaultCommand) {
        String hash = Utils.getHash(cipherText.getBytes());
        String commandLoaded = this.persisted.getString(cmdKeyPrefix + hash);
        if (commandLoaded == null) {
            if (shouldSaveCommands()) {
                this.persisted.setString(cmdKeyPrefix + hash, defaultCommand);
            }
            commandLoaded = defaultCommand;
        }
        return commandLoaded;
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

    // public int getSizeCommands() {
    //     int counter = 0;
    //     for (String key : persisted.stringKeys()) {
    //         if (key.startsWith(cmdKeyPrefix)) {
    //             counter++;
    //         }
    //     }
    //     return counter;
    // }

}
