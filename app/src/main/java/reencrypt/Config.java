package reencrypt;

import java.io.Serializable;

import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.persistence.Persistence;

public class Config implements Serializable {
    public static final String fileMarker = "{file}";
    public static final String argMarker = "{arg}";
    private static final String cmdKeyPrefix = "sh/";
    
    String requestPattern, responsePattern, decodeCommand, encodeCommand, targetPattern;
    boolean shouldPatchProxy, shouldSaveCommands;
    PersistedObject persisted;

    public Config(Persistence persistence) {
        this.persisted = persistence.extensionData();
        this.requestPattern = getPreference("requestPattern", "\\r\\n\\r\\n(.+)");
        this.responsePattern = getPreference("responsePattern", "data\":\"(.*?)\"");
        this.decodeCommand = getPreference("decodeCommand", "node /tmp/crypt/rsaEncrypt.js selfDecrypt --file " + fileMarker);
        this.encodeCommand = getPreference("encodeCommand", "node /tmp/crypt/rsaEncrypt.js publicEncrypt " + argMarker);
        this.targetPattern = getPreference("targetPattern", "/v1/graphql");
        this.shouldPatchProxy = getBoolean("shouldPatchProxy", false);
        this.shouldSaveCommands = getBoolean("shouldSaveCommands", true);
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

    public void updateFields(String requestPattern, String responsePattern, String decodeCommand, String encodeCommand, String targetPattern) {
        this.requestPattern = requestPattern;
        this.persisted.setString("requestPattern", requestPattern);
        this.responsePattern = responsePattern;
        this.persisted.setString("responsePattern", responsePattern);
        this.decodeCommand = decodeCommand;
        this.persisted.setString("decodeCommand", decodeCommand);
        this.encodeCommand = encodeCommand;
        this.persisted.setString("encodeCommand", encodeCommand);
        this.targetPattern = targetPattern;
        this.persisted.setString("targetPattern", targetPattern);

    }

    public void updatePatchProxy(boolean shouldPatchProxy) {
        this.shouldPatchProxy = shouldPatchProxy;
        this.persisted.setBoolean("shouldPatchProxy", shouldPatchProxy);
    }

    public void updateSaveCommands(boolean shouldSaveCommands) {
        this.shouldSaveCommands = shouldSaveCommands;
        this.persisted.setBoolean("shouldSaveCommands", shouldSaveCommands);
    }

    public String getRequestPattern() {
        return requestPattern;
    }

    public String getResponsePattern() {
        return responsePattern;
    }

    public String getPattern(boolean isRequest) {
        return isRequest ? getRequestPattern() : getResponsePattern();
    }

    public String getDecodeCommand() {
        return decodeCommand;
    }

    public String getEncodeCommand() {
        return encodeCommand;
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

    public void eraseCommand(String cipherText) {
        if (shouldSaveCommands()) {
            var hash = Utils.getHash(cipherText.getBytes());
            persisted.deleteString(cmdKeyPrefix + hash);
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
