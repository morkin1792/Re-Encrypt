package reencrypt;

import java.io.Serializable;
import java.util.HashMap;

public class Config implements Serializable {
    public static final String fileMarker = "{file}";
    public static final String argMarker = "{arg}";
    
    String requestPattern, responsePattern, decodeCommand, encodeCommand, targetPattern;
    boolean shouldPatchProxy;
    // ArrayList<Integer> commands;
    HashMap<String, String> commandsHistory;

    public Config() {
        this.requestPattern = "\\r\\n\\r\\n(.+)";
        this.responsePattern = "data\":\"(.*?)\"";
        this.decodeCommand = "node /home/temp/Vaults/crypt/rsaEncrypt.js selfDecrypt --file " + fileMarker;
        this.encodeCommand = "node /home/temp/Vaults/crypt/rsaEncrypt.js publicEncrypt --file " + fileMarker;
        this.targetPattern = "/v1/graphql";
        this.shouldPatchProxy = false;
        // commands = new ArrayList<>();
        commandsHistory = new HashMap<>();
    }

    public void updateFields(String requestPattern, String responsePattern, String decodeCommand, String encodeCommand, String targetPattern) {
        this.requestPattern = requestPattern;
        this.responsePattern = responsePattern;
        this.decodeCommand = decodeCommand;
        this.encodeCommand = encodeCommand;
        this.targetPattern = targetPattern;
    }

    public void updatePatchProxy(boolean shouldPatchProxy) {
        this.shouldPatchProxy = shouldPatchProxy;
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
        // todo: interface check   
        return true;
    }
    
    public String loadSaveCommand(String cipherText, String command) {
        String hash = Utils.getHash(cipherText.getBytes());
        String commandLoaded = loadCommand(hash);
        if (commandLoaded == null) {
            saveCommand(hash, command);
            commandLoaded = command;
        }
        return commandLoaded;
    }

    private String loadCommand(String hash) {

        return commandsHistory.get(hash);
    }

    private void saveCommand(String hash, String command) {
        commandsHistory.put(hash, command);
    }

    public void eraseCommand(String cipherText) {
        var hash = Utils.getHash(cipherText.getBytes());
        commandsHistory.remove(hash);
    }

}
