package burp;

import java.io.Serializable;
import java.util.HashMap;

public class Config implements Serializable {
    public static final String replaceMarker = "{}";
    
    public String requestPattern, responsePattern, decodeCommand, encodeCommand;
    public HashMap<String, String> commandsHistory;

    public Config() {
        this.requestPattern = "data\":\"(.*?)\"";
        this.responsePattern = "data\":\"(.*?)\"";
        this.decodeCommand = "node /home/user/crypt.js d " + replaceMarker;
        this.encodeCommand = "node /home/user/crypt.js e " + replaceMarker;
        commandsHistory = new HashMap<>();
    }

    public String loadSaveCommand(String hash, String command) {
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

    public void eraseCommand(String hash) {
        commandsHistory.remove(hash);
    }

}
