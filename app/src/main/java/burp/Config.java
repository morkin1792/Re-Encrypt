package burp;

import java.io.Serializable;

public class Config implements Serializable {
    public String requestPattern, responsePattern, decodeCommand, encodeCommand;

    public Config(String requestPattern, String responsePattern, String decodeCommand, String encodeCommand) {
        this.requestPattern = requestPattern;
        this.responsePattern = responsePattern;
        this.decodeCommand = decodeCommand;
        this.encodeCommand = encodeCommand;
    }

}
