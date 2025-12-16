package reencrypt;

public class LogData {
    String toolSource;
    boolean isRequest;
    String cipherOperation;
    String method;
    String url;
    String plainText;
    String cipherText;
    String patternName;

    public LogData(String toolSource, boolean isRequest, String method, String url) {
        this.toolSource = toolSource;
        this.isRequest = isRequest;
        this.method = method;
        this.url = url;
    }

    public void update(String cipherText, String plainText, String patternName, String cipherOperation) {
        this.cipherText = cipherText;
        this.plainText = plainText;
        this.patternName = patternName;
        this.cipherOperation = cipherOperation;
    }
}
