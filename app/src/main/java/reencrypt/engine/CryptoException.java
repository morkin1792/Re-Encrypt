package reencrypt.engine;

/**
 * Exception thrown by crypto engines when encryption/decryption fails.
 */
public class CryptoException extends Exception {
    public CryptoException(String message) {
        super(message);
    }

    public CryptoException(String message, Throwable cause) {
        super(message, cause);
    }
}
