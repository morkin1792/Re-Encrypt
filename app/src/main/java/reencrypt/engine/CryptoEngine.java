package reencrypt.engine;

import java.util.Map;

import reencrypt.ui.EngineConfigPanel;

/**
 * Interface for built-in encryption/decryption engines.
 * Each engine provides its own config UI panel and handles
 * encrypt/decrypt operations without external shell commands.
 */
public interface CryptoEngine {

    /** Unique ID for this engine (e.g. "aes", "rsa"). Used in serialization. */
    String getId();

    /** Display name shown in the UI dropdown (e.g. "AES", "RSA"). */
    String getDisplayName();

    /**
     * Decrypt the input string using the given engine parameters.
     *
     * @param input  the captured data (may be encoded depending on engine params)
     * @param params flat key-value configuration map
     * @return the decrypted plaintext
     * @throws CryptoException if decryption fails
     */
    String decrypt(String input, Map<String, String> params) throws CryptoException;

    /**
     * Encrypt the plaintext string using the given engine parameters.
     *
     * @param input  the plaintext to encrypt
     * @param params flat key-value configuration map
     * @return the encrypted output (encoded depending on engine params)
     * @throws CryptoException if encryption fails
     */
    String encrypt(String input, Map<String, String> params) throws CryptoException;

    /**
     * Validate the engine parameters for real blocking problems (missing/invalid key, IV,
     * wrong size, file not found, ...).
     *
     * @param params the parameters to validate
     * @return error message, or null if there is no blocking problem
     */
    String validate(Map<String, String> params);

    /**
     * An optional informational note (not a blocking problem), e.g. a best-practice hint.
     * Shown with an info icon/color, never in the patterns table.
     *
     * @return an informational message, or null
     */
    default String info(Map<String, String> params) {
        return null;
    }

    /**
     * Build the Swing config panel for this engine.
     * The panel is shown inside the config popup dialog.
     *
     * @param existingParams current params (may be null for new patterns)
     * @return the config panel instance
     */
    EngineConfigPanel createConfigPanel(Map<String, String> existingParams);
}
