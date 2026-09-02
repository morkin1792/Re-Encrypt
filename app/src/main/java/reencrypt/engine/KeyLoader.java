package reencrypt.engine;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import reencrypt.OperationResult;
import reencrypt.ShellCommand;
import reencrypt.exception.CommandException;

/**
 * Handles loading key/IV values from text, command, or file sources.
 *
 */
public class KeyLoader {

    // Cache for file contents when reload is disabled: filePath -> content
    private static final ConcurrentHashMap<String, String> fileCache = new ConcurrentHashMap<>();

    /**
     * Load a key/IV value from the engine params.
     *
     * @param params     the engine params map
     * @param prefix     the param key prefix (e.g. "key", "iv", "publicKey", "privateKey")
     * @return the raw string value (before format decoding)
     * @throws CryptoException if file cannot be read
     */
    public static String loadValue(Map<String, String> params, String prefix) throws CryptoException {
        return loadValue(params, prefix, "");
    }

    /**
     * Load a key/IV value, allowing a "command" source to reference the data being
     * processed via the {DATA}/{FILE} placeholders.
     *
     * @param data the data currently being processed (ciphertext for decrypt,
     *             plaintext for encrypt), substituted into command sources
     */
    public static String loadValue(Map<String, String> params, String prefix, String data) throws CryptoException {
        String source = params.getOrDefault(prefix + "Source", "text");
        String value = params.getOrDefault(prefix, "");

        if ("file".equals(source)) {
            return loadFromFile(value, params, prefix);
        }
        if ("command".equals(source)) {
            return runCommand(value, data, componentName(prefix));
        }
        return value;
    }

    /** Friendly name of the component a prefix refers to, for error messages. */
    private static String componentName(String prefix) {
        switch (prefix) {
        case "key": return "Key";
        case "iv": return "IV";
        case "publicKey": return "Public key";
        case "privateKey": return "Private key";
        default: return prefix;
        }
    }

    /**
     * Load a key/IV value and decode it using the specified format.
     *
     * @param params     the engine params map
     * @param prefix     the param key prefix (e.g. "key", "iv")
     * @param formatKey  the param key for the format (e.g. "keyFormat", "ivFormat")
     * @return decoded bytes
     * @throws CryptoException if loading or decoding fails
     */
    public static byte[] loadAndDecode(Map<String, String> params, String prefix, String formatKey)
            throws CryptoException {
        return loadAndDecode(params, prefix, formatKey, "");
    }

    /**
     * Load a key/IV value and decode it, allowing command sources to reference the
     * data being processed via {DATA}/{FILE}.
     */
    public static byte[] loadAndDecode(Map<String, String> params, String prefix, String formatKey, String data)
            throws CryptoException {
        String rawValue = loadValue(params, prefix, data);
        String format = params.getOrDefault(formatKey, "UTF-8");
        try {
            return EncodingUtils.decodeKeyValue(rawValue, format);
        } catch (CryptoException e) {
            throw new CryptoException(componentName(prefix) + ": " + e.getMessage(), e);
        }
    }

    /**
     * Run a shell command to produce a key/IV/key-material value. The command may
     * use the {DATA}/{FILE} placeholders, substituted with the data being processed.
     * It is executed fresh on every operation (no caching).
     */
    private static String runCommand(String commandTemplate, String data, String component) throws CryptoException {
        if (commandTemplate == null || commandTemplate.isEmpty()) {
            throw new CryptoException(component + " command is empty");
        }
        try {
            OperationResult result = new ShellCommand(commandTemplate, data == null ? "" : data).execute();
            return result.getOutputCheckingExitCode();
        } catch (CommandException e) {
            throw new CryptoException(component + " command failed: " + e.getMessage(), e);
        } catch (IOException | InterruptedException e) {
            throw new CryptoException(component + " command error: " + e.getMessage(), e);
        }
    }

    /**
     * Run the command configured under {@code prefix} and return its raw stdout
     * bytes (no newline trimming), for command sources that emit binary key
     * material such as DER-encoded keys.
     */
    public static byte[] loadCommandBytes(Map<String, String> params, String prefix, String data)
            throws CryptoException {
        String commandTemplate = params.getOrDefault(prefix, "");
        String component = componentName(prefix);
        if (commandTemplate == null || commandTemplate.isEmpty()) {
            throw new CryptoException(component + " command is empty");
        }
        try {
            return new ShellCommand(commandTemplate, data == null ? "" : data).executeRawChecked();
        } catch (CommandException e) {
            throw new CryptoException(component + " command failed: " + e.getMessage(), e);
        } catch (IOException | InterruptedException e) {
            throw new CryptoException(component + " command error: " + e.getMessage(), e);
        }
    }

    private static String loadFromFile(String filePath, Map<String, String> params, String prefix)
            throws CryptoException {
        if (filePath == null || filePath.isEmpty()) {
            throw new CryptoException(componentName(prefix) + ": no file path specified");
        }

        boolean shouldReload = "true".equals(params.getOrDefault(prefix + "ReloadFile", "true"));

        if (!shouldReload) {
            String cached = fileCache.get(filePath);
            if (cached != null) {
                return cached;
            }
        }

        try {
            Path path = Paths.get(filePath);
            if (!Files.exists(path)) {
                throw new CryptoException(componentName(prefix) + ": file not found: " + filePath);
            }
            String content = new String(Files.readAllBytes(path));
            if (!shouldReload) {
                fileCache.put(filePath, content);
            }
            return content;
        } catch (IOException e) {
            throw new CryptoException(componentName(prefix) + ": failed to read file: " + filePath + " - "
                    + e.getMessage(), e);
        }
    }

    /**
     * Load raw bytes from a file (for DER format keys).
     */
    public static byte[] loadBytesFromFile(String filePath, Map<String, String> params, String prefix)
            throws CryptoException {
        if (filePath == null || filePath.isEmpty()) {
            throw new CryptoException(componentName(prefix) + ": no file path specified");
        }

        try {
            Path path = Paths.get(filePath);
            if (!Files.exists(path)) {
                throw new CryptoException(componentName(prefix) + ": file not found: " + filePath);
            }
            return Files.readAllBytes(path);
        } catch (IOException e) {
            throw new CryptoException(componentName(prefix) + ": failed to read file: " + filePath + " - "
                    + e.getMessage(), e);
        }
    }

    /** Clear the file cache (useful for testing or when config changes). */
    public static void clearCache() {
        fileCache.clear();
    }
}
