package reencrypt.engine;

import java.util.Base64;

/**
 * Shared encoding/decoding utilities for crypto engines.
 * Supports Raw, Base64, Base64URL, and Hex formats.
 */
public class EncodingUtils {

    // --- Encode ---

    public static String encode(byte[] data, String encoding) throws CryptoException {
        switch (encoding) {
        case "Raw":
            return new String(data);
        case "Base64":
            return Base64.getEncoder().encodeToString(data);
        case "Base64URL":
            return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
        case "Hex":
            return bytesToHex(data);
        default:
            throw new CryptoException("Unknown encoding: " + encoding);
        }
    }

    // --- Decode ---

    public static byte[] decode(String data, String encoding) throws CryptoException {
        try {
            switch (encoding) {
            case "Raw":
                return data.getBytes();
            case "Base64":
                return Base64.getDecoder().decode(data);
            case "Base64URL":
                return Base64.getUrlDecoder().decode(data);
            case "Hex":
                return hexToBytes(data);
            default:
                throw new CryptoException("Unknown encoding: " + encoding);
            }
        } catch (IllegalArgumentException e) {
            throw new CryptoException("Invalid " + encoding + " value: " + e.getMessage(), e);
        }
    }

    /**
     * Decode a Base64 value from a JWE segment. JWE mandates Base64URL without
     * padding, but some implementations emit standard Base64 (with '+', '/' and
     * '=' padding) or stray whitespace. This accepts all of those forms.
     */
    public static byte[] decodeBase64Url(String value) throws CryptoException {
        String s = value.replaceAll("\\s", "");        // drop whitespace/newlines
        s = s.replace('-', '+').replace('_', '/');      // normalize URL alphabet -> standard
        int mod = s.length() % 4;
        if (mod == 1) {
            throw new CryptoException("Invalid Base64 value: bad length");
        }
        if (mod == 2) {
            s += "==";
        } else if (mod == 3) {
            s += "=";
        }
        try {
            return Base64.getDecoder().decode(s);
        } catch (IllegalArgumentException e) {
            throw new CryptoException("Invalid Base64 value: " + e.getMessage(), e);
        }
    }

    // --- Key/IV format decoding ---

    /**
     * Decode a key or IV value from the given format.
     *
     * @param value  the raw string value (user input or file content)
     * @param format "UTF-8", "Hex", "Base64", or "Empty"
     * @return decoded bytes, or empty array for "Empty"
     */
    public static byte[] decodeKeyValue(String value, String format) throws CryptoException {
        if ("Empty".equals(format) || value == null || value.isEmpty()) {
            return new byte[0];
        }
        switch (format) {
        case "UTF-8":
            return value.getBytes();
        case "Hex":
            return hexToBytes(value);
        case "Base64":
            try {
                return Base64.getDecoder().decode(value);
            } catch (IllegalArgumentException e) {
                throw new CryptoException("Invalid Base64 value: " + e.getMessage(), e);
            }
        default:
            throw new CryptoException("Unknown key format: " + format);
        }
    }

    // --- Hex helpers ---

    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }

    public static byte[] hexToBytes(String hex) throws CryptoException {
        String cleanHex = hex.replaceAll("\\s", ""); // Allow spaces in hex strings
        if (cleanHex.length() % 2 != 0) {
            throw new CryptoException("Invalid hex value: odd number of characters");
        }
        byte[] bytes = new byte[cleanHex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            int high = Character.digit(cleanHex.charAt(i * 2), 16);
            int low = Character.digit(cleanHex.charAt(i * 2 + 1), 16);
            if (high == -1 || low == -1) {
                throw new CryptoException("Invalid hex character at position " + (i * 2));
            }
            bytes[i] = (byte) ((high << 4) | low);
        }
        return bytes;
    }

    // --- Validation helpers ---

    /**
     * Try to decode a value with the given format and return error message if invalid.
     *
     * @return error message, or null if valid
     */
    public static String validateKeyValue(String value, String format, String fieldName) {
        if ("Empty".equals(format) || value == null || value.isEmpty()) {
            return null;
        }
        try {
            decodeKeyValue(value, format);
            return null;
        } catch (CryptoException e) {
            return "Invalid " + format + " value for " + fieldName + ".";
        }
    }

    /**
     * Validate AES key length after decoding.
     *
     * @return error message, or null if valid
     */
    public static String validateAesKeyLength(byte[] keyBytes) {
        int len = keyBytes.length;
        if (len != 16 && len != 24 && len != 32) {
            return "Invalid key length (" + len + "). AES requires 16, 24, or 32 bytes.";
        }
        return null;
    }
}
