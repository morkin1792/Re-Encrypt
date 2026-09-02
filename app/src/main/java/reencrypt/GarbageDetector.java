package reencrypt;

/**
 * Heuristic check for "garbage" decryption output. Unauthenticated cipher modes
 * (CTR/CFB/OFB, NoPadding) and raw RSA cannot detect a wrong key — they produce random
 * bytes instead of an error. Such output, once lenient-decoded to text, is full of
 * U+FFFD replacement characters, NUL bytes and control characters, whereas real
 * plaintext is not. This lets the cache avoid storing wrong-key results.
 */
public class GarbageDetector {

    private static final char NUL = '\u0000';
    private static final char REPLACEMENT = '\uFFFD';
    private static final double BAD_RATIO_THRESHOLD = 0.10;

    public static boolean looksLikeGarbage(String output) {
        if (output == null || output.isEmpty()) {
            return false;
        }
        int bad = 0;
        for (int i = 0; i < output.length(); i++) {
            char c = output.charAt(i);
            if (c == NUL) {
                return true; // NUL is essentially never present in real text
            }
            if (c == REPLACEMENT) {
                bad++; // came from invalid bytes during lenient decoding
                continue;
            }
            if (c == '\t' || c == '\n' || c == '\r') {
                continue; // common whitespace is fine
            }
            if (Character.getType(c) == Character.CONTROL) {
                bad++;
            }
        }
        return (double) bad / output.length() >= BAD_RATIO_THRESHOLD;
    }
}
