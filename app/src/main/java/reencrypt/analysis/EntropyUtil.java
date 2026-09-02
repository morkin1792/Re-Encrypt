package reencrypt.analysis;

import java.nio.charset.StandardCharsets;

/**
 * Shannon entropy helpers, used both to auto-locate the likely ciphertext and to
 * inform the analyzer's hints (high entropy ~ random/encrypted, low ~ structured/text).
 */
public class EntropyUtil {

    /** Shannon entropy in bits per byte (0.0 .. 8.0). */
    public static double shannonBitsPerByte(byte[] data) {
        if (data == null || data.length == 0) {
            return 0.0;
        }
        int[] counts = new int[256];
        for (byte b : data) {
            counts[b & 0xff]++;
        }
        double entropy = 0.0;
        double len = data.length;
        double log2 = Math.log(2);
        for (int c : counts) {
            if (c == 0) {
                continue;
            }
            double p = c / len;
            entropy -= p * (Math.log(p) / log2);
        }
        return entropy;
    }

    public static double shannonBitsPerByte(String s) {
        return shannonBitsPerByte(s.getBytes(StandardCharsets.UTF_8));
    }
}
