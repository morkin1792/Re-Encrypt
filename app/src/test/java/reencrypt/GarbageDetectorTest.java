package reencrypt;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

public class GarbageDetectorTest {

    private static final char NUL = (char) 0;
    private static final char REPLACEMENT = (char) 0xFFFD;

    @Test
    void plainTextIsNotGarbage() {
        assertFalse(GarbageDetector.looksLikeGarbage("hello world, this is normal text"));
        assertFalse(GarbageDetector.looksLikeGarbage("{\"user\":\"alice\",\"id\":42}"));
        assertFalse(GarbageDetector.looksLikeGarbage("line1\nline2\twith tabs\r\n"));
        assertFalse(GarbageDetector.looksLikeGarbage("acentuacao e simbolos validos"));
    }

    @Test
    void emptyIsNotGarbage() {
        assertFalse(GarbageDetector.looksLikeGarbage(""));
        assertFalse(GarbageDetector.looksLikeGarbage(null));
    }

    @Test
    void nulMakesItGarbage() {
        assertTrue(GarbageDetector.looksLikeGarbage("abc" + NUL + "def"));
    }

    @Test
    void replacementCharsMakeItGarbage() {
        assertTrue(GarbageDetector.looksLikeGarbage(String.valueOf(REPLACEMENT).repeat(4) + "x"));
    }

    @Test
    void randomBytesDecodedAreGarbage() {
        // Random bytes lenient-decoded to text look like wrong-key output.
        byte[] random = new byte[200];
        long seed = 0x9e3779b97f4a7c15L;
        for (int i = 0; i < random.length; i++) {
            seed = seed * 6364136223846793005L + 1442695040888963407L;
            random[i] = (byte) (seed >>> 56);
        }
        String text = new String(random, StandardCharsets.UTF_8);
        assertTrue(GarbageDetector.looksLikeGarbage(text));
    }
}
