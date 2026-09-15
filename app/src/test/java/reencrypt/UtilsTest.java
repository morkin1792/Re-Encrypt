package reencrypt;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class UtilsTest {

    @Test
    void testGetHash_returnsConsistentHash() {
        byte[] data = "hello world".getBytes();

        long hash1 = Utils.getHash(data);
        long hash2 = Utils.getHash(data);

        assertEquals(hash1, hash2, "Same input should produce same hash");
    }

    @Test
    void testGetHash_differentInputsDifferentHashes() {
        byte[] data1 = "hello".getBytes();
        byte[] data2 = "world".getBytes();

        long hash1 = Utils.getHash(data1);
        long hash2 = Utils.getHash(data2);

        assertNotEquals(hash1, hash2, "Different inputs should produce different hashes");
    }

    @Test
    void testGetHash_emptyInput() {
        byte[] data = "".getBytes();

        // Should not throw, should return a valid hash
        long hash = Utils.getHash(data);
        System.out.println("Hash of empty string: " + hash + " (hex: " + Long.toHexString(hash) + ")");
    }

    @Test
    void testGetHash_printSampleHashes() {
        String[] samples = { "test", "password123", "encrypted_data_here" };

        for (String sample : samples) {
            long hash = Utils.getHash(sample.getBytes());
            System.out.println("Input: \"" + sample + "\" -> Hash: " + hash + " (hex: " + Long.toHexString(hash) + ")");
        }
    }

    @Test
    void testHexToColor() {
        // Standard RGB
        java.awt.Color red = Utils.hexToColor("#FF0000");
        assertEquals(255, red.getRed());
        assertEquals(0, red.getGreen());
        assertEquals(0, red.getBlue());
        assertEquals(255, red.getAlpha());

        // Standard RGB without hash
        java.awt.Color green = Utils.hexToColor("00FF00");
        assertEquals(0, green.getRed());
        assertEquals(255, green.getGreen());
        assertEquals(0, green.getBlue());

        // ARGB (8 digits) - Assuming implementation expects AARRGGBB
        // Alpha=FF (255), Red=00, Green=00, Blue=CC
        java.awt.Color alphaBlue = Utils.hexToColor("FF0000CC");
        assertEquals(255, alphaBlue.getAlpha());
        assertEquals(0, alphaBlue.getRed());
        assertEquals(0, alphaBlue.getGreen());
        assertEquals(0xCC, alphaBlue.getBlue());

        // Test lowercase
        java.awt.Color blueLower = Utils.hexToColor("#0000ff");
        assertEquals(255, blueLower.getBlue());
    }

    /**
     * Both spellings are in use on purpose: hexToColor reads 8 digits as Java ARGB, so the CSS-looking
     * "#f09e2cff" lands on purple (the warning alerts) while the 6-digit "#f09e2c" is the orange kept
     * for the garbage alert. Pin both so neither drifts into the other.
     */
    @org.junit.jupiter.api.Test
    void eightDigitHexIsArgbAndSixDigitIsRgb() {
        java.awt.Color purple = Utils.hexToColor("#f09e2cff");
        org.junit.jupiter.api.Assertions.assertEquals(158, purple.getRed());
        org.junit.jupiter.api.Assertions.assertEquals(44, purple.getGreen());
        org.junit.jupiter.api.Assertions.assertEquals(255, purple.getBlue());

        java.awt.Color orange = Utils.hexToColor("#f09e2c");
        org.junit.jupiter.api.Assertions.assertEquals(240, orange.getRed());
        org.junit.jupiter.api.Assertions.assertEquals(158, orange.getGreen());
        org.junit.jupiter.api.Assertions.assertEquals(44, orange.getBlue());
    }
}
