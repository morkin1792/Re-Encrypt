package reencrypt.analysis;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

public class CiphertextLocatorTest {

    @Test
    void entropyOfUniformBytesIsHigh() {
        byte[] all = new byte[256];
        for (int i = 0; i < 256; i++) {
            all[i] = (byte) i;
        }
        assertEquals(8.0, EntropyUtil.shannonBitsPerByte(all), 0.0001);
    }

    @Test
    void entropyOfConstantIsZero() {
        byte[] same = new byte[100];
        assertEquals(0.0, EntropyUtil.shannonBitsPerByte(same), 0.0001);
    }

    @Test
    void locatesHighEntropyBodyToken() {
        String highEntropy = "Zm9vYmFyQmF6cXV4MTIzNDU2Nzg5MEFCQ0RFRkdI";
        String request = "POST /api HTTP/1.1\r\n"
                + "Host: example.com\r\n"
                + "Content-Type: application/json\r\n"
                + "\r\n"
                + "{\"data\":\"" + highEntropy + "\"}";
        int[] span = CiphertextLocator.locate(request, null, true);
        String picked = request.substring(span[0], span[1]);
        assertEquals(highEntropy, picked, "should select the high-entropy body value");
    }

    @Test
    void pastedFallsBackToWholeWhenNoStandoutToken() {
        String text = "short low entropy";
        int[] span = CiphertextLocator.locate(text, null, false);
        assertEquals(0, span[0]);
        assertEquals(text.length(), span[1]);
    }

    @Test
    void trimsSurroundingQuotesAndWhitespace() {
        int[] span = CiphertextLocator.locate("\"abc\" ", null, false);
        assertEquals("abc", "\"abc\" ".substring(span[0], span[1]));
    }

    @Test
    void emptyInputReturnsEmptyRange() {
        int[] span = CiphertextLocator.locate("", null, false);
        assertEquals(0, span[0]);
        assertTrue(span[1] == 0);
    }
}
