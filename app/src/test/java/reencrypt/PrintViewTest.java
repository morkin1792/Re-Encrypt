package reencrypt;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

import com.google.gson.JsonParser;

/**
 * The two things that kept Burp's Pretty tab from formatting the Print Tab: a Content-Length left over
 * from the ciphertext, and plaintext JSON spliced into a JSON string.
 */
class PrintViewTest {

    private static String str(byte[] b) {
        return new String(b, StandardCharsets.ISO_8859_1);
    }

    private static byte[] bytes(String s) {
        return s.getBytes(StandardCharsets.ISO_8859_1);
    }

    private static CapturePattern jsonParam() {
        // Captures the value inside "data":"..."
        return new CapturePattern("data", "\"data\":\"(.*?)\"", "", "d", "e",
                true, false, false, false, false, PatternType.CUSTOM_REGEX, "\"data\":\"(.*?)\"");
    }

    @Test
    void contentLengthIsCorrectedToTheBodyActuallyPresent() {
        byte[] message = bytes("POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 999\r\n\r\n{\"a\":1}");
        int[] shift = new int[2];

        String fixed = str(ReEncrypt.fixContentLength(message, shift));

        assertTrue(fixed.contains("Content-Length: 7"), fixed);
        assertTrue(fixed.endsWith("{\"a\":1}"), "the body must be untouched");
        assertEquals(-2, shift[1], "999 -> 7 removes two bytes, so later offsets move back two");
    }

    @Test
    void aMessageWithoutContentLengthIsLeftAlone() {
        byte[] message = bytes("POST /x HTTP/1.1\r\nHost: h\r\n\r\n{\"a\":1}");
        int[] shift = new int[2];
        assertEquals(str(message), str(ReEncrypt.fixContentLength(message, shift)));
        assertEquals(0, shift[1]);
    }

    @Test
    void anAlreadyCorrectContentLengthReportsNoShift() {
        byte[] message = bytes("POST /x HTTP/1.1\r\nContent-Length: 7\r\n\r\n{\"a\":1}");
        int[] shift = new int[2];
        ReEncrypt.fixContentLength(message, shift);
        assertEquals(0, shift[1]);
    }

    /** The whole point: after unquoting, the print view is a JSON document Pretty can format. */
    @Test
    void jsonPlaintextNestsAsAnObjectInsteadOfBreakingTheDocument() throws Exception {
        ReEncrypt reEncrypt = new ReEncrypt(null);
        byte[] body = bytes("{\"data\":\"CIPHERTEXT\"}");
        String plain = "{\"idEstrategia\":\"prelogin\"}";

        String plainSplice = str(reEncrypt.matchReplace(body, jsonParam(), plain));
        assertThrowsJson(plainSplice); // what it used to produce

        String unquoted = str(reEncrypt.matchReplaceUnquoting(body, jsonParam(), plain, new int[3]));
        assertEquals("{\"data\":{\"idEstrategia\":\"prelogin\"}}", unquoted);
        JsonParser.parseString(unquoted); // parses, so Pretty has something to format
    }

    @Test
    void nonJsonPlaintextKeepsItsQuotes() throws Exception {
        ReEncrypt reEncrypt = new ReEncrypt(null);
        byte[] body = bytes("{\"data\":\"CIPHERTEXT\"}");
        String unquoted = str(reEncrypt.matchReplaceUnquoting(body, jsonParam(), "user=jodson", new int[3]));
        assertEquals("{\"data\":\"user=jodson\"}", unquoted);
    }

    @Test
    void onlyRealJsonCountsAsJson() {
        assertTrue(ReEncrypt.looksLikeJson("{\"a\":1}"));
        assertTrue(ReEncrypt.looksLikeJson("  [1,2] "));
        assertFalse(ReEncrypt.looksLikeJson("{\"a\":"), "a truncated object must not be unquoted");
        assertFalse(ReEncrypt.looksLikeJson("plain text"));
        assertFalse(ReEncrypt.looksLikeJson(""));
        assertFalse(ReEncrypt.looksLikeJson(null));
    }

    @Test
    void unquotingReportsTheWiderSpanSoHighlightsStayAligned() throws Exception {
        ReEncrypt reEncrypt = new ReEncrypt(null);
        byte[] body = bytes("{\"data\":\"CIPHERTEXT\"}");
        int[] span = new int[3]; // {newStart, newEnd, oldEnd}
        reEncrypt.matchReplaceUnquoting(body, jsonParam(), "{\"a\":1}", span);

        assertEquals(str(body).indexOf('"', str(body).indexOf("data\":") + 5), span[0],
                "the replacement starts at the opening quote it swallowed");
        assertEquals(str(body).length() - 1, span[2], "and ends past the closing quote");
    }

    /**
     * The corruption this replaced: two patterns matching the same value were applied one after the
     * other, so the second regex ran over text the first had substituted, matched a quote inside it and
     * spliced the payload in a second time. Every span is now measured against the original content.
     */
    @Test
    void twoPatternsOnTheSameValueCannotDuplicateThePayload() throws Exception {
        ReEncrypt reEncrypt = new ReEncrypt(null);
        byte[] body = bytes("{\"data\":\"CIPHERTEXT\"}");
        String plain = "{\"agencia\":\"07100\",\"conta\":\"7729648\"}";

        // Two active patterns capturing the same value - the shape that produced the duplication.
        CapturePattern first = jsonParam();
        CapturePattern second = jsonParam();

        java.util.List<ReEncrypt.Replacement> plan = new java.util.ArrayList<>();
        for (CapturePattern p : java.util.List.of(first, second)) {
            int[] span = ReEncrypt.replacementSpan(body, p, plain);
            plan.add(new ReEncrypt.Replacement(span[0], span[1], plain.getBytes("Windows-1252")));
        }
        java.util.List<int[]> spans = new java.util.ArrayList<>();
        String out = str(ReEncrypt.applyReplacements(body, plan, spans));

        assertEquals("{\"data\":{\"agencia\":\"07100\",\"conta\":\"7729648\"}}", out);
        assertEquals(1, spans.size(), "the second pattern claims the same bytes, so only one applies");
        JsonParser.parseString(out);
        assertEquals(1, out.split("agencia", -1).length - 1, "the payload must appear exactly once");
    }

    @Test
    void separatePatternsBothApplyAndReportWhereTheyLanded() throws Exception {
        byte[] body = bytes("{\"a\":\"AAA\",\"b\":\"BBB\"}");
        CapturePattern pa = new CapturePattern("a", "\"a\":\"(.*?)\"", "", "d", "e",
                true, false, false, false, false, PatternType.CUSTOM_REGEX, "\"a\":\"(.*?)\"");
        CapturePattern pb = new CapturePattern("b", "\"b\":\"(.*?)\"", "", "d", "e",
                true, false, false, false, false, PatternType.CUSTOM_REGEX, "\"b\":\"(.*?)\"");

        java.util.List<ReEncrypt.Replacement> plan = new java.util.ArrayList<>();
        plan.add(new ReEncrypt.Replacement(ReEncrypt.replacementSpan(body, pa, "1")[0],
                ReEncrypt.replacementSpan(body, pa, "1")[1], bytes("1")));
        plan.add(new ReEncrypt.Replacement(ReEncrypt.replacementSpan(body, pb, "22222")[0],
                ReEncrypt.replacementSpan(body, pb, "22222")[1], bytes("22222")));

        java.util.List<int[]> spans = new java.util.ArrayList<>();
        String out = str(ReEncrypt.applyReplacements(body, plan, spans));

        assertEquals("{\"a\":\"1\",\"b\":\"22222\"}", out);
        assertEquals(2, spans.size());
        // Spans are in FINAL coordinates: the second must account for the first changing the length.
        assertEquals("1", out.substring(spans.get(0)[0], spans.get(0)[1]));
        assertEquals("22222", out.substring(spans.get(1)[0], spans.get(1)[1]));
    }

    private static void assertThrowsJson(String candidate) {
        try {
            JsonParser.parseString(candidate);
            throw new AssertionError("expected invalid JSON, got: " + candidate);
        } catch (RuntimeException expected) {
            // exactly the breakage that left Pretty with nothing to do
        }
    }
}
