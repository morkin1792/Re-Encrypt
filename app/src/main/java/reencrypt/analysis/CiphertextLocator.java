package reencrypt.analysis;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import reencrypt.CapturePattern;
import reencrypt.Config;
import reencrypt.ReEncrypt;

/**
 * Locates the most likely ciphertext span within a message, for the "Auto" marker action.
 * Priority: existing request patterns -> highest-entropy token in the body -> in the
 * headers -> the whole content.
 */
public class CiphertextLocator {

    // Token characters typical of encoded ciphertext (base64/base64url/hex/JWT dotted form).
    private static final Pattern TOKEN = Pattern.compile("[A-Za-z0-9+/=_.\\-]{16,}");
    private static final double MIN_ENTROPY = 4.0; // bits/byte
    private static final int MIN_LEN = 16;

    /**
     * @param messageText   the editor content (a full HTTP request/response, or pasted text)
     * @param config        used to reuse the user's configured request patterns (may be null)
     * @param isHttpMessage true when messageText is a sent request/response (enables the
     *                      patterns step and the body/headers split)
     * @return {startInclusive, endExclusive} offsets into messageText
     */
    public static int[] locate(String messageText, Config config, boolean isHttpMessage) {
        if (messageText == null || messageText.isEmpty()) {
            return new int[] { 0, 0 };
        }
        return trimSpan(messageText, locateRaw(messageText, config, isHttpMessage));
    }

    /** Shrink a span past surrounding whitespace and one matching quote pair. */
    private static int[] trimSpan(String text, int[] span) {
        int s = span[0];
        int e = span[1];
        while (s < e && Character.isWhitespace(text.charAt(s))) {
            s++;
        }
        while (e > s && Character.isWhitespace(text.charAt(e - 1))) {
            e--;
        }
        if (e - s >= 2) {
            char a = text.charAt(s);
            char b = text.charAt(e - 1);
            if ((a == '"' && b == '"') || (a == '\'' && b == '\'')) {
                s++;
                e--;
                while (s < e && Character.isWhitespace(text.charAt(s))) {
                    s++;
                }
                while (e > s && Character.isWhitespace(text.charAt(e - 1))) {
                    e--;
                }
            }
        }
        return new int[] { s, e };
    }

    private static int[] locateRaw(String messageText, Config config, boolean isHttpMessage) {
        if (isHttpMessage && config != null) {
            for (CapturePattern p : config.getActivePatterns(true)) {
                try {
                    return ReEncrypt.searchPattern(p.getCaptureRegex(), messageText.getBytes());
                } catch (Exception e) {
                    // pattern not found in this message — try the next one
                }
            }
        }

        if (isHttpMessage) {
            int bodyStart = indexOfBody(messageText);
            if (bodyStart >= 0 && bodyStart < messageText.length()) {
                int[] body = highestEntropyToken(messageText, bodyStart, messageText.length());
                if (body != null) {
                    return body;
                }
                int[] headers = highestEntropyToken(messageText, 0, bodyStart);
                if (headers != null) {
                    return headers;
                }
            }
        } else {
            int[] whole = highestEntropyToken(messageText, 0, messageText.length());
            if (whole != null) {
                return whole;
            }
        }

        return new int[] { 0, messageText.length() };
    }

    private static int indexOfBody(String text) {
        int i = text.indexOf("\r\n\r\n");
        if (i >= 0) {
            return i + 4;
        }
        i = text.indexOf("\n\n");
        if (i >= 0) {
            return i + 2;
        }
        return -1;
    }

    private static int[] highestEntropyToken(String text, int from, int to) {
        Matcher m = TOKEN.matcher(text.subSequence(from, to));
        double best = -1;
        int bestStart = -1;
        int bestEnd = -1;
        while (m.find()) {
            String tok = m.group();
            if (tok.length() < MIN_LEN) {
                continue;
            }
            double e = EntropyUtil.shannonBitsPerByte(tok);
            if (e >= MIN_ENTROPY && e > best) {
                best = e;
                bestStart = from + m.start();
                bestEnd = from + m.end();
            }
        }
        return bestStart >= 0 ? new int[] { bestStart, bestEnd } : null;
    }
}
