package reencrypt.ui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;

/** Pre-filling a new pattern's target scope from the message the analyzer was opened on. */
class SeedTargetTest {

    private static final String REQUEST = "POST /api/x HTTP/1.1\r\nHost: api.example.com\r\n\r\nblob";

    @Test
    void theHostBecomesAnEscapedRegex() {
        assertEquals("api\\.example\\.com", SettingsTab.targetRegexFor("https://api.example.com/api/x", REQUEST));
    }

    @Test
    void aResponseHasNoHostHeaderAndStillGetsTheUrlHost() {
        String response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\nblob";
        assertEquals("api\\.example\\.com", SettingsTab.targetRegexFor("https://api.example.com/api/x", response));
    }

    @Test
    void aStaleWindowFillsNothing() {
        // Text pasted from somewhere else: its Host disagrees with the URL the window was opened on.
        assertNull(SettingsTab.targetRegexFor("https://api.example.com/api/x",
                "GET / HTTP/1.1\r\nHost: other.test\r\n\r\n"));
    }

    @Test
    void aPortInTheHostHeaderStillMatches() {
        assertEquals("api\\.example\\.com", SettingsTab.targetRegexFor("https://api.example.com/api/x",
                "POST /api/x HTTP/1.1\r\nHost: api.example.com:8443\r\n\r\nblob"));
    }

    @Test
    void withoutAUrlNothingIsGuessed() {
        assertNull(SettingsTab.targetRegexFor(null, REQUEST));
        assertNull(SettingsTab.targetRegexFor("not a url", REQUEST));
    }
}
