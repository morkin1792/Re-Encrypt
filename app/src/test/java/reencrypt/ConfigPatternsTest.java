package reencrypt;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Test;

import burp.api.montoya.persistence.Persistence;

/** One ordered list holding both directions: storage, migration and reordering. */
class ConfigPatternsTest {

    private final Map<String, Object> store = new HashMap<>();

    private Persistence persistence() {
        return FakePersistence.create(store);
    }

    private static CapturePattern pattern(String name, boolean isRequest) {
        CapturePattern p = new CapturePattern(name, "(.*)", "", "d", "e",
                true, false, false, false, false, PatternType.CUSTOM_REGEX, "(.*)");
        p.setRequest(isRequest);
        return p;
    }

    private static String names(List<CapturePattern> patterns) {
        return patterns.stream().map(p -> p.getName() + (p.isRequest() ? "(req)" : "(resp)"))
                .collect(Collectors.joining(" "));
    }

    @Test
    void legacySplitStorageBecomesOneListRequestsFirst() {
        store.put("requestPatterns", "[{\"name\":\"A\",\"captureRegex\":\"(.*)\"},"
                + "{\"name\":\"B\",\"captureRegex\":\"(.*)\"}]");
        store.put("responsePatterns", "[{\"name\":\"X\",\"captureRegex\":\"(.*)\"}]");

        Config config = new Config(persistence());

        assertEquals("A(req) B(req) X(resp)", names(config.getPatterns()));
        // The old keys are dropped, so the merge happens once and cannot resurrect stale copies.
        assertNull(store.get("requestPatterns"));
        assertNull(store.get("responsePatterns"));
        assertFalse(((String) store.get("patterns")).isEmpty());
    }

    @Test
    void aStoredListRoundTripsWithItsOrderAndDirections() {
        Config config = new Config(persistence());
        config.addPattern(pattern("a", true));
        config.addPattern(pattern("x", false));
        config.addPattern(pattern("b", true));

        assertEquals("a(req) x(resp) b(req)", names(new Config(persistence()).getPatterns()));
    }

    @Test
    void patternsMoveFreelyPastTheOtherDirection() {
        Config config = new Config(persistence());
        config.addPattern(pattern("a", true));
        config.addPattern(pattern("x", false));
        config.addPattern(pattern("b", true));

        config.movePattern(2, 1); // b jumps above the response pattern
        assertEquals("a(req) b(req) x(resp)", names(config.getPatterns()));

        config.movePattern(0, 2); // a drops to the bottom, past x
        assertEquals("b(req) x(resp) a(req)", names(config.getPatterns()));
    }

    @Test
    void perDirectionViewsKeepRelativeOrder() {
        Config config = new Config(persistence());
        config.addPattern(pattern("a", true));
        config.addPattern(pattern("x", false));
        config.addPattern(pattern("b", true));
        config.getPatterns().get(2).setEnabled(false);

        assertEquals("a(req) b(req)", names(config.getPatterns(true)));
        assertEquals("x(resp)", names(config.getPatterns(false)));
        assertEquals("a(req)", names(new ArrayList<>(List.of(config.getActivePatterns(true)))));
    }

    @Test
    void mergeByNameReplacesInPlaceAndLeavesTheRestAlone() {
        Config config = new Config(persistence());
        config.addPattern(pattern("a", true));
        config.addPattern(pattern("x", false));

        // "x" comes back as a request pattern; "new" is unknown; "a" is not mentioned at all.
        Config.MergeResult merge = config.mergePatternsByName(List.of(pattern("x", true), pattern("new", true)));

        assertEquals(1, merge.replaced);
        assertEquals(1, merge.added);
        assertTrue(merge.changed);
        assertEquals("a(req) x(req) new(req)", names(config.getPatterns()));
    }

    @Test
    void reapplyingTheSameFileChangesNothing() {
        Config config = new Config(persistence());
        config.addPattern(pattern("a", true));

        // Auto-load applies the file on every tick; an unchanged file must not churn the table.
        assertFalse(config.mergePatternsByName(List.of(pattern("a", true))).changed);
    }

    @Test
    void aPatternDeletedInBurpComesBackOnTheNextTick() {
        Config config = new Config(persistence());
        config.addPattern(pattern("a", true));
        config.removePattern(0);

        Config.MergeResult merge = config.mergePatternsByName(List.of(pattern("a", true)));

        assertTrue(merge.changed);
        assertEquals(1, merge.added);
        assertEquals("a(req)", names(config.getPatterns()));
    }

    @Test
    void aFileKeepsTheMixedOrder() {
        Config config = new Config(persistence());
        config.addPattern(pattern("a", true));
        config.addPattern(pattern("x", false));
        config.addPattern(pattern("b", true));

        String json = ConfigJson.toFile(config.getPatterns(), null, false);
        assertEquals("a(req) x(resp) b(req)", names(ConfigJson.fromFile(json).patterns));
    }
}
