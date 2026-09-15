package reencrypt.ui;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * When an editor tab may re-decode the message it is showing.
 *
 * <p>The rule exists because re-decoding is destructive: it runs {@code setBytes}, which replaces the
 * editor's text with a fresh decrypt of the original message and clears Montoya's modified flag. Burp
 * calls {@code uiComponent()} on every render, so anything that moves the patterns version — an
 * auto-load tick, an edit in the table, an import, "create pattern" — reaches into every open editor
 * on its next repaint. Landing that on a half-typed Repeater request throws the typing away and, worse,
 * leaves {@code isModified()} false, so Burp sends the untouched message and the ciphertext still
 * carries the original value.
 */
class RequestResponseTabRefreshTest {

    private static final boolean EDITING = true;
    private static final boolean IDLE = false;

    @Test
    void aPatternChangeRefreshesAnIdleEditor() {
        // The reason the refresh exists: alerts and the Print Tab must follow the current pattern set,
        // and Burp does not resend the message when a pattern changes.
        assertTrue(RequestResponseTab.shouldRefreshEditors(7, 6, 2, IDLE));
    }

    @Test
    void unsentEditsSurviveAPatternChange() {
        // The regression: a version bump while the user is typing used to re-decode over their work,
        // which both discarded the edit and cleared the modified flag, so Send went out unmodified.
        assertFalse(RequestResponseTab.shouldRefreshEditors(7, 6, 2, EDITING));
    }

    @Test
    void unsentEditsOutrankEvenAnEmptyEditorList() {
        // Edits always win. No rebuild reason may reach in while there is unsent work.
        assertFalse(RequestResponseTab.shouldRefreshEditors(7, 6, 0, EDITING));
        assertFalse(RequestResponseTab.shouldRefreshEditors(6, 6, 0, EDITING));
    }

    @Test
    void anUnchangedVersionDoesNotRefresh() {
        // Every render would otherwise re-decode, which is the same clobber by another route.
        assertFalse(RequestResponseTab.shouldRefreshEditors(6, 6, 2, IDLE));
    }

    @Test
    void anEmptyEditorListIsBuiltEvenWhenTheVersionMatches() {
        // First render of a tab: nothing has been built yet, and there is nothing to lose.
        assertTrue(RequestResponseTab.shouldRefreshEditors(6, 6, 0, IDLE));
    }

    // ---- which editors may re-encrypt back into the message ----
    //
    // The editor list holds one editor per active pattern, whatever URL the message has: only the tabs
    // are filtered. So an editor for a pattern scoped to another endpoint is present, invisible, and
    // still holding the plaintext of the last message it decoded. Every pattern captures the same
    // encrypted field, so its regex matches here too — and re-encrypting it would drop that stale text
    // over the span the user just edited, which is exactly what made a Repeater edit come back with the
    // original value while a differently-scoped pattern was enabled.

    private static final boolean IN_SCOPE = true;
    private static final boolean OTHER_ENDPOINT = false;
    private static final boolean DECODED = true;
    private static final boolean NOT_DECODED = false;

    @Test
    void anEditorThatDecodedThisMessageWritesBack() {
        assertTrue(RequestResponseTab.mayWriteBack(IN_SCOPE, DECODED));
    }

    @Test
    void aPatternScopedToAnotherEndpointNeverWritesBack() {
        // The regression: it has no tab, so nothing on screen hints that it is about to overwrite.
        assertFalse(RequestResponseTab.mayWriteBack(OTHER_ENDPOINT, DECODED));
        assertFalse(RequestResponseTab.mayWriteBack(OTHER_ENDPOINT, NOT_DECODED));
    }

    @Test
    void anEditorThatDidNotDecodeThisMessageNeverWritesBack() {
        // In scope but the decrypt failed: whatever it holds belongs to some earlier message.
        assertFalse(RequestResponseTab.mayWriteBack(IN_SCOPE, NOT_DECODED));
    }

    @Test
    void theRefreshIsNotConsumedWhileEditsAreHeld() {
        // The caller leaves renderedPatternsVersion stale on a skip, so the pending refresh is
        // deferred rather than lost: the same inputs refresh once the edits are gone.
        assertFalse(RequestResponseTab.shouldRefreshEditors(9, 6, 2, EDITING));
        assertTrue(RequestResponseTab.shouldRefreshEditors(9, 6, 2, IDLE));
    }
}
