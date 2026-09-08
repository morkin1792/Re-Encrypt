package reencrypt.analysis;

import java.util.HashMap;

/**
 * One analysis result: a human-readable hint plus, when actionable, what a new pattern should
 * run (see SettingsTab.createPatternFromSuggestion) -- either an engine id + params, or a pair
 * of Custom Command decode/encode commands. The two are mutually exclusive, mirroring
 * CapturePattern's own two modes.
 */
public class Suggestion {

    private final String title;
    private final String explanation;
    private final int confidence; // 0..100
    private final String engineId; // null unless this suggestion seeds a built-in engine
    private final HashMap<String, String> engineParams; // null when engineId is null
    private final String decCommand; // null unless this suggestion seeds Custom Command mode
    private final String encCommand; // null when decCommand is null

    private Suggestion(String title, String explanation, int confidence, String engineId,
            HashMap<String, String> engineParams, String decCommand, String encCommand) {
        this.title = title;
        this.explanation = explanation;
        this.confidence = confidence;
        this.engineId = engineId;
        this.engineParams = engineParams;
        this.decCommand = decCommand;
        this.encCommand = encCommand;
    }

    /** An actionable suggestion that can pre-fill a pattern (engine + params). */
    public static Suggestion engine(String title, String explanation, int confidence, String engineId,
            HashMap<String, String> params) {
        return new Suggestion(title, explanation, confidence, engineId, params, null, null);
    }

    /**
     * An actionable suggestion that pre-fills a Custom Command pattern. Used where the value is
     * not encrypted at all but still has to be decoded to be readable and re-encoded to be sent.
     */
    public static Suggestion command(String title, String explanation, int confidence, String decCommand,
            String encCommand) {
        return new Suggestion(title, explanation, confidence, null, null, decCommand, encCommand);
    }

    /** A non-actionable hint (no "Create pattern" button), e.g. "this is a signed JWT". */
    public static Suggestion info(String title, String explanation, int confidence) {
        return new Suggestion(title, explanation, confidence, null, null, null, null);
    }

    public String getTitle() {
        return title;
    }

    public String getExplanation() {
        return explanation;
    }

    public int getConfidence() {
        return confidence;
    }

    public String getEngineId() {
        return engineId;
    }

    public HashMap<String, String> getEngineParams() {
        return engineParams;
    }

    public String getDecCommand() {
        return decCommand;
    }

    public String getEncCommand() {
        return encCommand;
    }

    /** Whether this suggestion carries enough to seed a pattern (shows "Create pattern"). */
    public boolean isActionable() {
        return engineId != null || decCommand != null;
    }

    /**
     * Whether this suggestion says the value is <em>encrypted</em>. Narrower than
     * {@link #isActionable()}: an encoded-text finding can seed a pattern but is not ciphertext,
     * and the analysis UI must not count it when deciding whether a value looks like a cipher.
     */
    public boolean indicatesEncryption() {
        return engineId != null;
    }
}
