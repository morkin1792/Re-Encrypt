package reencrypt.analysis;

import java.util.HashMap;

/**
 * One analysis result: a human-readable hint plus, when actionable, the engine id and
 * params needed to seed a new pattern (see SettingsTab.createPatternFromSuggestion).
 */
public class Suggestion {

    private final String title;
    private final String explanation;
    private final int confidence; // 0..100
    private final String engineId; // null = non-actionable info
    private final HashMap<String, String> engineParams; // null when engineId is null

    private Suggestion(String title, String explanation, int confidence, String engineId,
            HashMap<String, String> engineParams) {
        this.title = title;
        this.explanation = explanation;
        this.confidence = confidence;
        this.engineId = engineId;
        this.engineParams = engineParams;
    }

    /** An actionable suggestion that can pre-fill a pattern (engine + params). */
    public static Suggestion engine(String title, String explanation, int confidence, String engineId,
            HashMap<String, String> params) {
        return new Suggestion(title, explanation, confidence, engineId, params);
    }

    /** A non-actionable hint (no "Create pattern" button), e.g. "this is a signed JWT". */
    public static Suggestion info(String title, String explanation, int confidence) {
        return new Suggestion(title, explanation, confidence, null, null);
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

    public boolean isActionable() {
        return engineId != null;
    }
}
