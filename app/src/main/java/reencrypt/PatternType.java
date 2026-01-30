package reencrypt;

/**
 * Enum representing the type of capture pattern.
 */
public enum PatternType {
    HEADER("Header"), PARAMETER_URL_ENCODED("Parameter (URL-encoded)"), PARAMETER_JSON("Parameter (JSON)"),
    WHOLE_BODY("Whole Body"), CUSTOM_REGEX("Custom Regex");

    private final String displayName;

    PatternType(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }

    /**
     * Get PatternType from display name (used in dropdown).
     */
    public static PatternType fromDisplayName(String displayName) {
        for (PatternType type : values()) {
            if (type.displayName.equals(displayName)) {
                return type;
            }
        }
        return CUSTOM_REGEX; // Default fallback
    }

    /**
     * Build the regex pattern from type and input value.
     */
    public String buildRegex(String input) {
        switch (this) {
        case HEADER:
            return input.isEmpty() ? null : "(?i)" + input + ": (.*)";
        case PARAMETER_URL_ENCODED:
            return input.isEmpty() ? null : input + "=(.*?)(?:&|$)";
        case PARAMETER_JSON:
            return input.isEmpty() ? null : "\"" + input + "\":\"(.*?)\"";
        case WHOLE_BODY:
            return "\\r\\n\\r\\n(.+)";
        case CUSTOM_REGEX:
            return input;
        default:
            return null;
        }
    }

    /**
     * Get all display names for use in dropdown.
     */
    public static String[] getDisplayNames() {
        PatternType[] types = values();
        String[] names = new String[types.length];
        for (int i = 0; i < types.length; i++) {
            names[i] = types[i].displayName;
        }
        return names;
    }
}
