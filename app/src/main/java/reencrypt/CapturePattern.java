package reencrypt;

import java.io.Serializable;
import java.util.HashMap;
import java.util.regex.Pattern;

import burp.api.montoya.MontoyaApi;

public class CapturePattern implements Serializable {
    // Fixed so adding fields later doesn't break deserialization of saved patterns
    private static final long serialVersionUID = 1L;

    boolean enabled, patchProxy, useCacheSystem, saveToLog, useProjectScope;
    String name;
    String captureRegex;
    String urlTargetRegex;
    String decCommand, encCommand;
    PatternType patternType;
    String patternInput; // The user input (header name, param name, or custom regex)
    // Engine fields (null = custom command mode, backward compatible)
    String engineId; // null | "aes" | "rsa"
    HashMap<String, String> engineParams;
    // Skip caching output that looks like a wrong-key result (default on)
    boolean detectGarbage = true;

    public CapturePattern(String name, String captureRegex, String urlTargetRegex, String decCommand, String encCommand,
            boolean enabled, boolean patchProxy, boolean useCacheSystem, boolean saveToLog, boolean useProjectScope,
            PatternType patternType, String patternInput) {
        this.enabled = enabled;
        this.captureRegex = captureRegex;
        this.urlTargetRegex = urlTargetRegex;
        this.name = name;
        this.decCommand = decCommand;
        this.encCommand = encCommand;
        this.patchProxy = patchProxy;
        this.useCacheSystem = useCacheSystem;
        this.saveToLog = saveToLog;
        this.useProjectScope = useProjectScope;
        this.patternType = patternType;
        this.patternInput = patternInput;
    }

    // Constructor for engine-based patterns
    public CapturePattern(String name, String captureRegex, String urlTargetRegex, boolean enabled, boolean patchProxy,
            boolean useCacheSystem, boolean saveToLog, boolean useProjectScope, PatternType patternType,
            String patternInput, String engineId, HashMap<String, String> engineParams) {
        this(name, captureRegex, urlTargetRegex, "", "", enabled, patchProxy, useCacheSystem, saveToLog,
                useProjectScope, patternType, patternInput);
        this.engineId = engineId;
        this.engineParams = engineParams;
    }

    // Legacy constructor for backward compatibility
    public CapturePattern(String name, String captureRegex, String urlTargetRegex, String decCommand, String encCommand,
            boolean enabled, boolean patchProxy, boolean useCacheSystem, boolean saveToLog) {
        this(name, captureRegex, urlTargetRegex, decCommand, encCommand, enabled, patchProxy, useCacheSystem, saveToLog,
                false, PatternType.CUSTOM_REGEX, captureRegex);
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getCaptureRegex() {
        return captureRegex;
    }

    public String getURLTargetRegex() {
        return urlTargetRegex;
    }

    public PatternType getPatternType() {
        return patternType;
    }

    public String getPatternInput() {
        return patternInput;
    }

    public boolean isTarget(String url, MontoyaApi api) {
        if (useProjectScope) {
            return api.scope().isInScope(url);
        }
        if (urlTargetRegex == null || urlTargetRegex.isEmpty()) {
            return true; // Empty regex matches all URLs
        }
        return Pattern.compile(urlTargetRegex).matcher(url).find();
    }

    public boolean usesProjectScope() {
        return useProjectScope;
    }

    public boolean shouldPatchProxy(String url, MontoyaApi api) {
        return patchProxy && isTarget(url, api);
    }

    public boolean shouldPatchProxy() {
        return patchProxy;
    }

    public boolean shouldUseCacheSystem() {
        return useCacheSystem;
    }

    public boolean shouldDetectGarbage() {
        return detectGarbage;
    }

    public void setDetectGarbage(boolean detectGarbage) {
        this.detectGarbage = detectGarbage;
    }

    public boolean shouldSaveToLog() {
        return saveToLog;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDecCommand() {
        return decCommand;
    }

    public String getEncCommand() {
        return encCommand;
    }

    public boolean usesEngine() {
        return engineId != null;
    }

    public String getEngineId() {
        return engineId;
    }

    public HashMap<String, String> getEngineParams() {
        return engineParams;
    }

    public CapturePattern clone() {
        CapturePattern cloned = new CapturePattern(name, captureRegex, urlTargetRegex, decCommand, encCommand, enabled,
                patchProxy, useCacheSystem, saveToLog, useProjectScope, patternType, patternInput);
        cloned.engineId = this.engineId;
        cloned.engineParams = this.engineParams != null ? new HashMap<>(this.engineParams) : null;
        cloned.detectGarbage = this.detectGarbage;
        return cloned;
    }
}
