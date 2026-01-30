package reencrypt;

import java.io.Serializable;
import java.util.regex.Pattern;

import burp.api.montoya.MontoyaApi;

public class CapturePattern implements Serializable {
    boolean enabled, patchProxy, useCacheSystem, saveToLog, useProjectScope;
    String name;
    String captureRegex;
    String urlTargetRegex;
    String decCommand, encCommand;
    PatternType patternType;
    String patternInput; // The user input (header name, param name, or custom regex)

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

    // Legacy constructor for backward compatibility
    public CapturePattern(String name, String captureRegex, String urlTargetRegex, String decCommand, String encCommand,
            boolean enabled, boolean patchProxy, boolean useCacheSystem, boolean saveToLog) {
        this(name, captureRegex, urlTargetRegex, decCommand, encCommand, enabled, patchProxy, useCacheSystem, saveToLog,
                false, PatternType.CUSTOM_REGEX, captureRegex);
    }

    public boolean isEnabled() {
        return enabled;
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

    public CapturePattern clone() {
        return new CapturePattern(name, captureRegex, urlTargetRegex, decCommand, encCommand, enabled, patchProxy,
                useCacheSystem, saveToLog, useProjectScope, patternType, patternInput);
    }
}
