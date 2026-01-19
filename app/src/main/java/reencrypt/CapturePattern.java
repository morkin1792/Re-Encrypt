package reencrypt;

import java.io.Serializable;
import java.util.regex.Pattern;

public class CapturePattern implements Serializable {
    boolean enabled, patchProxy, useCacheSystem, saveToLog;
    String name;
    String patternRegex;
    String urlTargetRegex;
    String decCommand, encCommand;

    public CapturePattern(String name, String patternRegex, String urlTargetRegex, String decCommand, String encCommand,
            boolean enabled, boolean patchProxy, boolean useCacheSystem, boolean saveToLog) {
        this.enabled = enabled;
        this.patternRegex = patternRegex;
        this.urlTargetRegex = urlTargetRegex;
        this.name = name;
        this.decCommand = decCommand;
        this.encCommand = encCommand;
        this.patchProxy = patchProxy;
        this.useCacheSystem = useCacheSystem;
        this.saveToLog = saveToLog;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public String getPatternRegex() {
        return patternRegex;
    }

    public String getURLTargetRegex() {
        return urlTargetRegex;
    }

    public boolean isTarget(String url) {
        return Pattern.compile(urlTargetRegex).matcher(url).find();
    }

    public boolean shouldPatchProxy(String url) {
        return patchProxy && isTarget(url);
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
        return new CapturePattern(name, patternRegex, urlTargetRegex, decCommand, encCommand, enabled, patchProxy,
                useCacheSystem, saveToLog);
    }
}
