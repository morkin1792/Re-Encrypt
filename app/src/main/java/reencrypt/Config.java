package reencrypt;

import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;

import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.persistence.Persistence;

public class Config implements Serializable {
    public static final String fileMarker = "{FILE}";
    public static final String dataMarker = "{DATA}";
    private static final String cmdKeyPrefix = "sh/";

    ArrayList<CapturePattern> requestPatterns, responsePatterns;
    String decodeCommand, encodeCommand;
    boolean shouldSaveCommands, reloadRequestEditors, reloadResponseEditors;
    PersistedObject persisted;

    public Config(Persistence persistence) {
        this.persisted = persistence.extensionData();
        this.responsePatterns = getPreference("responsePatterns", new ArrayList<CapturePattern>());
        this.requestPatterns = getPreference("requestPatterns", new ArrayList<CapturePattern>());
        this.shouldSaveCommands = getPreference("shouldSaveCommands", true);
        this.reloadRequestEditors = true;
        this.reloadResponseEditors = true;
    }

    public CapturePattern[] getActivePatterns(boolean isRequest) {
        ArrayList<CapturePattern> result = new ArrayList<>();
        var patterns = isRequest ? requestPatterns
                : responsePatterns;
        for (var pattern : patterns) {
            if (pattern.isEnabled())
                result.add(pattern);
        }
        return result.toArray(new CapturePattern[0]);
    }

    private boolean getPreference(String key, boolean defaultValue) {
        Boolean preference = persisted.getBoolean(key);
        if (preference == null) {
            persisted.setBoolean(key, defaultValue);
            preference = defaultValue;
        }
        return preference;
    }

    private String getPreference(String key, String defaultValue) {
        String preference = persisted.getString(key);
        if (preference == null) {
            persisted.setString(key, defaultValue);
            preference = defaultValue;
        }
        return preference;
    }

    private <T extends Serializable> ArrayList<T> getPreference(String key, ArrayList<T> defaultValue) {
        try {
            String serialized = Utils.serialize(defaultValue);
            String preference = getPreference(key, serialized);
            return Utils.deserialize(preference);
        } catch (Exception e) {
            System.out.println("Failed to load patterns: " + e);
            return defaultValue;
        }
    }

    private <T extends Serializable> void updatePreference(String key, ArrayList<T> value) throws IOException {
        this.persisted.setString(key, Utils.serialize(value));
    }

    private void savePatterns(boolean isRequest) {
        try {
            if (isRequest) {
                updatePreference("requestPatterns", requestPatterns);
            } else {
                updatePreference("responsePatterns", responsePatterns);
            }
        } catch (Exception e) {
            System.out.println("Failed to save patterns: " + e.getMessage());
        }
    }

    public void updateSaveCommands(boolean shouldSaveCommands) {
        this.shouldSaveCommands = shouldSaveCommands;
        this.persisted.setBoolean("shouldSaveCommands", shouldSaveCommands);
    }

    void setReloadEditors(boolean isRequest) {
        if (isRequest) {
            this.reloadRequestEditors = true;
        } else {
            this.reloadResponseEditors = true;
        }
    }

    public void addPattern(CapturePattern newPattern, boolean isRequest) {
        getPatterns(isRequest).add(newPattern);
        setReloadEditors(isRequest);
        savePatterns(isRequest);
    }

    public void clonePattern(int index, boolean isRequest) {
        CapturePattern pattern = getPatterns(isRequest).get(index);
        CapturePattern newPattern = pattern.clone();
        newPattern.setName("Pattern " + (getPatterns(isRequest).size() + 1));
        addPattern(newPattern, isRequest);
        setReloadEditors(isRequest);
        savePatterns(isRequest);
    }

    public void editPattern(int index, CapturePattern newPattern, boolean isRequest) {
        getPatterns(isRequest).set(index, newPattern);
        setReloadEditors(isRequest);
        savePatterns(isRequest);
    }

    public void movePattern(int currentIndex, int newIndex, boolean isRequest) {
        if (newIndex < 0 || newIndex > getPatterns(isRequest).size() - 1)
            return;
        CapturePattern newValue = getPatterns(isRequest).get(newIndex);
        CapturePattern currentValue = getPatterns(isRequest).get(currentIndex);
        editPattern(newIndex, currentValue, isRequest);
        editPattern(currentIndex, newValue, isRequest);
        setReloadEditors(isRequest);
        savePatterns(isRequest);
    }

    public void removePattern(int index, boolean isRequest) {
        getPatterns(isRequest).remove(index);
        setReloadEditors(isRequest);
        savePatterns(isRequest);
    }

    public ArrayList<CapturePattern> getPatterns(boolean isRequest) {
        var patterns = requestPatterns;
        if (!isRequest) {
            patterns = responsePatterns;
        }
        return patterns;
    }

    public boolean shouldSaveCommands() {
        return shouldSaveCommands;
    }

    public String getCommand(String cipherText, String defaultCommand) {
        String hash = Utils.getHash(cipherText.getBytes());
        String commandLoaded = this.persisted.getString(cmdKeyPrefix + hash);
        if (commandLoaded == null) {
            if (shouldSaveCommands()) {
                this.persisted.setString(cmdKeyPrefix + hash, defaultCommand);
            }
            commandLoaded = defaultCommand;
        }
        return commandLoaded;
    }

    public boolean checkReloadEditors(boolean isRequest) {
        if (isRequest) {
            boolean result = reloadRequestEditors;
            reloadRequestEditors = false;
            return result;
        } else {
            boolean result = reloadResponseEditors;
            reloadResponseEditors = false;
            return result;
        }
    }

}
