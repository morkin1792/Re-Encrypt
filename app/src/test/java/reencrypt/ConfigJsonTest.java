package reencrypt;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;


class ConfigJsonTest {

    private CapturePattern commandPattern() {
        return new CapturePattern("cmd", "\"data\":\"([^\"]+)\"", "example.org", "dec {FILE}", "enc {FILE}",
                true, true, true, false, false, PatternType.CUSTOM_REGEX, "\"data\":\"([^\"]+)\"");
    }

    private CapturePattern enginePattern() {
        HashMap<String, String> params = new HashMap<>();
        params.put("mode", "GCM");
        params.put("key", "s3cret");
        params.put("keyFormat", "Hex");
        return new CapturePattern("eng", "(.*)", "", true, false, false, true, false,
                PatternType.WHOLE_BODY, "", "aes", params);
    }

    @Test
    void listRoundTripKeepsEveryField() {
        List<CapturePattern> original = List.of(commandPattern(), enginePattern());
        ArrayList<CapturePattern> back = ConfigJson.listFromJson(ConfigJson.listToJson(original));

        assertEquals(2, back.size());
        CapturePattern cmd = back.get(0);
        assertEquals("cmd", cmd.getName());
        assertEquals("\"data\":\"([^\"]+)\"", cmd.getCaptureRegex());
        assertEquals("example.org", cmd.getURLTargetRegex());
        assertEquals("dec {FILE}", cmd.getDecCommand());
        assertEquals("enc {FILE}", cmd.getEncCommand());
        assertTrue(cmd.isEnabled());
        assertTrue(cmd.shouldPatchProxy());
        assertTrue(cmd.shouldUseCacheSystem());
        assertFalse(cmd.shouldSaveToLog());
        assertEquals(PatternType.CUSTOM_REGEX, cmd.getPatternType());
        assertNull(cmd.getEngineId());

        CapturePattern eng = back.get(1);
        assertEquals("aes", eng.getEngineId());
        assertEquals("GCM", eng.getEngineParams().get("mode"));
        assertEquals("s3cret", eng.getEngineParams().get("key"));
        assertEquals(PatternType.WHOLE_BODY, eng.getPatternType());
    }

    @Test
    void detectGarbageDefaultsToTrueWhenAbsent() {
        ArrayList<CapturePattern> back = ConfigJson.listFromJson("[{\"name\":\"x\"}]");
        assertTrue(back.get(0).shouldDetectGarbage());
    }

    @Test
    void unknownKeysAreIgnored() {
        ArrayList<CapturePattern> back = ConfigJson
                .listFromJson("[{\"name\":\"x\",\"somethingFromTheFuture\":42}]");
        assertEquals(1, back.size());
        assertEquals("x", back.get(0).getName());
    }

    @Test
    void badPatternTypeIsSkippedButTheRestSurvives() {
        String json = "{\"reencrypt\":1,\"patterns\":["
                + "{\"name\":\"bad\",\"patternType\":\"NOT_A_TYPE\",\"isRequest\":true},"
                + "{\"name\":\"good\",\"patternType\":\"HEADER\",\"isRequest\":true}]}";
        ConfigJson.ImportResult result = ConfigJson.fromFile(json);

        assertEquals(1, result.patterns.size());
        assertEquals("good", result.patterns.get(0).getName());
        assertEquals(1, result.errors.size());
    }

    @Test
    void newerFormatVersionIsRefused() {
        assertThrows(IllegalArgumentException.class,
                () -> ConfigJson.fromFile("{\"reencrypt\":999,\"patterns\":[]}"));
    }

    @Test
    void aFileWithoutTheVersionKeyIsRefused() {
        assertThrows(IllegalArgumentException.class, () -> ConfigJson.fromFile("{\"patterns\":[]}"));
    }

    @Test
    void patternsOnlyFileCarriesNoSettings() {
        String json = ConfigJson.toFile(List.of(commandPattern()), null, false);
        assertFalse(json.contains("\"settings\""));
        assertFalse(ConfigJson.fromFile(json).hasSettings);
    }

    @Test
    void settingsRoundTripKeepsTypes() {
        Map<String, Object> settings = new LinkedHashMap<>();
        settings.put("logFilePath", "/tmp/x.log");
        settings.put("repeaterEncryptOnlyOnModification", true);
        settings.put("reqPrintEditorHighlightColor", -256);

        ConfigJson.ImportResult result = ConfigJson
                .fromFile(ConfigJson.toFile(List.of(), settings, false));

        assertTrue(result.hasSettings);
        assertEquals("/tmp/x.log", result.settings.get("logFilePath"));
        assertEquals(Boolean.TRUE, result.settings.get("repeaterEncryptOnlyOnModification"));
        assertEquals(-256, result.settings.get("reqPrintEditorHighlightColor"));
    }

    @Test
    void stripSecretsBlanksSecretValuesNotSettings() {
        String json = ConfigJson.toFile(List.of(enginePattern()), null, true);
        CapturePattern back = ConfigJson.fromFile(json).patterns.get(0);

        assertEquals("", back.getEngineParams().get("key"));
        assertEquals("GCM", back.getEngineParams().get("mode"));
        // Named like a secret, but a setting: blanking it would silently downgrade the key format.
        assertEquals("Hex", back.getEngineParams().get("keyFormat"));
    }

    @Test
    void exchangeFilesCarryNoEnabledStateAndDefaultToActive() {
        CapturePattern disabled = new CapturePattern("off", "(.*)", "", "d", "e",
                false, false, false, false, false, PatternType.CUSTOM_REGEX, "(.*)");
        String json = ConfigJson.toFile(List.of(disabled), null, false);

        assertFalse(json.contains("\"enabled\""));
        // Auto-load has no checkbox to ask, so a pattern in a file is meant to run.
        assertTrue(ConfigJson.fromFile(json).patterns.get(0).isEnabled());
    }

    @Test
    void persistenceKeepsEnabledState() {
        CapturePattern disabled = new CapturePattern("off", "(.*)", "", "d", "e",
                false, false, false, false, false, PatternType.CUSTOM_REGEX, "(.*)");
        assertFalse(ConfigJson.listFromJson(ConfigJson.listToJson(List.of(disabled))).get(0).isEnabled());
    }

    @Test
    void filesAreIndentedButParseEitherWay() {
        String json = ConfigJson.toFile(List.of(commandPattern()), null, false);
        assertTrue(json.contains("\n  \"reencrypt\""), "exchange files are written indented");

        // A hand-minified (or agent-generated) file must import the same way.
        String minified = json.replaceAll("\\s*\\n\\s*", "");
        assertEquals("cmd", ConfigJson.fromFile(minified).patterns.get(0).getName());
    }

    @Test
    void persistenceStaysCompact() {
        assertFalse(ConfigJson.listToJson(List.of(commandPattern())).contains("\n"));
    }

    @Test
    void exportDowngradesProjectScopeToEverything() {
        CapturePattern projectScoped = new CapturePattern("p", "(.*)", "ignored", "d", "e",
                true, false, false, false, true, PatternType.CUSTOM_REGEX, "(.*)");

        CapturePattern back = ConfigJson
                .fromFile(ConfigJson.toFile(List.of(projectScoped), null, false))
                .patterns.get(0);

        // "Project In-Scope" means the receiving Burp project's scope, which a file cannot carry.
        assertFalse(back.usesProjectScope());
        assertEquals("", back.getURLTargetRegex());
    }

    @Test
    void persistenceKeepsProjectScope() {
        CapturePattern projectScoped = new CapturePattern("p", "(.*)", "", "d", "e",
                true, false, false, false, true, PatternType.CUSTOM_REGEX, "(.*)");

        ArrayList<CapturePattern> back = ConfigJson.listFromJson(ConfigJson.listToJson(List.of(projectScoped)));
        assertTrue(back.get(0).usesProjectScope());
    }
}
