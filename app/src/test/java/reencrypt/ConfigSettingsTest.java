package reencrypt;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import burp.api.montoya.persistence.Persistence;

/** Export/import of the settings block: a file carries only what its author changed. */
class ConfigSettingsTest {

    private static Persistence fakePersistence() {
        return FakePersistence.create();
    }

    @Test
    void anUntouchedConfigExportsNothing() {
        // Also the parity check on defaultSettings(): any default that drifts from the constructor's
        // shows up here as a stray key.
        assertTrue(new Config(fakePersistence()).exportSettings().isEmpty(),
                "defaultSettings() disagrees with the values the constructor falls back to");
    }

    @Test
    void onlyChangedSettingsAreExported() {
        Config config = new Config(fakePersistence());
        config.setIntruderPatternName("safra body");

        Map<String, Object> exported = config.exportSettings();
        assertEquals(Set.of("intruderPatternName"), exported.keySet());
        assertEquals("safra body", exported.get("intruderPatternName"));
    }

    @Test
    void importRestoresDefaultsForKeysTheFileOmits() throws Exception {
        Config config = new Config(fakePersistence());
        config.setIntruderPatternName("stale");
        config.setRepeaterEncryptOnlyOnModification(false);

        // The block is authoritative: repeaterEncryptOnlyOnModification is absent, so it resets.
        config.importSettings(Map.of("intruderPatternName", "fresh"));

        assertEquals(Set.of("intruderPatternName"), config.exportSettings().keySet());
        assertEquals("fresh", config.getIntruderPatternName());
        assertTrue(config.isRepeaterEncryptOnlyOnModification());
    }

    @Test
    void exportImportRoundTripsThroughAFile() throws Exception {
        Config source = new Config(fakePersistence());
        source.setIntruderPatternName("safra body");
        String json = ConfigJson.toFile(java.util.List.of(), source.exportSettings(), false);

        // The machine-specific log path must not travel with an untouched config.
        assertTrue(!json.contains("logFilePath"), "an unchanged logFilePath must stay out of the file");

        Config target = new Config(fakePersistence());
        target.setRepeaterEncryptOnlyOnModification(false);
        ConfigJson.ImportResult result = ConfigJson.fromFile(json);
        assertTrue(result.hasSettings);
        target.importSettings(result.settings);

        assertEquals(source.exportSettings(), target.exportSettings());
    }
}
