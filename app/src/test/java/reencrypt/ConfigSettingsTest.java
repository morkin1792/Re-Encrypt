package reencrypt;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.persistence.Persistence;

/** Export/import of the settings block: a file carries only what its author changed. */
class ConfigSettingsTest {

    /** Persistence backed by a plain map, so getPreference's write-back behaves like the real one. */
    private static Persistence fakePersistence() {
        Map<String, Object> store = new HashMap<>();
        PersistedObject persisted = (PersistedObject) Proxy.newProxyInstance(
                ConfigSettingsTest.class.getClassLoader(), new Class[] { PersistedObject.class },
                (proxy, method, args) -> {
                    String name = method.getName();
                    if (name.equals("toString")) {
                        return "fakePersistedObject";
                    }
                    if (name.startsWith("get") && args != null && args.length == 1) {
                        return store.get(args[0]);
                    }
                    if (name.startsWith("set") && args != null && args.length == 2) {
                        store.put((String) args[0], args[1]);
                        return null;
                    }
                    return null;
                });
        return (Persistence) Proxy.newProxyInstance(ConfigSettingsTest.class.getClassLoader(),
                new Class[] { Persistence.class },
                (proxy, method, args) -> method.getName().equals("extensionData") ? persisted : null);
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
        config.setIntruderEncryptCommand("node enc.js {FILE}");

        Map<String, Object> exported = config.exportSettings();
        assertEquals(Set.of("intruderEncryptCommand"), exported.keySet());
        assertEquals("node enc.js {FILE}", exported.get("intruderEncryptCommand"));
    }

    @Test
    void importRestoresDefaultsForKeysTheFileOmits() throws Exception {
        Config config = new Config(fakePersistence());
        config.setIntruderEncryptCommand("stale");
        config.setRepeaterEncryptOnlyOnModification(false);

        // The block is authoritative: repeaterEncryptOnlyOnModification is absent, so it resets.
        config.importSettings(Map.of("intruderEncryptCommand", "fresh"));

        assertEquals(Set.of("intruderEncryptCommand"), config.exportSettings().keySet());
        assertEquals("fresh", config.getIntruderEncryptCommand());
        assertTrue(config.isRepeaterEncryptOnlyOnModification());
    }

    @Test
    void exportImportRoundTripsThroughAFile() throws Exception {
        Config source = new Config(fakePersistence());
        source.setIntruderEncryptCommand("node enc.js {FILE}");
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
