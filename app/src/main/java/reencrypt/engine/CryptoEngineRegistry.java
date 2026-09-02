package reencrypt.engine;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;

/**
 * Registry of all available built-in crypto engines.
 * Engines are registered in a specific order that maps to the UI dropdown.
 */
public class CryptoEngineRegistry {
    public static final String CUSTOM_COMMAND = "Custom Command";

    private static final LinkedHashMap<String, CryptoEngine> engines = new LinkedHashMap<>();

    static {
        register(new AesEngine());
        register(new RsaEngine());
    }

    public static void register(CryptoEngine engine) {
        engines.put(engine.getId(), engine);
    }

    public static CryptoEngine get(String id) {
        return engines.get(id);
    }

    /** Returns engines in registration order (for dropdown). */
    public static Collection<CryptoEngine> getAll() {
        return engines.values();
    }

    /**
     * Returns display names for the Encryption Mode dropdown.
     * First item is always "Custom Command", followed by engine display names.
     */
    public static String[] getDropdownNames() {
        List<String> names = new ArrayList<>();
        names.add(CUSTOM_COMMAND);
        for (CryptoEngine e : engines.values()) {
            names.add(e.getDisplayName());
        }
        return names.toArray(new String[0]);
    }

    /**
     * Find an engine by its display name (used when mapping dropdown selection back to engine).
     *
     * @return the engine, or null if displayName is "Custom Command" or unknown
     */
    public static CryptoEngine getByDisplayName(String displayName) {
        for (CryptoEngine e : engines.values()) {
            if (e.getDisplayName().equals(displayName)) {
                return e;
            }
        }
        return null;
    }
}
