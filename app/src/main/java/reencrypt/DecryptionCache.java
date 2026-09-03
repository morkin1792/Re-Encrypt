package reencrypt;

import java.util.HashMap;
import java.util.Map;

import burp.api.montoya.persistence.PersistedObject;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * Persistent cache for decryption outputs. Maps XXH128 hash (64-bit) of
 * ciphertext → plaintext result.
 */
public class DecryptionCache {
    private static final String CACHE_KEY = "decryptionCache";
    private HashMap<Long, String> cache;
    private PersistedObject persisted;

    public DecryptionCache(PersistedObject persisted) {
        this.persisted = persisted;
        load();
    }

    /**
     * Get cached plaintext for the given ciphertext.
     * 
     * @return cached plaintext or null if not found
     */
    public String get(String cipherText) {
        long hash = Utils.getHash(cipherText.getBytes());
        return cache.get(hash);
    }

    /**
     * Store plaintext result for the given ciphertext.
     */
    public void put(String cipherText, String plainText) {
        long hash = Utils.getHash(cipherText.getBytes());
        cache.put(hash, plainText);
        save();
    }

    /**
     * Clear all cached entries.
     */
    public void clear() {
        cache.clear();
        save();
    }

    /**
     * Get approximate size of cached data in bytes.
     */
    public long getCacheSizeInBytes() {
        long size = 0;
        for (String value : cache.values()) {
            // Add size of the Long key (8 bytes) plus the string value length
            size += 8;
            if (value != null) {
                size += value.length();
            }
        }
        return size;
    }

    private void load() {
        try {
            String serialized = persisted.getString(CACHE_KEY);
            cache = new HashMap<>();
            if (serialized != null && !serialized.isEmpty()) {
                // JSON object keys are strings; the cache is keyed by the ciphertext hash.
                for (Map.Entry<String, JsonElement> entry : JsonParser.parseString(serialized).getAsJsonObject().entrySet()) {
                    cache.put(Long.parseLong(entry.getKey()), entry.getValue().getAsString());
                }
            }
        } catch (Exception e) {
            System.out.println("Failed to load decryption cache: " + e.toString());
            cache = new HashMap<>();
        }
    }

    private void save() {
        try {
            JsonObject node = new JsonObject();
            for (Map.Entry<Long, String> entry : cache.entrySet()) {
                node.addProperty(Long.toString(entry.getKey()), entry.getValue());
            }
            persisted.setString(CACHE_KEY, node.toString());
        } catch (Exception e) {
            System.out.println("Failed to save decryption cache: " + e.toString());
        }
    }
}
