package reencrypt;

import java.io.IOException;
import java.util.HashMap;

import burp.api.montoya.persistence.PersistedObject;

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
            if (serialized != null && !serialized.isEmpty()) {
                cache = Utils.deserializeMap(serialized);
            } else {
                cache = new HashMap<>();
            }
        } catch (Exception e) {
            System.out.println("Failed to load decryption cache: " + e.getMessage());
            cache = new HashMap<>();
        }
    }

    private void save() {
        try {
            String serialized = Utils.serializeMap(cache);
            persisted.setString(CACHE_KEY, serialized);
        } catch (IOException e) {
            System.out.println("Failed to save decryption cache: " + e.getMessage());
        }
    }
}
