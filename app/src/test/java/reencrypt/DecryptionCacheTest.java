package reencrypt;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import java.lang.reflect.Proxy;
import burp.api.montoya.persistence.PersistedObject;

public class DecryptionCacheTest {

    private DecryptionCache cache;

    @BeforeEach
    void setUp() {
        PersistedObject fakePersisted = (PersistedObject) Proxy.newProxyInstance(
                DecryptionCacheTest.class.getClassLoader(), new Class[] { PersistedObject.class },
                (proxy, method, args) -> {
                    if (method.getName().equals("getString"))
                        return null;
                    return null;
                });
        cache = new DecryptionCache(fakePersisted);
    }

    @Test
    void testPutAndGet() {
        String cipher = "cipher123";
        String plain = "decoded output";
        cache.put(cipher, plain);

        assertEquals(plain, cache.get(cipher));
        assertNull(cache.get("unknown_cipher"));
    }

    @Test
    void testClear() {
        cache.put("c1", "one");
        cache.put("c2", "two");

        assertNotNull(cache.get("c1"));
        cache.clear();
        assertNull(cache.get("c1"));
        assertNull(cache.get("c2"));
    }

    @Test
    void testCacheSizeCalculation() {
        assertEquals(0, cache.getCacheSizeInBytes());

        // Add one entry
        // Key: Hash of "test_cipher" (8 bytes)
        // Value: "test_val" (8 chars -> 8 length)
        // size = 8 + 8 = 16

        String cipher = "test_cipher";
        String val = "test_val";
        cache.put(cipher, val);
        assertEquals(16, cache.getCacheSizeInBytes());

        cache.put("another", "longer_value"); // 12 chars
        // 16 + (8 + 12) = 16 + 20 = 36
        assertEquals(36, cache.getCacheSizeInBytes());
    }
}
