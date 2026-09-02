package reencrypt.engine;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;

import org.junit.jupiter.api.Test;

import reencrypt.GarbageDetector;

public class AesEngineTest {

    // Base64URL of {"alg":"dir","enc":"A128CTR"} - a stand-in JWE protected header
    private static final String JWE_HEADER = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q1RSIn0";

    private static final boolean IS_WINDOWS = System.getProperty("os.name").toLowerCase().contains("win");

    private HashMap<String, String> jweParams(String mode) {
        HashMap<String, String> params = new HashMap<>();
        params.put("ciphertextStructure", "jwe");
        params.put("mode", mode);
        params.put("key", "0123456789abcdef"); // 16-byte AES-128 key
        params.put("keyFormat", "UTF-8");
        params.put("keySource", "text");
        return params;
    }

    @Test
    void jweCtrRoundTripPreservesFullCiphertext() throws Exception {
        AesEngine engine = new AesEngine();
        HashMap<String, String> params = jweParams("CTR");
        // Header is normally captured during decrypt; seed it for the first encrypt.
        params.put("jweHeader", JWE_HEADER);
        params.put("jweEncryptedKey", "");

        // Longer than one AES block so the old "always chop 16 bytes as a tag" bug
        // would silently drop part of the ciphertext.
        String plaintext = "this is a secret message longer than sixteen bytes";

        String token = engine.encrypt(plaintext, params);
        String[] parts = token.split("\\.", -1);
        assertEquals(5, parts.length, "JWE compact serialization must have 5 segments");

        assertEquals(plaintext, engine.decrypt(token, params), "CTR JWE must round-trip without losing bytes");
    }

    @Test
    void jweDecryptCapturesHeaderForReEncrypt() throws Exception {
        AesEngine engine = new AesEngine();
        HashMap<String, String> params = jweParams("CTR");
        params.put("jweHeader", JWE_HEADER);
        params.put("jweEncryptedKey", "");

        String token = engine.encrypt("payload to capture from", params);

        // Simulate a fresh pattern that has not captured the header yet.
        params.remove("jweHeader");
        params.remove("jweEncryptedKey");
        params.remove("jweTag");

        engine.decrypt(token, params);

        assertEquals(JWE_HEADER, params.get("jweHeader"), "decrypt must capture the protected header");
        assertNotNull(params.get("jweTag"), "decrypt must capture the tag segment");
    }

    @Test
    void decodeBase64UrlAcceptsStandardBase64() throws Exception {
        // The IV segment from the reported failing token: standard Base64 with '+' and '=='
        byte[] iv = EncodingUtils.decodeBase64Url("vnzgATDrtpUz1uOgMqR+nA==");
        assertEquals(16, iv.length, "IV should decode to 16 bytes despite standard-Base64 chars");
    }

    @Test
    void jweCtrRoundTripWithStandardBase64Segments() throws Exception {
        AesEngine engine = new AesEngine();
        HashMap<String, String> params = new HashMap<>();
        params.put("ciphertextStructure", "jwe");
        params.put("mode", "CTR");
        params.put("key", "cIBzeufDx28EmlgGrJUObpZggt8lUXHV"); // 32-byte AES-256 key
        params.put("keyFormat", "UTF-8");
        params.put("keySource", "text");
        params.put("jweHeader", JWE_HEADER);
        params.put("jweEncryptedKey", "");
        // Emit standard Base64 (with padding) segments, like the reported token.
        params.put("jweEncoding", "standard");
        params.put("jwePadded", "true");

        String plaintext = "secret payload that exercises standard base64 segments";
        String token = engine.encrypt(plaintext, params);

        // Fresh pattern: only the key is known, encoding must be re-detected on decrypt.
        HashMap<String, String> fresh = new HashMap<>();
        fresh.put("ciphertextStructure", "jwe");
        fresh.put("mode", "CTR");
        fresh.put("key", "cIBzeufDx28EmlgGrJUObpZggt8lUXHV");
        fresh.put("keyFormat", "UTF-8");
        fresh.put("keySource", "text");

        assertEquals(plaintext, engine.decrypt(token, fresh), "standard-Base64 CTR JWE must decrypt");
        assertEquals("standard", fresh.get("jweEncoding"), "decrypt must detect the standard-Base64 style");
    }

    @Test
    void keyLoaderCommandSourceSubstitutesData() throws Exception {
        if (IS_WINDOWS) {
            return; // command uses POSIX shell syntax
        }
        HashMap<String, String> params = new HashMap<>();
        params.put("keySource", "command");
        params.put("key", "printf %s {DATA}");
        assertEquals("hello-data", KeyLoader.loadValue(params, "key", "hello-data"),
                "command source should run the command with {DATA} substituted");
    }

    @Test
    void aesRoundTripWithKeyFromCommandSource() throws Exception {
        if (IS_WINDOWS) {
            return;
        }
        AesEngine engine = new AesEngine();
        HashMap<String, String> params = new HashMap<>();
        params.put("ciphertextStructure", "raw");
        params.put("mode", "CBC");
        params.put("keySource", "command");
        params.put("key", "printf %s 0123456789abcdef"); // command emits a 16-byte key
        params.put("keyFormat", "UTF-8");
        params.put("ivSource", "text");
        params.put("iv", "abcdef9876543210");
        params.put("ivFormat", "UTF-8");
        params.put("encoding", "Base64");
        params.put("mirrorEncoding", "true");

        String plaintext = "command-sourced key works";
        String ciphertext = engine.encrypt(plaintext, params);
        assertEquals(plaintext, engine.decrypt(ciphertext, params));
    }

    @Test
    void opensslRoundTripWithHexKeyFormat() throws Exception {
        AesEngine engine = new AesEngine();
        HashMap<String, String> params = new HashMap<>();
        params.put("ciphertextStructure", "openssl");
        params.put("mode", "CBC");
        params.put("keySource", "text");
        params.put("key", "00112233445566778899aabbccddeeff"); // hex-encoded key material
        params.put("keyFormat", "Hex");
        params.put("keyDerivation", "evp_md5");
        params.put("opensslKeyLength", "32");
        params.put("encoding", "Base64");
        params.put("mirrorEncoding", "true");

        String plaintext = "openssl with a hex key";
        String ciphertext = engine.encrypt(plaintext, params);
        assertEquals(plaintext, engine.decrypt(ciphertext, params), "OpenSSL must honor the Hex key format");
    }

    @Test
    void opensslRoundTripWithUtf8KeyUnchanged() throws Exception {
        AesEngine engine = new AesEngine();
        HashMap<String, String> params = new HashMap<>();
        params.put("ciphertextStructure", "openssl");
        params.put("mode", "CBC");
        params.put("keySource", "text");
        params.put("key", "correct horse battery staple");
        params.put("keyFormat", "UTF-8");
        params.put("keyDerivation", "pbkdf2_sha256");
        params.put("pbkdf2Iterations", "10000");
        params.put("opensslKeyLength", "32");
        params.put("encoding", "Base64");
        params.put("mirrorEncoding", "true");

        String plaintext = "openssl utf-8 passphrase still works";
        String ciphertext = engine.encrypt(plaintext, params);
        assertEquals(plaintext, engine.decrypt(ciphertext, params));
    }

    @Test
    void aesCtrWrongKeyOutputIsDetectedAsGarbage() throws Exception {
        AesEngine engine = new AesEngine();
        HashMap<String, String> params = new HashMap<>();
        params.put("ciphertextStructure", "raw");
        params.put("mode", "CTR");
        params.put("keySource", "text");
        params.put("key", "0123456789abcdef");
        params.put("keyFormat", "UTF-8");
        params.put("ivSource", "text");
        params.put("iv", "abcdef9876543210");
        params.put("ivFormat", "UTF-8");
        params.put("encoding", "Base64");
        params.put("mirrorEncoding", "true");

        // Long plaintext so a wrong-key keystream reliably yields non-text output.
        String plaintext = "A".repeat(256);
        String ciphertext = engine.encrypt(plaintext, params);

        // Correct key: round-trips and is NOT flagged as garbage.
        String correct = engine.decrypt(ciphertext, params);
        assertEquals(plaintext, correct);
        assertFalse(GarbageDetector.looksLikeGarbage(correct));

        // Wrong key: decrypt does not error (CTR), but the output is detected as garbage.
        params.put("key", "ffffffffffffffff");
        String wrong = engine.decrypt(ciphertext, params);
        assertTrue(GarbageDetector.looksLikeGarbage(wrong));
    }

    @Test
    void jweGcmRoundTripStillWorks() throws Exception {
        AesEngine engine = new AesEngine();
        HashMap<String, String> params = jweParams("GCM");
        params.put("jweHeader", JWE_HEADER);
        params.put("jweEncryptedKey", "");

        String plaintext = "authenticated payload";
        String token = engine.encrypt(plaintext, params);

        assertEquals(plaintext, engine.decrypt(token, params), "GCM JWE must round-trip with its appended tag");
    }
}
