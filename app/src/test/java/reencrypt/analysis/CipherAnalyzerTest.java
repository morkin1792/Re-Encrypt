package reencrypt.analysis;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.junit.jupiter.api.Test;

import reencrypt.analysis.CipherAnalyzer.AnalysisResult;

public class CipherAnalyzerTest {

    private static String b64url(String s) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }

    private static Suggestion encodedTextNote(AnalysisResult r) {
        for (Suggestion s : r.suggestions) {
            if (s.getTitle().toLowerCase().contains("encoded text")) {
                return s;
            }
        }
        return null;
    }

    private static Suggestion firstEngine(AnalysisResult r, String engineId) {
        for (Suggestion s : r.suggestions) {
            if (engineId.equals(s.getEngineId())) {
                return s;
            }
        }
        return null;
    }

    @Test
    void detectsJwtAsSignedNotEncrypted() {
        String jwt = b64url("{\"alg\":\"HS256\",\"typ\":\"JWT\"}") + "." + b64url("{\"sub\":\"1\"}") + ".AAAA";
        AnalysisResult r = CipherAnalyzer.analyze(jwt);
        assertFalse(r.suggestions.isEmpty());
        Suggestion top = r.suggestions.get(0);
        assertTrue(top.getTitle().contains("JWT"));
        assertFalse(top.isActionable(), "a signed JWT should not be actionable (nothing to decrypt)");
        assertNull(firstEngine(r, "aes"), "JWT should not yield an AES engine suggestion");
    }

    @Test
    void detectsJweGcm() {
        String jwe = b64url("{\"alg\":\"dir\",\"enc\":\"A256GCM\"}") + ".AA.BB.CC.DD";
        AnalysisResult r = CipherAnalyzer.analyze(jwe);
        Suggestion aes = firstEngine(r, "aes");
        assertNotNull(aes, "JWE should yield an AES suggestion");
        assertEquals("jwe", aes.getEngineParams().get("ciphertextStructure"));
        assertEquals("GCM", aes.getEngineParams().get("mode"));
    }

    @Test
    void detectsNonstandardJweCtr() {
        String jwe = b64url("{\"alg\":\"RSA-OAEP\",\"enc\":\"A256CTR\"}") + ".AA.BB.CC.DD";
        AnalysisResult r = CipherAnalyzer.analyze(jwe);
        Suggestion aes = firstEngine(r, "aes");
        assertNotNull(aes);
        assertEquals("jwe", aes.getEngineParams().get("ciphertextStructure"));
        assertEquals("CTR", aes.getEngineParams().get("mode"));
    }

    @Test
    void detectsQuoteWrappedJwe() {
        String jwe = b64url("{\"alg\":\"dir\",\"enc\":\"A256GCM\"}") + ".AA.BB.CC.DD";
        AnalysisResult r = CipherAnalyzer.analyze("\"" + jwe + "\"");
        Suggestion aes = firstEngine(r, "aes");
        assertNotNull(aes, "a quote-wrapped JWE should still be detected");
        assertEquals("jwe", aes.getEngineParams().get("ciphertextStructure"));
    }

    @Test
    void detectsOpenSslSalted() {
        byte[] raw = new byte[8 + 8 + 16];
        byte[] magic = "Salted__".getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(magic, 0, raw, 0, 8);
        for (int i = 16; i < raw.length; i++) {
            raw[i] = (byte) (i * 7); // pseudo-random ciphertext bytes
        }
        String b64 = Base64.getEncoder().encodeToString(raw);
        AnalysisResult r = CipherAnalyzer.analyze(b64);
        Suggestion aes = firstEngine(r, "aes");
        assertNotNull(aes);
        assertEquals("openssl", aes.getEngineParams().get("ciphertextStructure"));
    }

    @Test
    void detectsBase64WrappedJwe() {
        String jwe = b64url("{\"alg\":\"dir\",\"enc\":\"A128GCM\"}") + ".AA.BB.CC.DD";
        String wrapped = Base64.getEncoder().encodeToString(jwe.getBytes(StandardCharsets.UTF_8));
        AnalysisResult r = CipherAnalyzer.analyze(wrapped);
        Suggestion aes = firstEngine(r, "aes");
        assertNotNull(aes, "a Base64-wrapped JWE should still be detected");
        assertEquals("jwe", aes.getEngineParams().get("ciphertextStructure"));
    }

    @Test
    void blockSizeHintForAesMultipleOf16() {
        byte[] raw = new byte[48]; // multiple of 16, not an RSA size
        for (int i = 0; i < raw.length; i++) {
            raw[i] = (byte) (i * 31 + 5);
        }
        AnalysisResult r = CipherAnalyzer.analyze(Base64.getEncoder().encodeToString(raw));
        Suggestion aes = firstEngine(r, "aes");
        assertNotNull(aes);
        assertEquals("CBC", aes.getEngineParams().get("mode"));
    }

    @Test
    void splitsTwoDotConcatenatedCiphertexts() {
        String two = "R30lA2wRkJCXjg2ejLFhhIbC1CNTdsff6zPwy+Wa8iEfiAsOjgf9a9Y//q45TuUpZLrftZThctijGoek"
                + "BYuPGFegfSQdx5BQmscCgTgIZr1gRHy76RA2pFcjogZMsGxLUj6V2sG3WUhNcwOpTvOZ7nrhvXtgJv5URnMZ9B9a49w="
                + ".ZxxovJU5s4WCosVWT/6KrcIZuf7SuGz/pvcyceCFDoYdf4XBvEbZnHV4upmft2KxnYRVPdQXjJN1H5IK6yMNaUujZT9V"
                + "Hi2UpG6tRBCLPwsQhN8KdefpqXJZgW0LSMT5vXFQln1yFmFDZxSOz9dJXNY8GAjMumXt1DPEynEk+ak=";
        CipherAnalyzer.SplitResult sr = CipherAnalyzer.bestSplit(two);
        assertEquals(2, sr.parts.size(), "dot-joined ciphertexts should split into two parts");
        assertTrue(sr.reason.contains("'.'"), "reason should name the delimiter: " + sr.reason);
        assertTrue(two.startsWith(sr.parts.get(0)));
        assertTrue(two.endsWith(sr.parts.get(1)));
    }

    @Test
    void splitsCiphertextsWithTrailingJunkPart() {
        String two = "R30lA2wRkJCXjg2ejLFhhIbC1CNTdsff6zPwy+Wa8iEfiAsOjgf9a9Y//q45TuUpZLrftZThctijGoek"
                + "BYuPGFegfSQdx5BQmscCgTgIZr1gRHy76RA2pFcjogZMsGxLUj6V2sG3WUhNcwOpTvOZ7nrhvXtgJv5URnMZ9B9a49w=";
        String b = "ZxxovJU5s4WCosVWT/6KrcIZuf7SuGz/pvcyceCFDoYdf4XBvEbZnHV4upmft2KxnYRVPdQXjJN1H5IK6yMNaUujZT9V"
                + "Hi2UpG6tRBCLPwsQhN8KdefpqXJZgW0LSMT5vXFQln1yFmFDZxSOz9dJXNY8GAjMumXt1DPEynEk+ak=";
        // Two real ciphertexts plus a short trailing flag — should still split (3 parts shown).
        CipherAnalyzer.SplitResult sr = CipherAnalyzer.bestSplit(two + "." + b + ".aaa");
        assertEquals(3, sr.parts.size(), "a trailing junk part should not block the split");
        assertTrue(sr.reason.contains("'.'"));
        assertEquals("aaa", sr.parts.get(2));
    }

    @Test
    void splitsOnPipeDelimiter() {
        byte[] x = new byte[24];
        byte[] y = new byte[24];
        for (int i = 0; i < 24; i++) {
            x[i] = (byte) (i * 31 + 5);
            y[i] = (byte) (i * 47 + 11);
        }
        String a = Base64.getEncoder().encodeToString(x); // Base64 of binary → ciphertext-like
        String b = Base64.getEncoder().encodeToString(y);
        CipherAnalyzer.SplitResult sr = CipherAnalyzer.bestSplit(a + "|" + b);
        assertEquals(2, sr.parts.size());
        assertTrue(sr.reason.contains("'|'"), "reason should name the pipe delimiter: " + sr.reason);
    }

    @Test
    void splitsEncodedBlobsEvenWhenNoneAreConfirmedCiphertext() {
        // Two Base64 blobs of readable text joined by '.': none decode to binary ciphertext, but
        // splitting and trying each is still useful, so the split should be offered.
        String a = Base64.getEncoder().encodeToString("the first readable data chunk!!".getBytes(StandardCharsets.UTF_8));
        String b = Base64.getEncoder().encodeToString("and the second readable data chunk".getBytes(StandardCharsets.UTF_8));
        CipherAnalyzer.SplitResult sr = CipherAnalyzer.bestSplit(a + "." + b);
        assertEquals(2, sr.parts.size(), "two encoded blobs should split even without a confirmed ciphertext");
        assertFalse(CipherAnalyzer.isCiphertextPart(sr.parts.get(0)));
        assertFalse(CipherAnalyzer.isCiphertextPart(sr.parts.get(1)));
    }

    @Test
    void splitsShortMetadataPlusKey() {
        // "RSA" (short, decodes cleanly) + a long PEM blob: one substantial blob + one clean
        // token → should still split into two parts.
        String value = "UlNB.LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BMEdDU3FHU0liM0RRRUJBUVVBQTRHTkFEQ0Jp"
                + "UUtCZ1FDdVR0Vjc0RWNvYTFVU3hENFlMeXZpSnhCTgozOTZWeHJXZlhFTG5lQ2N5a0t2SWdaYXVQYWtrTjFqSW42"
                + "NURLRWVOVEtsWFg5QmdPZ1VlbHdQQm8xR21qTFU2CmpmaVpQeTUyWE9LZ1pYWVdKVmxnR2ozUjIvTlplK2YyQWVN"
                + "M1R2NDA4S295NmNsd1B5U0MrMmkrZFlxN3E5M0gKYXBiTHpDWHNhYjIyU3Y0K2p3SURBUUFCCi0tLS0tRU5EIFBV"
                + "QkxJQyBLRVktLS0tLQ==";
        CipherAnalyzer.SplitResult sr = CipherAnalyzer.bestSplit(value);
        assertEquals(2, sr.parts.size(), "short metadata + a key blob should split into two parts");
        assertEquals("UlNB", sr.parts.get(0));
    }

    @Test
    void doesNotSplitSingleBase64OfText() {
        // Base64 of a PEM public key: one encoding of readable text, not several ciphertexts.
        String pem = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BMEdDU3FHU0liM0RRRUJBUVVBQTRHTkFEQ0JpUUtC"
                + "Z1FDdVR0Vjc0RWNvYTFVU3hENFlMeXZpSnhCTgozOTZWeHJXZlhFTG5lQ2N5a0t2SWdaYXVQYWtrTjFqSW42NURLR"
                + "WVOVEtsWFg5QmdPZ1VlbHdQQm8xR21qTFU2CmpmaVpQeTUyWE9LZ1pYWVdKVmxnR2ozUjIvTlplK2YyQWVNM1R2N"
                + "DA4S295NmNsd1B5U0MrMmkrZFlxN3E5M0gKYXBiTHpDWHNhYjIyU3Y0K2p3SURBUUFCCi0tLS0tRU5EIFBVQkxJQy"
                + "BLRVktLS0tLQ==";
        assertTrue(CipherAnalyzer.bestSplit(pem).parts.isEmpty(), "a single Base64 of text must not be split");
        AnalysisResult r = CipherAnalyzer.analyze(pem);
        assertNull(firstEngine(r, "aes"));
        assertNull(firstEngine(r, "rsa"));
        assertTrue(r.suggestions.stream().anyMatch(s -> s.getTitle().toLowerCase().contains("encoded text")),
                "should be recognized as encoded text, not ciphertext");
    }

    @Test
    void reportsOneEncodedTextNoteForSingleBase64() {
        String value = Base64.getEncoder().encodeToString("user=admin&role=superuser".getBytes(StandardCharsets.UTF_8));
        AnalysisResult r = CipherAnalyzer.analyze(value);
        long notes = r.suggestions.stream().filter(s -> s.getTitle().toLowerCase().contains("encoded text")).count();
        assertEquals(1, notes, "a plain Base64 of text must yield exactly one encoded-text note");
        Suggestion s = encodedTextNote(r);
        assertTrue(s.getExplanation().startsWith("Base64 decoding gives a readable text:"),
                "single-layer note should name just the one encoding: " + s.getExplanation());
        assertTrue(s.getExplanation().contains("user=admin&role=superuser"));
        assertFalse(s.getExplanation().contains("Intermediate layers"),
                "a single layer has no intermediates to list");
    }

    @Test
    void encodedTextNoteSeedsCustomCommands() {
        String value = Base64.getEncoder().encodeToString("user=admin&role=superuser".getBytes(StandardCharsets.UTF_8));
        Suggestion s = encodedTextNote(CipherAnalyzer.analyze(value));
        assertTrue(s.isActionable(), "an encoded value still needs a pattern to decode/re-encode it");
        assertFalse(s.indicatesEncryption(), "encoding is not encryption; the analysis UI must not call it a cipher");
        assertNull(s.getEngineId(), "encoded text is Custom Command mode, not an engine");
        assertEquals(EncodingCommands.decodeCommand(java.util.Arrays.asList("Base64")), s.getDecCommand());
        assertEquals(EncodingCommands.encodeCommand(java.util.Arrays.asList("Base64")), s.getEncCommand());
    }

    @Test
    void nestedEncodedTextSeedsTheWholeChain() {
        String inner = Base64.getEncoder().encodeToString("user=admin&role=superuser".getBytes(StandardCharsets.UTF_8));
        String value = Base64.getEncoder().encodeToString(inner.getBytes(StandardCharsets.UTF_8));
        Suggestion s = encodedTextNote(CipherAnalyzer.analyze(value));
        assertEquals(EncodingCommands.decodeCommand(java.util.Arrays.asList("Base64", "Base64")), s.getDecCommand());
        assertEquals(EncodingCommands.encodeCommand(java.util.Arrays.asList("Base64", "Base64")), s.getEncCommand());
    }

    @Test
    void peelsNestedBase64DownToThePlaintext() {
        String inner = Base64.getEncoder().encodeToString("user=admin&role=superuser".getBytes(StandardCharsets.UTF_8));
        String value = Base64.getEncoder().encodeToString(inner.getBytes(StandardCharsets.UTF_8));
        Suggestion s = encodedTextNote(CipherAnalyzer.analyze(value));
        assertTrue(s.getExplanation().startsWith("Base64 \u2192 Base64 decoding gives a readable text:"),
                "the note should name the whole chain: " + s.getExplanation());
        assertTrue(s.getExplanation().contains("user=admin&role=superuser"), "should reach the final plaintext");
        assertTrue(s.getExplanation().contains("1. after Base64: " + inner),
                "the intermediate layer must still be shown: " + s.getExplanation());
    }

    @Test
    void peelStopsAtTextThatOnlyLooksEncoded() {
        // "deadbeefcafe" is valid Hex, and its decode is binary -- the peel must stop at the text.
        String value = Base64.getEncoder().encodeToString("deadbeefcafe".getBytes(StandardCharsets.UTF_8));
        Suggestion s = encodedTextNote(CipherAnalyzer.analyze(value));
        assertTrue(s.getExplanation().startsWith("Base64 decoding gives a readable text:"),
                "a layer decoding to non-text must not be peeled: " + s.getExplanation());
        assertTrue(s.getExplanation().contains("deadbeefcafe"));
    }

    @Test
    void splitsMixedCiphertextMetadataAndKey() {
        String value = "ZxxovJU5s4WCosVWT/6KrcIZuf7SuGz/pvcyceCFDoYdf4XBvEbZnHV4upmft2KxnYRVPdQXjJN1H5IK6yMN"
                + "aUujZT9VHi2UpG6tRBCLPwsQhN8KdefpqXJZgW0LSMT5vXFQln1yFmFDZxSOz9dJXNY8GAjMumXt1DPEynEk+ak="
                + ".UlNB.ZW5j.UC0yNTY="
                + ".LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BMEdDU3FHU0liM0RRRUJBUVVBQTRHTkFEQ0JpUUtCZ1FD"
                + "c1BnUkZiWWRHZDJ0T0JFMVVtZU1mSjFOQwpST0czTFRkUFlMbHRLbGQyQm1meWppNnpQSzNwR2JsaHBWZk0zbUhTVj"
                + "ZvSGNnV0xzenltSi9KVUNhLzBuSFNJCndHdHVQNFVaVVJCbkxwc1N5SWs3eTltSCt5SjB6NlMwZnNtYkx5TFhxT1dq"
                + "am02QTM5OGJRdHQzbjBwQm1kV3AKR3FhUFBvU21GQjBwODl0Mml3SURBUUFCCi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQ==";
        CipherAnalyzer.SplitResult sr = CipherAnalyzer.bestSplit(value);
        assertEquals(5, sr.parts.size(), "should split into ciphertext + metadata + key parts");
        assertTrue(sr.reason.contains("'.'"));
        assertEquals("UlNB", sr.parts.get(1));
        assertTrue(CipherAnalyzer.isCiphertextPart(sr.parts.get(0)), "part 1 is the ciphertext");
        assertFalse(CipherAnalyzer.isCiphertextPart(sr.parts.get(4)), "the PEM key part is not ciphertext");
    }

    @Test
    void splitsEqualSizeBlocksWithoutDelimiter() {
        // Two equal-length Base64 blobs (each ends with '=' padding) concatenated with no delimiter:
        // the interior '=' makes the whole non-Base64, so it can only be read as two equal blocks.
        byte[] b1 = new byte[16];
        byte[] b2 = new byte[16];
        for (int i = 0; i < 16; i++) {
            b1[i] = (byte) (i * 17 + 3);
            b2[i] = (byte) (i * 29 + 7);
        }
        String p1 = Base64.getEncoder().encodeToString(b1); // 24 chars, ends "=="
        String p2 = Base64.getEncoder().encodeToString(b2);
        CipherAnalyzer.SplitResult sr = CipherAnalyzer.bestSplit(p1 + p2);
        assertEquals(2, sr.parts.size());
        assertTrue(sr.reason.contains("equal-size"), "reason should mention equal-size blocks: " + sr.reason);
    }

    @Test
    void doesNotSplitJwt() {
        String jwt = b64url("{\"alg\":\"HS256\",\"typ\":\"JWT\"}") + "." + b64url("{\"sub\":\"1\"}") + ".AAAA";
        assertTrue(CipherAnalyzer.bestSplit(jwt).parts.isEmpty(), "a JWT is one token, not multiple ciphertexts");
    }

    @Test
    void doesNotSplitShortValue() {
        assertTrue(CipherAnalyzer.bestSplit("a.b").parts.isEmpty(), "short dotted values are not ciphertexts");
    }

    @Test
    void preprocessStripsWrappingJunk() {
        String jwe = b64url("{\"alg\":\"dir\",\"enc\":\"A256GCM\"}") + ".AA.BB.CC.DD";
        assertNotNull(firstEngine(CipherAnalyzer.analyze("[" + jwe + "]"), "aes"), "brackets should be stripped");
        assertNotNull(firstEngine(CipherAnalyzer.analyze("  \"" + jwe + "\"  "), "aes"),
                "quotes/whitespace should be stripped");
    }

    @Test
    void detectsDoubleBase64WrappedJwe() {
        String jwe = b64url("{\"alg\":\"dir\",\"enc\":\"A128GCM\"}") + ".AA.BB.CC.DD";
        String once = Base64.getEncoder().encodeToString(jwe.getBytes(StandardCharsets.UTF_8));
        String twice = Base64.getEncoder().encodeToString(once.getBytes(StandardCharsets.UTF_8));
        AnalysisResult r = CipherAnalyzer.analyze(twice);
        assertNotNull(firstEngine(r, "aes"), "a double-Base64-wrapped JWE should still surface via nested decode");
    }

    @Test
    void rsaHintForModulusSizedBlob() {
        byte[] raw = new byte[256]; // 2048-bit RSA block
        for (int i = 0; i < raw.length; i++) {
            raw[i] = (byte) (i * 13 + 1);
        }
        AnalysisResult r = CipherAnalyzer.analyze(Base64.getEncoder().encodeToString(raw));
        Suggestion rsa = firstEngine(r, "rsa");
        assertNotNull(rsa);
        assertEquals("PKCS1", rsa.getEngineParams().get("encryptionScheme"));
        assertNull(firstEngine(r, "aes"), "an exact RSA modulus size should not also emit AES block noise");
    }
}
