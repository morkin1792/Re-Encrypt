package reencrypt.engine;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import reencrypt.ui.AesConfigPanel;
import reencrypt.ui.EngineConfigPanel;

/**
 * Built-in AES encryption/decryption engine.
 * Supports multiple modes (CBC, ECB, GCM, CTR, CFB, OFB) and
 * ciphertext structures (raw, IV+CT, IV+CT+Tag, OpenSSL enc, JWE).
 */
public class AesEngine implements CryptoEngine {

    @Override
    public String getId() {
        return "aes";
    }

    @Override
    public String getDisplayName() {
        return "AES";
    }

    @Override
    public String decrypt(String input, Map<String, String> params) throws CryptoException {
        String structure = params.getOrDefault("ciphertextStructure", "raw");

        switch (structure) {
        case "jwe":
            return decryptJwe(input, params);
        case "openssl":
            return decryptOpenSsl(input, params);
        default:
            return decryptStandard(input, params, structure);
        }
    }

    @Override
    public String encrypt(String input, Map<String, String> params) throws CryptoException {
        String structure = params.getOrDefault("ciphertextStructure", "raw");

        switch (structure) {
        case "jwe":
            return encryptJwe(input, params);
        case "openssl":
            return encryptOpenSsl(input, params);
        default:
            return encryptStandard(input, params, structure);
        }
    }

    // ========== Standard structures: raw, iv_ct, iv_ct_tag ==========

    private String decryptStandard(String input, Map<String, String> params, String structure) throws CryptoException {
        try {
            // Determine encoding
            String encoding = getInputEncoding(params);
            byte[] rawData = EncodingUtils.decode(input, encoding);

            String mode = params.getOrDefault("mode", "CBC");
            byte[] key = KeyLoader.loadAndDecode(params, "key", "keyFormat", input);
            byte[] iv;
            byte[] ciphertext;
            byte[] tag = null;

            switch (structure) {
            case "iv_ct": {
                int ivLen = getIvLength(params, mode);
                iv = Arrays.copyOfRange(rawData, 0, ivLen);
                ciphertext = Arrays.copyOfRange(rawData, ivLen, rawData.length);
                break;
            }
            case "iv_ct_tag": {
                int ivLen = getIvLength(params, mode);
                int tagLen = getTagLengthBytes(params);
                iv = Arrays.copyOfRange(rawData, 0, ivLen);
                ciphertext = Arrays.copyOfRange(rawData, ivLen, rawData.length - tagLen);
                tag = Arrays.copyOfRange(rawData, rawData.length - tagLen, rawData.length);
                break;
            }
            default: // "raw" - ciphertext only
                ciphertext = rawData;
                iv = KeyLoader.loadAndDecode(params, "iv", "ivFormat", input);
                break;
            }

            // For GCM with tag, append tag to ciphertext (Java GCM expects tag appended)
            if ("GCM".equals(mode) && tag != null) {
                byte[] ctWithTag = new byte[ciphertext.length + tag.length];
                System.arraycopy(ciphertext, 0, ctWithTag, 0, ciphertext.length);
                System.arraycopy(tag, 0, ctWithTag, ciphertext.length, tag.length);
                ciphertext = ctWithTag;
            }

            byte[] plaintext = doDecrypt(key, iv, ciphertext, mode, params);
            return new String(plaintext, StandardCharsets.UTF_8);
        } catch (CryptoException e) {
            throw e;
        } catch (Exception e) {
            throw new CryptoException("AES decryption failed (check the key, IV, mode and padding): "
                    + e.getMessage(), e);
        }
    }

    private String encryptStandard(String input, Map<String, String> params, String structure) throws CryptoException {
        try {
            String mode = params.getOrDefault("mode", "CBC");
            byte[] key = KeyLoader.loadAndDecode(params, "key", "keyFormat", input);
            byte[] iv;

            switch (structure) {
            case "iv_ct":
            case "iv_ct_tag":
                // Generate random IV for encrypt
                iv = generateRandomIv(mode);
                break;
            default: // "raw"
                iv = KeyLoader.loadAndDecode(params, "iv", "ivFormat", input);
                break;
            }

            byte[] plaintext = input.getBytes(StandardCharsets.UTF_8);
            byte[] encrypted = doEncrypt(key, iv, plaintext, mode, params);

            byte[] output;
            switch (structure) {
            case "iv_ct":
                output = new byte[iv.length + encrypted.length];
                System.arraycopy(iv, 0, output, 0, iv.length);
                System.arraycopy(encrypted, 0, output, iv.length, encrypted.length);
                break;
            case "iv_ct_tag": {
                // For GCM, Java appends the tag to ciphertext
                int tagLen = getTagLengthBytes(params);
                byte[] cipherOnly = Arrays.copyOfRange(encrypted, 0, encrypted.length - tagLen);
                byte[] tagBytes = Arrays.copyOfRange(encrypted, encrypted.length - tagLen, encrypted.length);
                output = new byte[iv.length + cipherOnly.length + tagLen];
                System.arraycopy(iv, 0, output, 0, iv.length);
                System.arraycopy(cipherOnly, 0, output, iv.length, cipherOnly.length);
                System.arraycopy(tagBytes, 0, output, iv.length + cipherOnly.length, tagLen);
                break;
            }
            default: // "raw"
                output = encrypted;
                break;
            }

            String encoding = getOutputEncoding(params);
            return EncodingUtils.encode(output, encoding);
        } catch (CryptoException e) {
            throw e;
        } catch (Exception e) {
            throw new CryptoException("AES encryption failed: " + e.getMessage(), e);
        }
    }

    // ========== JWE Compact Serialization ==========

    private String decryptJwe(String input, Map<String, String> params) throws CryptoException {
        try {
            // Use limit -1 so an empty trailing segment (e.g. no tag for CTR/CFB/OFB)
            // is preserved instead of being dropped by split's default trimming.
            String[] parts = input.split("\\.", -1);
            if (parts.length != 5) {
                throw new CryptoException(
                        "Invalid JWE compact serialization: expected 5 parts, got " + parts.length);
            }

            // Part 1 = header, Part 2 = encrypted key, Part 3 = IV,
            // Part 4 = Ciphertext, Part 5 = Tag.
            // Standard JWE uses Base64URL, but tolerate standard Base64 (+/=) too.
            byte[] iv = EncodingUtils.decodeBase64Url(parts[2]);
            byte[] ciphertext = EncodingUtils.decodeBase64Url(parts[3]);
            byte[] tag = EncodingUtils.decodeBase64Url(parts[4]);

            // Preserve the protected header, encrypted key, tag and the original segment
            // encoding so encryptJwe can reassemble the token in the same style. params is
            // the pattern's live engineParams map, so these survive from this decrypt into
            // the re-encrypt within the same session.
            params.put("jweHeader", parts[0]);
            params.put("jweEncryptedKey", parts[1]);
            params.put("jweTag", parts[4]);
            rememberSegmentEncoding(parts[2] + parts[3], params);

            String mode = params.getOrDefault("mode", "GCM");
            byte[] key = KeyLoader.loadAndDecode(params, "key", "keyFormat", input);

            // For GCM, append tag to ciphertext (Java expects it)
            if ("GCM".equals(mode)) {
                byte[] ctWithTag = new byte[ciphertext.length + tag.length];
                System.arraycopy(ciphertext, 0, ctWithTag, 0, ciphertext.length);
                System.arraycopy(tag, 0, ctWithTag, ciphertext.length, tag.length);
                ciphertext = ctWithTag;
            }

            // AAD for JWE is the ASCII bytes of the Base64URL header
            byte[] aad = parts[0].getBytes("ASCII");
            byte[] plaintext = doDecryptWithAad(key, iv, ciphertext, mode, params, aad);
            return new String(plaintext, StandardCharsets.UTF_8);
        } catch (CryptoException e) {
            throw e;
        } catch (Exception e) {
            throw new CryptoException("JWE decryption failed (check the key and mode): " + e.getMessage(), e);
        }
    }

    private String encryptJwe(String input, Map<String, String> params) throws CryptoException {
        try {
            // Need original header and encrypted key for re-assembly
            String jweHeader = params.getOrDefault("jweHeader", "");
            String jweEncryptedKey = params.getOrDefault("jweEncryptedKey", "");

            if (jweHeader.isEmpty()) {
                throw new CryptoException("No JWE header available. Decrypt a JWE token first to capture the header.");
            }

            String mode = params.getOrDefault("mode", "GCM");
            byte[] key = KeyLoader.loadAndDecode(params, "key", "keyFormat", input);
            byte[] iv = generateRandomIv(mode);
            byte[] plaintext = input.getBytes(StandardCharsets.UTF_8);

            // AAD for JWE is the ASCII bytes of the Base64URL header
            byte[] aad = jweHeader.getBytes("ASCII");
            byte[] encrypted = doEncryptWithAad(key, iv, plaintext, mode, params, aad);

            // Reassemble JWE compact serialization, matching the original segment encoding
            String newIv = encodeSegment(iv, params);
            String newCiphertext;
            String newTag;

            if ("GCM".equals(mode)) {
                // GCM is the only mode where Java appends the authentication tag to the
                // ciphertext; split it back out into the dedicated JWE tag segment.
                int tagLen = getTagLengthBytes(params);
                byte[] cipherOnly = Arrays.copyOfRange(encrypted, 0, encrypted.length - tagLen);
                byte[] tagBytes = Arrays.copyOfRange(encrypted, encrypted.length - tagLen, encrypted.length);
                newCiphertext = encodeSegment(cipherOnly, params);
                newTag = encodeSegment(tagBytes, params);
            } else {
                // Non-GCM modes (CTR/CFB/OFB/CBC) produce no appended tag, so the whole
                // output is ciphertext. This engine does not compute the JWE AES-CBC-HMAC
                // integrity tag, so reuse the tag captured at decrypt time (empty if none).
                newCiphertext = encodeSegment(encrypted, params);
                newTag = params.getOrDefault("jweTag", "");
            }

            return jweHeader + "." + jweEncryptedKey + "." + newIv + "." + newCiphertext + "." + newTag;
        } catch (CryptoException e) {
            throw e;
        } catch (Exception e) {
            throw new CryptoException("JWE encryption failed: " + e.getMessage(), e);
        }
    }

    /**
     * Record whether the captured JWE segments used the standard Base64 alphabet
     * (with '+'/'/' and/or '=' padding) or Base64URL, so re-encryption can match it.
     */
    private void rememberSegmentEncoding(String sample, Map<String, String> params) {
        boolean stdAlphabet = sample.indexOf('+') >= 0 || sample.indexOf('/') >= 0;
        boolean urlAlphabet = sample.indexOf('-') >= 0 || sample.indexOf('_') >= 0;
        boolean padded = sample.indexOf('=') >= 0;
        String encoding;
        if (stdAlphabet) {
            encoding = "standard";
        } else if (urlAlphabet) {
            encoding = "url";
        } else {
            encoding = padded ? "standard" : "url"; // ambiguous: padding hints standard
        }
        params.put("jweEncoding", encoding);
        params.put("jwePadded", padded ? "true" : "false");
    }

    /**
     * Base64-encode a JWE segment using the encoding remembered from decrypt
     * (defaults to Base64URL without padding, the JWE standard, when unknown).
     */
    private String encodeSegment(byte[] data, Map<String, String> params) {
        Base64.Encoder encoder = "standard".equals(params.get("jweEncoding"))
                ? Base64.getEncoder()
                : Base64.getUrlEncoder();
        if (!"true".equals(params.get("jwePadded"))) {
            encoder = encoder.withoutPadding();
        }
        return encoder.encodeToString(data);
    }

    // ========== OpenSSL enc format ==========

    private String decryptOpenSsl(String input, Map<String, String> params) throws CryptoException {
        try {
            String encoding = getInputEncoding(params);
            byte[] rawData = EncodingUtils.decode(input, encoding);

            // Validate "Salted__" header
            String header = new String(Arrays.copyOfRange(rawData, 0, 8));
            if (!"Salted__".equals(header)) {
                throw new CryptoException("Invalid OpenSSL format: missing 'Salted__' header");
            }

            byte[] salt = Arrays.copyOfRange(rawData, 8, 16);
            byte[] ciphertext = Arrays.copyOfRange(rawData, 16, rawData.length);

            byte[] keyMaterial = KeyLoader.loadAndDecode(params, "key", "keyFormat", input);
            String mode = params.getOrDefault("mode", "CBC");
            String derivation = params.getOrDefault("keyDerivation", "evp_md5");

            int keyLen = getKeyLengthForMode(params);
            int ivLen = getBlockSize(mode);

            byte[][] derived = deriveKeyAndIv(keyMaterial, salt, keyLen, ivLen, derivation, params);
            byte[] key = derived[0];
            byte[] iv = derived[1];

            byte[] plaintext = doDecrypt(key, iv, ciphertext, mode, params);
            return new String(plaintext, StandardCharsets.UTF_8);
        } catch (CryptoException e) {
            throw e;
        } catch (Exception e) {
            throw new CryptoException("OpenSSL decryption failed (check the key/password and key derivation): "
                    + e.getMessage(), e);
        }
    }

    private String encryptOpenSsl(String input, Map<String, String> params) throws CryptoException {
        try {
            byte[] keyMaterial = KeyLoader.loadAndDecode(params, "key", "keyFormat", input);
            String mode = params.getOrDefault("mode", "CBC");
            String derivation = params.getOrDefault("keyDerivation", "evp_md5");

            // Generate random salt
            byte[] salt = new byte[8];
            new java.security.SecureRandom().nextBytes(salt);

            int keyLen = getKeyLengthForMode(params);
            int ivLen = getBlockSize(mode);

            byte[][] derived = deriveKeyAndIv(keyMaterial, salt, keyLen, ivLen, derivation, params);
            byte[] key = derived[0];
            byte[] iv = derived[1];

            byte[] plaintext = input.getBytes(StandardCharsets.UTF_8);
            byte[] encrypted = doEncrypt(key, iv, plaintext, mode, params);

            // Assemble: "Salted__" + salt + ciphertext
            byte[] output = new byte[8 + 8 + encrypted.length];
            System.arraycopy("Salted__".getBytes(), 0, output, 0, 8);
            System.arraycopy(salt, 0, output, 8, 8);
            System.arraycopy(encrypted, 0, output, 16, encrypted.length);

            String encoding = getOutputEncoding(params);
            return EncodingUtils.encode(output, encoding);
        } catch (CryptoException e) {
            throw e;
        } catch (Exception e) {
            throw new CryptoException("OpenSSL encryption failed: " + e.getMessage(), e);
        }
    }

    // ========== Core AES operations ==========

    private byte[] doDecrypt(byte[] key, byte[] iv, byte[] ciphertext, String mode, Map<String, String> params)
            throws Exception {
        return doDecryptWithAad(key, iv, ciphertext, mode, params, null);
    }

    private byte[] doDecryptWithAad(byte[] key, byte[] iv, byte[] ciphertext, String mode,
            Map<String, String> params, byte[] aad) throws Exception {
        String padding = getPadding(mode, params);
        String transformation = "AES/" + mode + "/" + padding;
        Cipher cipher = Cipher.getInstance(transformation);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");

        if ("ECB".equals(mode)) {
            cipher.init(Cipher.DECRYPT_MODE, keySpec);
        } else if ("GCM".equals(mode)) {
            int tagLenBits = Integer.parseInt(params.getOrDefault("gcmTagLength", "128"));
            GCMParameterSpec gcmSpec = new GCMParameterSpec(tagLenBits, iv);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
            if (aad != null) {
                cipher.updateAAD(aad);
            }
        } else {
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        }

        return cipher.doFinal(ciphertext);
    }

    private byte[] doEncrypt(byte[] key, byte[] iv, byte[] plaintext, String mode, Map<String, String> params)
            throws Exception {
        return doEncryptWithAad(key, iv, plaintext, mode, params, null);
    }

    private byte[] doEncryptWithAad(byte[] key, byte[] iv, byte[] plaintext, String mode,
            Map<String, String> params, byte[] aad) throws Exception {
        String padding = getPadding(mode, params);
        String transformation = "AES/" + mode + "/" + padding;
        Cipher cipher = Cipher.getInstance(transformation);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");

        if ("ECB".equals(mode)) {
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        } else if ("GCM".equals(mode)) {
            int tagLenBits = Integer.parseInt(params.getOrDefault("gcmTagLength", "128"));
            GCMParameterSpec gcmSpec = new GCMParameterSpec(tagLenBits, iv);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
            if (aad != null) {
                cipher.updateAAD(aad);
            }
        } else {
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        }

        return cipher.doFinal(plaintext);
    }

    // ========== Key derivation (OpenSSL) ==========

    private byte[][] deriveKeyAndIv(byte[] keyMaterial, byte[] salt, int keyLen, int ivLen, String derivation,
            Map<String, String> params) throws Exception {
        if ("pbkdf2_sha256".equals(derivation)) {
            int iterations = Integer.parseInt(params.getOrDefault("pbkdf2Iterations", "10000"));
            return deriveKeyAndIvPbkdf2(keyMaterial, salt, keyLen, ivLen, iterations);
        }
        // Default: EVP_BytesToKey with MD5
        return deriveKeyAndIvEvp(keyMaterial, salt, keyLen, ivLen);
    }

    /**
     * OpenSSL's EVP_BytesToKey with MD5 - the legacy key derivation.
     */
    private byte[][] deriveKeyAndIvEvp(byte[] passBytes, byte[] salt, int keyLen, int ivLen) throws Exception {
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
        byte[] derived = new byte[keyLen + ivLen];
        byte[] block = new byte[0];
        int offset = 0;

        while (offset < derived.length) {
            md.reset();
            if (block.length > 0) {
                md.update(block);
            }
            md.update(passBytes);
            md.update(salt);
            block = md.digest();
            int copyLen = Math.min(block.length, derived.length - offset);
            System.arraycopy(block, 0, derived, offset, copyLen);
            offset += copyLen;
        }

        byte[] key = Arrays.copyOfRange(derived, 0, keyLen);
        byte[] iv = Arrays.copyOfRange(derived, keyLen, keyLen + ivLen);
        return new byte[][] { key, iv };
    }

    /**
     * PBKDF2 with SHA-256 key derivation.
     */
    private byte[][] deriveKeyAndIvPbkdf2(byte[] passBytes, byte[] salt, int keyLen, int ivLen, int iterations)
            throws Exception {
        // Reconstruct chars as UTF-8 so a plain (UTF-8) key behaves exactly as before;
        // Hex/Base64 key material is mapped through its UTF-8 view.
        char[] passChars = new String(passBytes, StandardCharsets.UTF_8).toCharArray();
        javax.crypto.spec.PBEKeySpec spec = new javax.crypto.spec.PBEKeySpec(passChars, salt,
                iterations, (keyLen + ivLen) * 8);
        javax.crypto.SecretKeyFactory factory = javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] derived = factory.generateSecret(spec).getEncoded();
        byte[] key = Arrays.copyOfRange(derived, 0, keyLen);
        byte[] iv = Arrays.copyOfRange(derived, keyLen, keyLen + ivLen);
        return new byte[][] { key, iv };
    }

    // ========== Helpers ==========

    private String getPadding(String mode, Map<String, String> params) {
        switch (mode) {
        case "ECB":
        case "CBC":
            return params.getOrDefault("padding", "PKCS5Padding");
        default:
            return "NoPadding";
        }
    }

    private int getBlockSize(String mode) {
        return "GCM".equals(mode) ? 12 : 16; // GCM typically uses 12-byte IV
    }

    private int getIvLength(Map<String, String> params, String mode) {
        String ivLenStr = params.getOrDefault("ivLength", "auto");
        if (!"auto".equals(ivLenStr)) {
            return Integer.parseInt(ivLenStr);
        }
        return getBlockSize(mode);
    }

    private int getTagLengthBytes(Map<String, String> params) {
        int tagBits = Integer.parseInt(params.getOrDefault("gcmTagLength", "128"));
        return tagBits / 8;
    }

    private int getKeyLengthForMode(Map<String, String> params) {
        // For OpenSSL, default to 32 bytes (AES-256)
        String keyLenStr = params.getOrDefault("opensslKeyLength", "32");
        return Integer.parseInt(keyLenStr);
    }

    private byte[] generateRandomIv(String mode) {
        int ivLen = getBlockSize(mode);
        byte[] iv = new byte[ivLen];
        new java.security.SecureRandom().nextBytes(iv);
        return iv;
    }

    private String getInputEncoding(Map<String, String> params) {
        if ("true".equals(params.getOrDefault("mirrorEncoding", "true"))) {
            return params.getOrDefault("encoding", "Base64");
        }
        return params.getOrDefault("inputEncoding", "Base64");
    }

    private String getOutputEncoding(Map<String, String> params) {
        if ("true".equals(params.getOrDefault("mirrorEncoding", "true"))) {
            return params.getOrDefault("encoding", "Base64");
        }
        return params.getOrDefault("outputEncoding", "Base64");
    }

    // ========== Validation ==========

    @Override
    public String validate(Map<String, String> params) {
        if (params == null) {
            return "No parameters configured.";
        }

        String structure = params.getOrDefault("ciphertextStructure", "raw");
        String mode = params.getOrDefault("mode", "CBC");

        // Validate key
        if ("openssl".equals(structure)) {
            String key = params.getOrDefault("key", "");
            if (key.isEmpty()) {
                return "Key is required for OpenSSL.";
            }
        } else {
            String keyValue = params.getOrDefault("key", "");
            String keyFormat = params.getOrDefault("keyFormat", "UTF-8");
            String keySource = params.getOrDefault("keySource", "text");

            if (keyValue.isEmpty()) {
                return "Key is required.";
            }

            if ("text".equals(keySource)) {
                String formatError = EncodingUtils.validateKeyValue(keyValue, keyFormat, "key");
                if (formatError != null) {
                    return formatError;
                }
                try {
                    byte[] keyBytes = EncodingUtils.decodeKeyValue(keyValue, keyFormat);
                    String lenError = EncodingUtils.validateAesKeyLength(keyBytes);
                    if (lenError != null) {
                        return lenError;
                    }
                } catch (CryptoException e) {
                    return e.getMessage();
                }
            } else if ("file".equals(keySource)) {
                if (!new java.io.File(keyValue).exists()) {
                    return "Key file not found: " + keyValue;
                }
            }
        }

        // Validate IV (only for "raw" structure with non-ECB modes)
        if ("raw".equals(structure) && !"ECB".equals(mode)) {
            String ivValue = params.getOrDefault("iv", "");
            if (ivValue.isEmpty()) {
                return "IV is required for " + mode + " mode.";
            }
            String ivFormat = params.getOrDefault("ivFormat", "UTF-8");
            String ivSource = params.getOrDefault("ivSource", "text");
            if ("text".equals(ivSource)) {
                String formatError = EncodingUtils.validateKeyValue(ivValue, ivFormat, "IV");
                if (formatError != null) {
                    return formatError;
                }
            } else if ("file".equals(ivSource)) {
                if (!new java.io.File(ivValue).exists()) {
                    return "IV file not found: " + ivValue;
                }
            }
        }

        return null; // Valid
    }

    @Override
    public String info(Map<String, String> params) {
        if (params == null) {
            return null;
        }
        String structure = params.getOrDefault("ciphertextStructure", "raw");
        String mode = params.getOrDefault("mode", "CBC");
        // Advisory only — non-standard JWE modes still work in this tool.
        if ("jwe".equals(structure) && !"GCM".equals(mode) && !"CBC".equals(mode)) {
            return "JWE typically uses GCM or CBC mode.";
        }
        return null;
    }

    @Override
    public EngineConfigPanel createConfigPanel(Map<String, String> existingParams) {
        return new AesConfigPanel(existingParams);
    }
}
