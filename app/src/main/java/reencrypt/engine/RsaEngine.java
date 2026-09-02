package reencrypt.engine;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import reencrypt.ui.EngineConfigPanel;
import reencrypt.ui.RsaConfigPanel;

/**
 * Built-in RSA encryption/decryption engine.
 * Supports PKCS1, OAEP (with configurable digest), and Raw padding schemes.
 */
public class RsaEngine implements CryptoEngine {

    @Override
    public String getId() {
        return "rsa";
    }

    @Override
    public String getDisplayName() {
        return "RSA";
    }

    @Override
    public String decrypt(String input, Map<String, String> params) throws CryptoException {
        try {
            String encoding = getInputEncoding(params);
            byte[] ciphertext = EncodingUtils.decode(input, encoding);

            PrivateKey privateKey = loadPrivateKey(params, input);
            if (privateKey == null) {
                throw new CryptoException("Private key is required for decryption.");
            }

            Cipher cipher = getCipher(params);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] plaintext = cipher.doFinal(ciphertext);

            return new String(plaintext, StandardCharsets.UTF_8);
        } catch (CryptoException e) {
            throw e;
        } catch (Exception e) {
            throw new CryptoException("RSA decryption failed (check the private key and scheme): "
                    + e.getMessage(), e);
        }
    }

    @Override
    public String encrypt(String input, Map<String, String> params) throws CryptoException {
        try {
            PublicKey publicKey = loadPublicKey(params, input);
            if (publicKey == null) {
                throw new CryptoException("Public key is required for encryption.");
            }

            Cipher cipher = getCipher(params);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] ciphertext = cipher.doFinal(input.getBytes(StandardCharsets.UTF_8));

            String encoding = getOutputEncoding(params);
            return EncodingUtils.encode(ciphertext, encoding);
        } catch (CryptoException e) {
            throw e;
        } catch (Exception e) {
            throw new CryptoException("RSA encryption failed: " + e.getMessage(), e);
        }
    }

    // ========== Cipher setup ==========

    private Cipher getCipher(Map<String, String> params) throws Exception {
        String scheme = params.getOrDefault("encryptionScheme", "PKCS1");
        switch (scheme) {
        case "OAEP": {
            String digest = params.getOrDefault("oaepDigest", "SHA-256");
            String jcaDigest = mapDigestName(digest);
            MGF1ParameterSpec mgf1Spec = new MGF1ParameterSpec(jcaDigest);
            OAEPParameterSpec oaepSpec = new OAEPParameterSpec(jcaDigest, "MGF1", mgf1Spec,
                    PSource.PSpecified.DEFAULT);
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
            // Note: init with oaepSpec needs to be done by caller with the key
            // We return a configured cipher instance
            return Cipher.getInstance("RSA/ECB/OAEPWith" + jcaDigest + "AndMGF1Padding");
        }
        case "Raw":
            return Cipher.getInstance("RSA/ECB/NoPadding");
        case "PKCS1":
        default:
            return Cipher.getInstance("RSA/ECB/PKCS1Padding");
        }
    }

    private String mapDigestName(String digest) {
        switch (digest) {
        case "SHA-1":
            return "SHA-1";
        case "SHA-256":
            return "SHA-256";
        case "SHA-384":
            return "SHA-384";
        case "SHA-512":
            return "SHA-512";
        default:
            return "SHA-256";
        }
    }

    // ========== Key loading ==========

    private PublicKey loadPublicKey(Map<String, String> params, String data) throws CryptoException {
        // DER (binary) from file or command is handled separately; everything else
        // (text, PEM file, PEM command) resolves to a PEM string via KeyLoader.
        if (wantsDer(params, "publicKey")) {
            byte[] derBytes = loadDerBytes(params, "publicKey", data);
            if (derBytes == null || derBytes.length == 0) {
                return null;
            }
            try {
                return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(derBytes));
            } catch (Exception e) {
                throw new CryptoException("Invalid DER format for public key: " + e.getMessage(), e);
            }
        }

        String keyData = KeyLoader.loadValue(params, "publicKey", data);
        if (keyData == null || keyData.trim().isEmpty()) {
            return null;
        }
        return parsePemPublicKey(keyData);
    }

    private PrivateKey loadPrivateKey(Map<String, String> params, String data) throws CryptoException {
        if (wantsDer(params, "privateKey")) {
            byte[] derBytes = loadDerBytes(params, "privateKey", data);
            if (derBytes == null || derBytes.length == 0) {
                return null;
            }
            try {
                return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(derBytes));
            } catch (Exception e) {
                throw new CryptoException("Invalid DER format for private key: " + e.getMessage(), e);
            }
        }

        String keyData = KeyLoader.loadValue(params, "privateKey", data);
        if (keyData == null || keyData.trim().isEmpty()) {
            return null;
        }
        return parsePemPrivateKey(keyData);
    }

    /** True when the key is provided as binary DER (from a file or a command). */
    private boolean wantsDer(Map<String, String> params, String prefix) {
        String source = params.getOrDefault(prefix + "Source", "text");
        boolean isFileOrCommand = "file".equals(source) || "command".equals(source);
        return isFileOrCommand && "DER".equals(params.getOrDefault(prefix + "FileFormat", "PEM"));
    }

    /** Load raw DER bytes from either a file or a command source. */
    private byte[] loadDerBytes(Map<String, String> params, String prefix, String data) throws CryptoException {
        if ("command".equals(params.getOrDefault(prefix + "Source", "text"))) {
            return KeyLoader.loadCommandBytes(params, prefix, data);
        }
        String filePath = params.getOrDefault(prefix, "");
        if (filePath.isEmpty()) {
            return null;
        }
        return KeyLoader.loadBytesFromFile(filePath, params, prefix);
    }

    private PublicKey parsePemPublicKey(String pem) throws CryptoException {
        try {
            String base64 = pem.replaceAll("-----BEGIN.*?-----", "").replaceAll("-----END.*?-----", "")
                    .replaceAll("\\s", "");
            byte[] decoded = Base64.getDecoder().decode(base64);
            return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decoded));
        } catch (Exception e) {
            throw new CryptoException("Invalid PEM format for public key: " + e.getMessage(), e);
        }
    }

    private PrivateKey parsePemPrivateKey(String pem) throws CryptoException {
        try {
            String base64 = pem.replaceAll("-----BEGIN.*?-----", "").replaceAll("-----END.*?-----", "")
                    .replaceAll("\\s", "");
            byte[] decoded = Base64.getDecoder().decode(base64);
            return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(decoded));
        } catch (Exception e) {
            throw new CryptoException("Invalid PEM format for private key: " + e.getMessage(), e);
        }
    }

    // ========== Encoding helpers ==========

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

        String publicKey = params.getOrDefault("publicKey", "");
        String privateKey = params.getOrDefault("privateKey", "");

        if (publicKey.trim().isEmpty() && privateKey.trim().isEmpty()) {
            return "At least one key (public or private) is required.";
        }

        // Validate public key format if present
        if (!publicKey.trim().isEmpty()) {
            String pubSource = params.getOrDefault("publicKeySource", "text");
            if ("text".equals(pubSource)) {
                try {
                    parsePemPublicKey(publicKey);
                } catch (CryptoException e) {
                    return "Invalid PEM format for public key.";
                }
            } else if ("file".equals(pubSource)) {
                String fileFormat = params.getOrDefault("publicKeyFileFormat", "PEM");
                if (!new java.io.File(publicKey).exists()) {
                    return "File not found: " + publicKey;
                }
            }
        }

        // Validate private key format if present
        if (!privateKey.trim().isEmpty()) {
            String privSource = params.getOrDefault("privateKeySource", "text");
            if ("text".equals(privSource)) {
                try {
                    parsePemPrivateKey(privateKey);
                } catch (CryptoException e) {
                    return "Invalid PEM format for private key.";
                }
            } else if ("file".equals(privSource)) {
                if (!new java.io.File(privateKey).exists()) {
                    return "File not found: " + privateKey;
                }
            }
        }

        return null; // Valid
    }

    @Override
    public EngineConfigPanel createConfigPanel(Map<String, String> existingParams) {
        return new RsaConfigPanel(existingParams);
    }
}
