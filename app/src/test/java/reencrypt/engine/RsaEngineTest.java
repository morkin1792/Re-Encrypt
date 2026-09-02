package reencrypt.engine;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.File;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.HashMap;

import org.junit.jupiter.api.Test;

public class RsaEngineTest {

    private static final boolean IS_WINDOWS = System.getProperty("os.name").toLowerCase().contains("win");

    @Test
    void rsaRoundTripWithDerKeyFromCommand() throws Exception {
        if (IS_WINDOWS) {
            return; // uses `cat` to emit raw DER bytes
        }
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        File pub = File.createTempFile("re-pub", ".der");
        File priv = File.createTempFile("re-priv", ".der");
        pub.deleteOnExit();
        priv.deleteOnExit();
        Files.write(pub.toPath(), kp.getPublic().getEncoded());   // X.509 DER
        Files.write(priv.toPath(), kp.getPrivate().getEncoded()); // PKCS#8 DER

        RsaEngine engine = new RsaEngine();
        HashMap<String, String> params = new HashMap<>();
        params.put("encryptionScheme", "PKCS1");
        params.put("encoding", "Base64");
        params.put("mirrorEncoding", "true");
        params.put("publicKeySource", "command");
        params.put("publicKey", "cat " + pub.getAbsolutePath());
        params.put("publicKeyFileFormat", "DER");
        params.put("privateKeySource", "command");
        params.put("privateKey", "cat " + priv.getAbsolutePath());
        params.put("privateKeyFileFormat", "DER");

        String plaintext = "rsa DER key material via command source";
        String ciphertext = engine.encrypt(plaintext, params);
        assertEquals(plaintext, engine.decrypt(ciphertext, params),
                "RSA must accept DER key material emitted by a command");
    }

    @Test
    void rsaRoundTripWithPemKeyFromCommand() throws Exception {
        if (IS_WINDOWS) {
            return;
        }
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        String pubPem = "-----BEGIN PUBLIC KEY-----\n"
                + java.util.Base64.getMimeEncoder().encodeToString(kp.getPublic().getEncoded())
                + "\n-----END PUBLIC KEY-----";
        String privPem = "-----BEGIN PRIVATE KEY-----\n"
                + java.util.Base64.getMimeEncoder().encodeToString(kp.getPrivate().getEncoded())
                + "\n-----END PRIVATE KEY-----";

        File pub = File.createTempFile("re-pub", ".pem");
        File priv = File.createTempFile("re-priv", ".pem");
        pub.deleteOnExit();
        priv.deleteOnExit();
        Files.write(pub.toPath(), pubPem.getBytes());
        Files.write(priv.toPath(), privPem.getBytes());

        RsaEngine engine = new RsaEngine();
        HashMap<String, String> params = new HashMap<>();
        params.put("encryptionScheme", "PKCS1");
        params.put("encoding", "Base64");
        params.put("mirrorEncoding", "true");
        params.put("publicKeySource", "command");
        params.put("publicKey", "cat " + pub.getAbsolutePath());
        params.put("publicKeyFileFormat", "PEM");
        params.put("privateKeySource", "command");
        params.put("privateKey", "cat " + priv.getAbsolutePath());
        params.put("privateKeyFileFormat", "PEM");

        String plaintext = "rsa PEM key material via command source";
        String ciphertext = engine.encrypt(plaintext, params);
        assertEquals(plaintext, engine.decrypt(ciphertext, params));
    }
}
