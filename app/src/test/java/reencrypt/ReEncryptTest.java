package reencrypt;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.*;
import java.io.File;
import java.lang.reflect.Proxy;
import java.nio.file.Path;

import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.persistence.Persistence;

public class ReEncryptTest {

    private ReEncrypt reEncrypt;
    private Config config;
    private File tempLogFile;

    @BeforeEach
    void setUp(@TempDir Path tempDir) {
        tempLogFile = tempDir.resolve("test_reencrypt.log").toFile();

        // Mock Persistence and PersistedObject
        PersistedObject fakePersisted = (PersistedObject) Proxy.newProxyInstance(ReEncryptTest.class.getClassLoader(),
                new Class[] { PersistedObject.class }, (proxy, method, args) -> {
                    if (method.getName().equals("getString") && args.length > 0) {
                        String key = (String) args[0];
                        if ("logFilePath".equals(key)) {
                            return tempLogFile.getAbsolutePath();
                        }
                        return null;
                    }
                    return null;
                });

        Persistence fakePersistence = (Persistence) Proxy.newProxyInstance(ReEncryptTest.class.getClassLoader(),
                new Class[] { Persistence.class }, (proxy, method, args) -> {
                    if (method.getName().equals("extensionData")) {
                        return fakePersisted;
                    }
                    return null;
                });

        config = new Config(fakePersistence);
        reEncrypt = new ReEncrypt(config);
    }

    @Test
    void generateUniqueNameSkipsNamesAlreadyTaken() {
        // Manual renames can park "Pattern 2" on the first row, so a count-based name would collide.
        config.addPattern(namedPattern("Pattern 2"), true);
        assertEquals("Pattern 3", config.generateUniqueName(true));

        // Both lists are checked: the settings table shows them merged.
        config.addPattern(namedPattern("Pattern 3"), false);
        assertEquals("Pattern 4", config.generateUniqueName(true));
    }

    private static CapturePattern namedPattern(String name) {
        return new CapturePattern(name, "(.*)", "", "d", "e",
                true, false, false, false, false, PatternType.CUSTOM_REGEX, "(.*)");
    }

    @Test
    void testSearchPattern() throws Exception {
        byte[] text = "key=\"value\"".getBytes();
        int[] indexes = ReEncrypt.searchPattern("key=\"(.*?)\"", text);

        assertEquals(5, indexes[0]);
        assertEquals(10, indexes[1]);

        String extracted = new String(text).substring(indexes[0], indexes[1]);
        assertEquals("value", extracted);
    }

    @Test
    void testMatchReplace() throws Exception {
        byte[] text = "key=\"value\"".getBytes();
        CapturePattern pattern = new CapturePattern("Test", "key=\"(.*?)\"", "", "", "", true, false, false, false);

        byte[] result = reEncrypt.matchReplace(text, pattern, "REPLACED");
        String resultStr = new String(result);

        assertEquals("key=\"REPLACED\"", resultStr);
    }

    @Test
    void testEncryptAndPatch_usingEcho() throws Exception {
        // Encyption simulation: echo "ENC_{DATA}"
        String encCommand = "echo ENC_{DATA}";
        CapturePattern pattern = new CapturePattern("Test", "data=(.*?)&", "", "", encCommand, true, true, false, true);

        byte[] request = "data=secret&other=1".getBytes();
        String plainText = "secret";

        LogData logData = new LogData("Test", true, "GET", "http://test");

        byte[] result = reEncrypt.encryptAndPatch(request, pattern, plainText, logData);
        String resultStr = new String(result);

        assertTrue(resultStr.contains("data=ENC_secret"), "Result was: " + resultStr);
    }

    @Test
    void testSearchAndDecrypt_usingEcho() throws Exception {
        // Decryption simulation: echo "DEC_{DATA}"
        String decCommand = "echo DEC_{DATA}";

        CapturePattern pattern = new CapturePattern("Test", "data=(.*?)&", "", decCommand, "", true, true, false, true);

        byte[] content = "data=ciphertext&other=1".getBytes();
        LogData logData = new LogData("Test", true, "GET", "http://test");

        OperationResult output = reEncrypt.searchAndDecrypt(pattern, content, logData);

        assertFalse(output.isFailed());
        String out = output.getOutput(); // ShellCommand handles newline stripping now
        assertEquals("DEC_ciphertext", out);
    }

    @Test
    void testIntruderEncryptionFlow() throws Exception {
        // Intruder scenario:
        // Request comes in as PLAINTEXT (payload injected).
        // pattern matches structure.
        // Find, extract, encrypt, replace.

        String encCommand = "echo ENC_{DATA}"; // will result in ENC_value
        CapturePattern pattern = new CapturePattern("IntruderTest", "val=(.*?)&", "", "", encCommand, true, true, false,
                true);

        byte[] request = "val=myPayload&other=1".getBytes();

        // 1. Find indexes
        int[] indexes = ReEncrypt.searchPattern(pattern.getCaptureRegex(), request);

        // 2. Extract
        String contentStr = new String(request);
        String extracted = contentStr.substring(indexes[0], indexes[1]);
        assertEquals("myPayload", extracted);

        // 3. Encrypt and Patch
        LogData logData = new LogData("Intruder", true, "POST", "http://test");
        byte[] result = reEncrypt.encryptAndPatch(request, pattern, extracted, logData);

        String resultStr = new String(result);
        assertTrue(resultStr.contains("val=ENC_myPayload&"), "Actual: " + resultStr);
    }
}
