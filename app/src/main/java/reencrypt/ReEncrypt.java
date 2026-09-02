package reencrypt;

import java.io.IOException;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import reencrypt.engine.CryptoEngine;
import reencrypt.engine.CryptoEngineRegistry;
import reencrypt.engine.CryptoException;
import reencrypt.exception.CommandException;
import reencrypt.exception.PatternException;

public class ReEncrypt {
    Config config;

    public ReEncrypt(Config config) {
        this.config = config;
    }

    public Config getConfig() {
        return config;
    }

    public byte[] encryptAndPatch(byte[] request, CapturePattern pattern, String plainText, LogData logData)
            throws Exception {
        int[] indexes = searchPattern(pattern.getCaptureRegex(), request);
        int beginIndex = indexes[0];
        int endIndex = indexes[1];
        String cipherText = encrypt(pattern, plainText);
        if (pattern.shouldSaveToLog()) {
            logData.update(cipherText, plainText, pattern.getName(), "Encrypt");
            config.writeLog(logData);
        }
        return patchRequest(request, beginIndex, endIndex, cipherText.getBytes());
    }

    public byte[] matchReplace(byte[] request, CapturePattern pattern, String newValue) throws PatternException {
        return matchReplace(request, pattern, newValue, null);
    }

    /**
     * Replace the captured span with {@code newValue}. When {@code outSpan} is a length-3 array
     * it is filled with {newStart, newEnd, oldEnd}: the byte range the new value occupies in the
     * returned content, plus the end of the region that was replaced (so callers can adjust other
     * tracked spans by the length delta). This lets the print editor highlight exactly the
     * decrypted regions instead of re-matching the regex (which can hit false positives).
     */
    public byte[] matchReplace(byte[] request, CapturePattern pattern, String newValue, int[] outSpan)
            throws PatternException {
        int[] indexes = searchPattern(pattern.getCaptureRegex(), request);
        int beginIndex = indexes[0];
        int endIndex = indexes[1];
        byte[] newBytes = newValue.getBytes();
        if (outSpan != null && outSpan.length >= 3) {
            outSpan[0] = beginIndex;
            outSpan[1] = beginIndex + newBytes.length;
            outSpan[2] = endIndex;
        }
        return patchRequest(request, beginIndex, endIndex, newBytes);
    }

    public String encrypt(CapturePattern pattern, String plainText) throws Exception {
        if (pattern.usesEngine()) {
            CryptoEngine engine = CryptoEngineRegistry.get(pattern.getEngineId());
            return engine.encrypt(plainText, pattern.getEngineParams());
        }
        ShellCommand command = new ShellCommand(pattern.getEncCommand(), plainText);
        return command.execute().getOutputCheckingExitCode();
    }

    public String encrypt(String rawCommand, String plainText)
            throws IOException, InterruptedException, CommandException {
        ShellCommand command = new ShellCommand(rawCommand, plainText);
        String cipherText = command.execute().getOutputCheckingExitCode();
        return cipherText;
    }

    byte[] patchRequest(byte[] rawContent, int beginIndex, int endIndex, byte[] contentPayload) {
        byte[] preContent = Arrays.copyOfRange(rawContent, 0, beginIndex);
        byte[] postContent = Arrays.copyOfRange(rawContent, endIndex, rawContent.length);

        byte[] newRequest = new byte[preContent.length + contentPayload.length + postContent.length];
        System.arraycopy(preContent, 0, newRequest, 0, preContent.length);
        System.arraycopy(contentPayload, 0, newRequest, preContent.length, contentPayload.length);
        System.arraycopy(postContent, 0, newRequest, preContent.length + contentPayload.length, postContent.length);
        return newRequest;
    }

    public static int[] searchPattern(String regex, byte[] text) throws PatternException {
        Matcher matcher = Pattern.compile(regex).matcher(new String(text));
        if (matcher.find()) {
            return new int[] { matcher.start(1), matcher.end(1) };
        }
        throw new PatternException(regex);
    }

    public OperationResult searchAndDecrypt(CapturePattern pattern, byte[] content, LogData logData)
            throws IOException, InterruptedException, PatternException {
        int[] indexes = searchPattern(pattern.getCaptureRegex(), content);
        int beginIndex = indexes[0];
        int endIndex = indexes[1];
        String cipherText = new String(content).substring(beginIndex, endIndex);
        OperationResult commandOutput = decryptWithCache(pattern, cipherText);
        if (pattern.shouldSaveToLog() && !commandOutput.isFailed()) {
            logData.update(cipherText, commandOutput.getOutput(), pattern.getName(), "Decrypt");
            config.writeLog(logData);
        }
        return commandOutput;
    }

    /**
     * Decrypt with cache fallback. On success: caches the result if pattern has
     * caching enabled. On failure: returns cached result if available.
     */
    private OperationResult decryptWithCache(CapturePattern pattern, String cipherText)
            throws IOException, InterruptedException {
        DecryptionCache decryptionCache = config.getDecryptionCache();
        OperationResult commandOutput = decrypt(pattern, cipherText);
        if (pattern.shouldUseCacheSystem()) {
            // Treat garbage (likely wrong-key) output like a soft failure: never cache it,
            // and fall back to a previously cached good value if one exists.
            boolean garbage = !commandOutput.isFailed() && pattern.shouldDetectGarbage()
                    && GarbageDetector.looksLikeGarbage(commandOutput.getOutput());
            if (!commandOutput.isFailed() && !garbage) {
                decryptionCache.put(cipherText, commandOutput.getOutput());
            } else {
                String cachedOutput = decryptionCache.get(cipherText);
                if (cachedOutput != null) {
                    OperationResult fallback = new OperationResult(cachedOutput, commandOutput.getOutput());
                    if (garbage) {
                        fallback.markGarbage(); // so the UI can say it fell back due to garbage, not a failure
                    }
                    return fallback;
                }
                if (garbage) {
                    commandOutput.markGarbage();
                }
            }
        }
        return commandOutput;
    }

    private OperationResult decrypt(CapturePattern pattern, String cipherText)
            throws IOException, InterruptedException {
        if (pattern.usesEngine()) {
            try {
                CryptoEngine engine = CryptoEngineRegistry.get(pattern.getEngineId());
                String result = engine.decrypt(cipherText, pattern.getEngineParams());
                return new OperationResult(result, 0);
            } catch (CryptoException e) {
                return new OperationResult(e.getMessage(), 1);
            }
        }
        ShellCommand command = new ShellCommand(pattern.getDecCommand(), cipherText);
        return command.execute();
    }
}