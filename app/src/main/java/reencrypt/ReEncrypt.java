package reencrypt;

import java.io.IOException;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
            throws IOException, InterruptedException, PatternException, CommandException {
        int[] indexes = searchPattern(pattern.getCaptureRegex(), request);
        int beginIndex = indexes[0];
        int endIndex = indexes[1];
        String cipherText = encrypt(pattern.getEncCommand(), plainText);
        if (pattern.shouldSaveToLog()) {
            logData.update(cipherText, plainText, pattern.getName(), "Encrypt");
            config.writeLog(logData);
        }
        return patchRequest(request, beginIndex, endIndex, cipherText.getBytes());
    }

    public byte[] matchReplace(byte[] request, CapturePattern pattern, String newValue) throws PatternException {
        int[] indexes = searchPattern(pattern.getCaptureRegex(), request);
        int beginIndex = indexes[0];
        int endIndex = indexes[1];
        return patchRequest(request, beginIndex, endIndex, newValue.getBytes());
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

    public CommandOutput searchAndDecrypt(CapturePattern pattern, byte[] content, LogData logData)
            throws IOException, InterruptedException, PatternException {
        int[] indexes = searchPattern(pattern.getCaptureRegex(), content);
        int beginIndex = indexes[0];
        int endIndex = indexes[1];
        String cipherText = new String(content).substring(beginIndex, endIndex);
        CommandOutput commandOutput = decryptWithCache(pattern, cipherText);
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
    private CommandOutput decryptWithCache(CapturePattern pattern, String cipherText)
            throws IOException, InterruptedException {
        DecryptionCache decryptionCache = config.getDecryptionCache();
        CommandOutput commandOutput = decrypt(pattern.getDecCommand(), cipherText);
        if (pattern.shouldUseCacheSystem()) {
            if (!commandOutput.isFailed()) {
                decryptionCache.put(cipherText, commandOutput.getOutput());
            } else {
                String cachedOutput = decryptionCache.get(cipherText);
                if (cachedOutput != null) {
                    return new CommandOutput(cachedOutput, commandOutput.getOutput());
                }
            }
        }
        return commandOutput;

    }

    private CommandOutput decrypt(String decCommand, String cipherText) throws IOException, InterruptedException {
        ShellCommand command = new ShellCommand(decCommand, cipherText);
        return command.execute();
    }

}