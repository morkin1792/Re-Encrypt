package reencrypt;

import java.io.IOException;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import reencrypt.exception.PatternException;

public class ReEncrypt {
    Config config;

    public ReEncrypt(Config config) {
        this.config = config;
    }

    public Config getConfig() {
        return config;
    }

    public byte[] encryptAndPatch(byte[] request, CapturePattern pattern, String plainText)
            throws IOException, InterruptedException, PatternException {
        int[] indexes = searchPattern(pattern.getPatternRegex(), request);
        int beginIndex = indexes[0];
        int endIndex = indexes[1];
        String cipherText = encrypt(pattern.getEncCommand(), plainText);
        return patchRequest(request, beginIndex, endIndex, cipherText.getBytes());
    }

    public String encrypt(String rawCommand, String plainText) throws IOException, InterruptedException {
        ShellCommand command = new ShellCommand(rawCommand, plainText);
        String cipherText = command.execute();
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

    public String searchAndDecrypt(CapturePattern pattern, byte[] content)
            throws IOException, InterruptedException, PatternException {
        int[] indexes = searchPattern(pattern.getPatternRegex(), content);
        int beginIndex = indexes[0];
        int endIndex = indexes[1];
        String cipherText = new String(content).substring(beginIndex, endIndex);
        return decrypt(pattern.getDecCommand(), cipherText);
    }

    String decrypt(String decCommand, String cipherText) throws IOException, InterruptedException {
        ShellCommand command = new ShellCommand(decCommand, cipherText);
        String plainText = command.execute();
        return plainText;

    }

}