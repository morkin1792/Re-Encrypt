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

    public byte[] encryptAndPatch(byte[] request, boolean isRequest, String plainText) throws CommandException, IOException, PatternException {
        int[] indexes = searchPattern(isRequest, request);
        int beginIndex = indexes[0];
        int endIndex = indexes[1];
        String cipherText = encrypt(plainText);
        return patchRequest(request, beginIndex, endIndex, cipherText.getBytes());
    }

    public String encrypt(String plainText) throws CommandException, IOException {
        ShellCommand command = getEncodeCommand(plainText);
        String cipherText = command.execute(true);
        return cipherText;
    }

    ShellCommand getEncodeCommand(String plainText) throws IOException {
        String rawCommand = config.getEncodeCommand();
        return new ShellCommand(rawCommand, plainText);
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

    public int[] searchPattern(boolean isRequest, byte[] text) throws PatternException {
        return searchPattern(config.getPattern(isRequest), text);
    }

    public static int[] searchPattern(String regex, byte[] text) throws PatternException {
        Matcher matcher = Pattern.compile(regex).matcher(new String(text));
        if (matcher.find()) {
            return new int[] { matcher.start(1), matcher.end(1) };
        }
        throw new PatternException(regex);
    }

    ShellCommand getDecodeCommand(String cipherText, IMessageBoard board) throws IOException {
        var rawCommand = config.getDecodeCommand();
        if (config.shouldSaveCommands()) {
            String historyCommand = config.loadSaveCommand(cipherText, rawCommand);
            
            if (!historyCommand.equals(rawCommand)) {
                if (board != null) {
                    board.showMessage("[*] It was decrypted/decoded with a cached command: \n" + historyCommand);
                }
                rawCommand = historyCommand;
            
            } else if (board != null) {
                board.showMessage("");
            }
        }
        return new ShellCommand(rawCommand, cipherText);
    }
    
    void eraseCommandHistory(String cipherText) {
        if (!config.shouldSaveCommands()) return;
        config.eraseCommand(cipherText);
    }


    public String searchAndDecrypt(String regex, byte[] content) throws CommandException, IOException, PatternException {
        return searchAndDecrypt(regex, content, null);
    }

    public String searchAndDecrypt(boolean isRequest, byte[] content, IMessageBoard board) throws CommandException, IOException, PatternException {
        return searchAndDecrypt(config.getPattern(isRequest), content, board);
    }

    public String searchAndDecrypt(String regex, byte[] content, IMessageBoard board) throws CommandException, IOException, PatternException {
        int[] indexes = searchPattern(regex, content);
        int beginIndex = indexes[0];
        int endIndex = indexes[1];
        String cipherText = new String(content).substring(beginIndex, endIndex);
        return decrypt(cipherText, board);
    }

    String decrypt(String cipherText, IMessageBoard board) throws CommandException, IOException {
        try {
            ShellCommand command = getDecodeCommand(cipherText, board);
            String plainText = command.execute(true);
            // if exception eraseCommandHistory and continue exception
            return plainText;
        } catch (Exception exception) {
            eraseCommandHistory(cipherText);
            throw exception;
        }
    }

    public boolean shouldPatchProxyRequest(String url) {
        return config.shouldPatchProxy() && Pattern.compile(config.getTargetPattern()).matcher(url).find();
    }

}