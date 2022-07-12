package burp;

import java.awt.Component;
import java.awt.BorderLayout;
import java.awt.Font;

import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.JPanel;
import javax.swing.JTextArea;

import java.io.PrintWriter;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class MessageEditorTab implements IMessageEditorTab {
    private JTextArea messageArea;
    // private ITextEditor editor;
    private IMessageEditor editor;

    
    private byte[] savedRequest;
    private TabScreen tabScreen;
    private PrintWriter stdout;
    private boolean isRequest, decodeException;
    private Config config;
    
    public MessageEditorTab(IMessageEditorController controller, boolean editable, TabScreen tabScreen, IBurpExtenderCallbacks callbacks, Config config)
    {
        isRequest = true;
        this.config = config;
        this.tabScreen = tabScreen;
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        //editor = callbacks.createTextEditor();
        // editor.setEditable(editable);
        editor = callbacks.createMessageEditor(controller, editable);
    }

    @Override
    public String getTabCaption()
    {
        return BurpExtender.name;
    }

    @Override
    public Component getUiComponent() {
        JPanel panel = new JPanel(new BorderLayout());
        messageArea = new JTextArea(2, 2);
        messageArea.setLineWrap(true);
		Font hackFont = new Font("Hack", Font.BOLD, 13);
        messageArea.setFont(hackFont);
        messageArea.setFocusable(true);
        messageArea.setEditable(false);
        panel.add(messageArea, BorderLayout.NORTH);
        panel.add(editor.getComponent(), BorderLayout.CENTER);
        return panel;
    }

    public void showMessage(String message) {
        messageArea.setText(message);
        messageArea.setVisible(message.length() > 0);

    }

    @Override
    public boolean isEnabled(byte[] content, boolean isRequest) {
        try {
            getPatternIndexes(content, isRequest);
            return true;
        } catch (Exception exception) {  }
        return false;
    }

    public int[] getPatternIndexes(byte[] content, boolean isRequest) throws Exception {
        return searchPattern(tabScreen.getPattern(isRequest), content);
    }

    public int[] searchPattern(String regex, byte[] text) throws Exception {
        Matcher matcher = Pattern.compile(regex).matcher(new String(text));
        if (matcher.find()) {
            return new int[] { matcher.start(1), matcher.end(1) };
        }
        throw new Exception("searchRegexPattern: pattern not found");
    }

    @Override
    public void setMessage(byte[] content, boolean isRequest) {
        if (content == null) return;

        this.isRequest = isRequest;
        savedRequest = content;
        String cipherText = "";
        try {
            int[] indexes = getPatternIndexes(content, isRequest);
            int beginIndex = indexes[0];
            int endIndex = indexes[1];
            cipherText = new String(content).substring(beginIndex, endIndex);
            String[] command = getDecodeCommand(cipherText);
            String plainText = Utils.executeCommand(command, true);
            // editor.setText(plainText.getBytes());
            // Utils.Log(stdout, new String(plainText.getBytes("Windows-1252"), "Windows-1252").substring(170+95, 170+95 + 1));
            editor.setMessage(plainText.getBytes("Windows-1252"), isRequest);
        } catch (Exception e) {
            decodeException = true;
            eraseCommandHistory(cipherText);
            // editor.setText("".getBytes());
            editor.setMessage("".getBytes(), isRequest);
            showMessage(e.toString());
            Utils.Log(stdout, e.toString());
        }
    }

    public String getHash( byte[] cipherText) {
        MessageDigest md5 = null;
        try {
            md5 = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {}
        md5.update(cipherText);
        return new BigInteger(1,md5.digest()).toString(16);
    }

    public String[] getEncodeCommand(String plainText) {
        String rawCommand = tabScreen.getEncodeCommand();
        return Utils.patchCommand(rawCommand, plainText);
    }

    public String[] getDecodeCommand(String cipherText) {
        var rawCommand = tabScreen.getDecodeCommand();
        if (tabScreen.shouldSaveDecodeCommands()) {
            var hash = getHash(cipherText.getBytes());
            String historyCommand = config.loadSaveCommand(hash, rawCommand);
            Utils.Log(stdout, "loaded  : " + rawCommand);            
            if (!historyCommand.equals(rawCommand)) {
                showMessage("[*] It was decrypted/decoded with a cached command: \n" + 
                historyCommand);
                rawCommand = historyCommand;
                // todo: try edit component to force update
            } else {
                showMessage("");
            }
        }
        return Utils.patchCommand(rawCommand, cipherText);
    }
        
    public void eraseCommandHistory(String cipherText) {
        if (!tabScreen.shouldSaveDecodeCommands()) return;
        var hash = getHash(cipherText.getBytes());
        config.eraseCommand(hash);
    }

    public byte[] patchRequest(byte[] rawContent, int beginIndex, int endIndex, byte[] contentPayload) {
        byte[] preContent = Arrays.copyOfRange(rawContent, 0, beginIndex);
        byte[] postContent = Arrays.copyOfRange(rawContent, endIndex, rawContent.length);

        byte[] newRequest = new byte[preContent.length + contentPayload.length + postContent.length];
        System.arraycopy(preContent, 0, newRequest, 0, preContent.length);
        System.arraycopy(contentPayload, 0, newRequest, preContent.length, contentPayload.length);
        System.arraycopy(postContent, 0, newRequest, preContent.length + contentPayload.length, postContent.length);
        return newRequest;
    }
    
    @Override
    public byte[] getMessage() {
        if (decodeException && 
        // !editor.isTextModified()) {
            !editor.isMessageModified()) {
                return savedRequest;
        }
        // String plainText = new String(editor.getText());
        String plainText = new String(editor.getMessage(), Charset.forName("utf8"));

        try {
            String[] command = getEncodeCommand(plainText);
            String cipherText = Utils.executeCommand(command, true);
            int[] indexes = getPatternIndexes(savedRequest, this.isRequest);
            int beginIndex = indexes[0];
            int endIndex = indexes[1];
            return patchRequest(savedRequest, beginIndex, endIndex, cipherText.getBytes());
        } catch (Exception e) {
            showMessage(e.toString());
            Utils.Log(stdout, e.toString());
        }
        return savedRequest;
    }

    @Override
    public boolean isModified() {
        return true;
    }

    @Override
    public byte[] getSelectedData()
    {
        // return editor.getSelectedText();
        return editor.getSelectedData();
    }
    
    
}