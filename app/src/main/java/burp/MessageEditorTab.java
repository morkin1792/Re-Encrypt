package burp;

import java.awt.Component;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.io.PrintWriter;

public class MessageEditorTab implements IMessageEditorTab {
    private ITextEditor editor;
    private byte[] savedRequest;
    private TabScreen tabScreen;
    private PrintWriter stdout;
    private boolean isRequest;

    public MessageEditorTab(IMessageEditorController controller, boolean editable, TabScreen tabScreen, IBurpExtenderCallbacks callbacks)
    {
        isRequest = true;
        this.tabScreen = tabScreen;
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        editor = callbacks.createTextEditor();
        editor.setEditable(editable);
    }

    @Override
    public String getTabCaption()
    {
        return BurpExtender.name;
    }

    @Override
    public Component getUiComponent() {
        return editor.getComponent();
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
        try {
            int[] indexes = getPatternIndexes(content, isRequest);
            int beginIndex = indexes[0];
            int endIndex = indexes[1];
            String cipherText = new String(content).substring(beginIndex, endIndex);
            String[] command = tabScreen.getDecodeCommand(cipherText);
            String plainText = BurpExtender.execCommand(command, true);
            editor.setText(plainText.getBytes());
        } catch (Exception e) {
            editor.setText(e.toString().getBytes());
            Utils.Log(stdout, e.toString());
        }
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
        String plainText = new String(editor.getText());
        String[] command = tabScreen.getEncodeCommand(plainText);
        try {
            String cipherText = BurpExtender.execCommand(command, true);
            int[] indexes = getPatternIndexes(savedRequest, this.isRequest);
            int beginIndex = indexes[0];
            int endIndex = indexes[1];
            return patchRequest(savedRequest, beginIndex, endIndex, cipherText.getBytes());
        } catch (Exception e) {
            Utils.Log(stdout, e.toString());
        }
        return savedRequest;
    }

    @Override
    public boolean isModified() {
        return editor.isTextModified();
    }

    @Override
    public byte[] getSelectedData()
    {
        return editor.getSelectedText();
    }
    
    
}