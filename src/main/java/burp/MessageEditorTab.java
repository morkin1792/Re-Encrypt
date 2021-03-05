package burp;

import java.awt.Component;
import java.awt.BorderLayout;
import java.util.Arrays;

import javax.swing.JPanel;

public class MessageEditorTab implements IMessageEditorTab {
    private ITextEditor txtEditor;
    private byte[] currentMessage;
    private TabScreen tabScreen;
    private IExtensionHelpers helpers;
    
    public MessageEditorTab(boolean editable, TabScreen tabScreen, IBurpExtenderCallbacks callbacks)
    {
        this.tabScreen = tabScreen;
        this.helpers = callbacks.getHelpers();
        txtEditor = callbacks.createTextEditor();
        txtEditor.setEditable(editable);
    }

    @Override
    public String getTabCaption()
    {
        return "RePost";
    }

    @Override
    public Component getUiComponent() {
        JPanel center = new JPanel(new BorderLayout());
        center.add(txtEditor.getComponent());
        return center;
    }

    @Override
    public boolean isEnabled(byte[] content, boolean isRequest) {
        // enable this tab for requests containing a data parameter
        return true;
    }

    public int[] getPatternIndexes(byte[] content) throws Exception{
        String beginPattern = tabScreen.getPrePattern();
        String endPattern = tabScreen.getPostPattern();

        int beginIndex = helpers.indexOf(content, beginPattern.getBytes(), false, 0, content.length) + beginPattern.length();
        int endIndex = helpers.indexOf(content, endPattern.getBytes(), false, 0, content.length);
        if (beginIndex < 0 || endIndex < 0) {
            throw new Exception("getPatternIndexes: pattern not found");
        }
        return new int[]{beginIndex, endIndex};
    }

    @Override
    public void setMessage(byte[] content, boolean isRequest) {
        if (content == null) {
            txtEditor.setText(null);
            txtEditor.setEditable(false);
        }
                        
        try {
            int[] indexes = getPatternIndexes(content);
            int beginIndex = indexes[0];
            int endIndex = indexes[1];
            
            String cipherText = new String(content).substring(beginIndex, endIndex);
            String[] command = tabScreen.getPreCommand(cipherText);
            
            String plainText = BurpExtender.execCommand(command, true);
            // System.out.println("plainText: " + plainText);
            txtEditor.setText(plainText.getBytes());
            currentMessage = content;
        } catch (Exception e) {
        }
    }
    
    @Override
    public byte[] getMessage() {
        String plainText = new String(txtEditor.getText());
        String[] command = tabScreen.getPostCommand(plainText);
        String cipherText = BurpExtender.execCommand(command, true);
        // System.out.println("cipherText: " + cipherText);
        try {
            int[] indexes = getPatternIndexes(currentMessage);
            int beginIndex = indexes[0];
            int endIndex = indexes[1];
            byte[] preContent = Arrays.copyOfRange(currentMessage, 0, beginIndex);
            byte[] postContent = Arrays.copyOfRange(currentMessage, endIndex, currentMessage.length);
            
            return (new String(preContent) + cipherText + new String(postContent)).getBytes();

        } catch (Exception e) {}

        
        return currentMessage;
    }

    @Override
    public boolean isModified() {
        return txtEditor.isTextModified();
    }

    @Override
    public byte[] getSelectedData()
    {
        return txtEditor.getSelectedText();
    }
    
    
}