package reencrypt;

import burp.api.montoya.ui.Selection;

import java.awt.Component;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Font;
import java.util.Optional;

import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.ScrollPaneConstants;

import java.nio.charset.Charset;

public class RequestResponseTab implements IMessageBoard {

    private RequestResponseEditor editor;
    private JTextArea errorArea;
    private JScrollPane scrollPane;
    private byte[] cachedRequestContent, cachedEditorContent;
    private boolean isRequest, readOnly;
    private String errorMessage;
    private Color colorMessage;
    private ReEncrypt reEncrypt;
    
    public RequestResponseTab(RequestResponseEditor editor, ReEncrypt reEncrypt, boolean readOnly)
    {
        this.isRequest = true;
        // this.decodeException = false;
        this.editor = editor;
        this.reEncrypt = reEncrypt;
        this.readOnly = readOnly;
        this.cachedEditorContent = new byte[]{};
        this.errorMessage = "";
    }

    public String caption()
    {
        return App.name;
    }

    public Component uiComponent() {
        JPanel panel = new JPanel(new BorderLayout());
        errorArea = new JTextArea(0, 0);
        errorArea.setLineWrap(true);
		Font hackFont = new Font("Hack", Font.BOLD, 13);
        errorArea.setFont(hackFont);
        errorArea.setFocusable(true);
        errorArea.setEditable(false);
        this.scrollPane = new JScrollPane(errorArea);
        scrollPane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
        panel.add(scrollPane, BorderLayout.NORTH);
        panel.add(editor.uiComponent(), BorderLayout.CENTER);
        showMessage(this.errorMessage, this.colorMessage);
        return panel;
    }

    public void showMessage(String message) {
        showMessage(message, Color.decode("#f14c4c"));
    }

    public void showMessage(String message, Color color) {
        this.errorMessage = message;
        this.colorMessage = color;
        errorArea.setText(message);
        errorArea.setForeground(color);
        errorArea.setVisible(message.length() > 0);
        scrollPane.setVisible(errorArea.isVisible());
    }

    public boolean isEnabledFor(byte[] content, boolean isRequest) {
        try {
            reEncrypt.searchPattern(isRequest, content);
            return true;
        } catch (Exception exception) {  }
        return false;
    }

    public void setBytes(byte[] content, boolean isRequest) {
        System.out.println("calling setBytes");
        if (content == null) return;

        this.isRequest = isRequest;
        this.cachedRequestContent = content;
        try {
            String plainText = reEncrypt.searchAndDecrypt(isRequest, content, this);
            this.cachedEditorContent = plainText.getBytes("Windows-1252");
            editor.setBytes(this.cachedEditorContent);
            
        } catch (Exception e) {
            // TODO: not set "" in repeater (but set in intercept)
            editor.setBytes("".getBytes());
            showMessage(e.getMessage());
        }
    }
    
    public byte[] getBytes() {
        System.out.println("calling getBytes");
        if (new String(this.cachedEditorContent).equals(new String(this.editor.getBytes()))) {
            return this.cachedRequestContent;
        }
        System.out.println("different");


        String plainText = new String(editor.getBytes(), Charset.forName("utf8"));

        try {
            return reEncrypt.encryptAndPatch(this.cachedRequestContent, this.isRequest, plainText);
        } catch (Exception e) {
            System.out.println(e.getMessage());
            showMessage(e.toString());
        }
        return cachedRequestContent;
    }

    public boolean isModified() {
        return editor.isModified();
    }

    public Selection selectedData()
    {
        Optional<Selection> selection = editor.selection();
        if (!selection.isEmpty()) {
            return selection.get();
        }
        return null;
    }
    
    
}