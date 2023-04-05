package reencrypt;

import burp.api.montoya.ui.Selection;

import java.awt.Component;
import java.awt.Dimension;
import java.awt.BorderLayout;
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
    // private PrintWriter stdout;
    private boolean isRequest, readOnly, firstView, decodeException;
    private String errorMessage;
    private ReEncrypt reEncrypt;
    
    public RequestResponseTab(RequestResponseEditor editor, ReEncrypt reEncrypt, boolean readOnly)
    {
        this.isRequest = true;
        this.decodeException = false;
        // this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.editor = editor;
        this.reEncrypt = reEncrypt;
        this.readOnly = readOnly;
        this.firstView = true;
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
        scrollPane.setMaximumSize(new Dimension(10, 10));
        scrollPane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
        panel.add(scrollPane, BorderLayout.NORTH);
        panel.add(editor.uiComponent(), BorderLayout.CENTER);
        showMessage(this.errorMessage);
        return panel;
    }

    public void showMessage(String message) {
        this.errorMessage = message;
        System.out.println(message);
        errorArea.setText(message);
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
            this.decodeException = true;
            editor.setBytes("".getBytes());
            showMessage(e.getMessage());
            // Utils.log(stdout, e.toString());
        }
        
        if (!this.decodeException && !readOnly && firstView) {
            this.firstView = false;
            System.out.println("if you don't change something, the request will be the same.");
            showMessage("if you don't change something, the request will be the same.");
        }
    }
    
    public byte[] getBytes() {
        System.out.println("calling getBytes");
        // System.out.println(new String(this.editor.getBytes()));
        // System.out.println("vs");
        // System.out.println(new String(this.cachedEditorContent));
        if (decodeException || this.cachedEditorContent == null || new String(this.cachedEditorContent).equals(new String(this.editor.getBytes()))) {
            return this.cachedRequestContent;
        }
        System.out.println("different");


        String plainText = new String(editor.getBytes(), Charset.forName("utf8"));

        try {
            return reEncrypt.encryptAndPatch(this.cachedRequestContent, this.isRequest, plainText);
        } catch (Exception e) {
            System.out.println(e.getMessage());
            showMessage(e.toString());
            // Utils.log(stdout, e.toString());
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