package reencrypt;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.EditorOptions;
import reencrypt.exception.PatternException;

import java.awt.Component;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Font;
import java.util.ArrayList;
import java.util.Optional;

import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.ScrollPaneConstants;

import java.nio.charset.Charset;

public class RequestResponseTab implements IMessageBoard {

    private MontoyaApi api;
    private ArrayList<RequestResponseEditor> editors;
    private final JPanel panel;
    private final JTextArea errorArea;
    private final Font hackFont;
    private JScrollPane scrollPane;
    private JTabbedPane tabbedPane;
    private byte[] cachedContentFromIsEnabledFor;
    private byte[] cachedContentFromSetBytes;
    private boolean isRequest;
    private String errorMessage;
    private Color colorMessage;
    private ReEncrypt reEncrypt;
    private boolean readOnly;
    private int cachedLastModifiedIndex, cachedCaretPosition;

    public RequestResponseTab(boolean isRequest, MontoyaApi api, ReEncrypt reEncrypt, boolean readOnly)
    {
        this.isRequest = isRequest;
        this.api = api;
        this.reEncrypt = reEncrypt;
        this.readOnly = readOnly;
        
        this.editors = new ArrayList<>();
        this.cachedLastModifiedIndex = 0;
        this.errorMessage = "";
        this.panel = new JPanel(new BorderLayout());
        this.errorArea = new JTextArea(0, 0);
        this.hackFont = new Font("Hack", Font.BOLD, 13);
        mountUi();
    }

    public String caption()
    {
        return App.name;
    }

    public void mountUi() {
        errorArea.setLineWrap(true);
        errorArea.setFont(hackFont);
        errorArea.setFocusable(true);
        errorArea.setEditable(false);
        this.scrollPane = new JScrollPane(errorArea);
        this.tabbedPane = new JTabbedPane();
        scrollPane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
        panel.add(scrollPane, BorderLayout.NORTH);
        panel.add(tabbedPane, BorderLayout.CENTER);

        showMessage(this.errorMessage, this.colorMessage);
    }

    void reloadEditors() {
        // saving the index of the modified tab
        int lastModifiedIndex = -1;
        for (var editor : editors) {
            if (editor.isModified()) {
                lastModifiedIndex = tabbedPane.indexOfTab(editor.getPattern().getName());
                cachedLastModifiedIndex = lastModifiedIndex;
                cachedCaretPosition = editor.caretPosition();
                break;
            }
        }
        if (lastModifiedIndex == -1) {
            lastModifiedIndex = cachedLastModifiedIndex;
        }

        editors.clear();

        tabbedPane.removeAll();

        CapturePattern[] patterns = reEncrypt.getConfig().getActivePatterns(isRequest);
        
        for (CapturePattern pattern : patterns) {
            RequestResponseEditor newEditor = null;
            if (isRequest) {
                if (!readOnly) {
                    newEditor = new RequestResponseEditor(api.userInterface().createHttpRequestEditor());
                } else {
                    newEditor = new RequestResponseEditor(api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY));
                }
            } else {
                if (!readOnly) {
                    newEditor = new RequestResponseEditor(api.userInterface().createHttpResponseEditor());
                } else {
                    newEditor = new RequestResponseEditor(api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY));

                }
            }
            System.out.println("reloading editors 7.");
            newEditor.setPattern(pattern);
            editors.add(newEditor);

        }

        System.out.println("middle of reloading editors.");
        for (var editor : editors) {
            try {
                if (cachedContentFromIsEnabledFor == null) {
                    System.out.println("cachedContentFromIsEnabledFor is null, setting to empty byte array.");
                    cachedContentFromIsEnabledFor = new byte[0];
                    System.out.println(editor.getPattern().getName() + " will not be enabled because no content was set yet.");
                }
                ReEncrypt.searchPattern(editor.getPattern().getRegex(), cachedContentFromIsEnabledFor);
                tabbedPane.add(editor.getPattern().getName(), editor.uiComponent());
                System.out.println("adding tabs " + editor.getPattern().getName());
            } catch (Exception e) {
                System.out.println(editors.size() + " editors found.");
                System.out.println("not adding tab " + editor + " because pattern not found." + e);
            }
        }
        
        // restoring the index of the modified tab
        if (tabbedPane.getTabCount() > 0 && lastModifiedIndex >= 0 && lastModifiedIndex < tabbedPane.getTabCount()) {
            tabbedPane.setSelectedIndex(lastModifiedIndex);
            System.out.println("size of editors: " + editors.size());
            System.out.println("size of tabbedPane: " + tabbedPane.getTabCount());
            System.out.println("lastModifiedIndex: " + lastModifiedIndex);
        }

    }

    public Component uiComponent() {
        System.out.println("uiComponent called.");
        if (reEncrypt.getConfig().checkReloadEditors(isRequest) || editors.size() == 0) {
            reloadEditors();
        }
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

    public boolean isEnabledFor(byte[] content) {
        System.out.println("isEnabledFor called. " + editors.size() + " editors found.");
        System.out.println("setting cachedContentFromIsEnabledFor with " + content.length + " bytes.");
        this.cachedContentFromIsEnabledFor = content;

        for (var pattern : reEncrypt.getConfig().getActivePatterns(isRequest)) {
            try {
                ReEncrypt.searchPattern(pattern.getRegex(), content);
                System.out.println("found pattern: " + pattern.name);
                return true;
            } catch (Exception exception) { 
                System.out.println("isEnableFor Exception" + exception);
                System.out.println(new String(content));
             }
        }
        return false;
    }

    public void setBytes(byte[] content) {
        System.out.println("calling setBytes. " + editors.size() + " editors found.");
        reloadEditors();
        if (content == null) return;

        this.cachedContentFromSetBytes = content;
        for (var editor : editors) {   
            System.out.println("looking for regex: " + editor.getPattern().getRegex());
            System.out.println("to apply the command: " + editor.getPattern().getDecCommand());
            try {
                // editor.setEnabled(true);
                String plainText = reEncrypt.searchAndDecrypt(editor.getPattern(), cachedContentFromSetBytes);
                editor.setBytes(plainText.getBytes("Windows-1252"));
                showMessage("");
            } catch (PatternException e) {
                editor.setBytes("[-] pattern not found".getBytes());
            } catch (Exception e) {
                System.out.println("exception in setBytes: " + e);
                // editor.setBytes("".getBytes());
                // editor.setEnabled(false);
                // showMessage(e.getMessage());
            }
        }
        // trying to restore the caret position
        if (cachedLastModifiedIndex >= 0 && cachedLastModifiedIndex < editors.size()) {
            var editor = editors.get(cachedLastModifiedIndex);
            System.out.println("restoring caret position to " + cachedCaretPosition);
            editor.setCaretPosition(cachedCaretPosition);
        }
    
    }
    
    public byte[] getBytes() {
        System.out.println("calling getBytes");
        byte[] patchedRequest = cachedContentFromSetBytes.clone();
        for (var editor : editors) {   
            String plainText = new String(editor.getBytes(), Charset.forName("utf8"));   
            try {
                patchedRequest = reEncrypt.encryptAndPatch(patchedRequest, editor.getPattern(), plainText);
            } catch (Exception e) {
                // showMessage(e.toString());
            }
            // return cachedContentFromSetBytes;
        }
        return patchedRequest;
    }

    public boolean isModified() {
        for (var editor : editors) {
            if (editor.isModified())
                return true;
        }
        return false;
    }

    public Selection selectedData()
    {
        for (var editor : editors) {
            Optional<Selection> selection = editor.selection();
            if (!selection.isEmpty()) {
                return selection.get();
            }
        }
        return null;
    }
    
    
}