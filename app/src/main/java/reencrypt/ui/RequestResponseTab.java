package reencrypt.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.requests.MalformedRequestException;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.EditorOptions;
import reencrypt.App;
import reencrypt.CapturePattern;
import reencrypt.LogData;
import reencrypt.ReEncrypt;
import reencrypt.Utils;

import java.awt.Component;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Font;
import java.util.ArrayList;
import java.util.Optional;
import java.util.regex.Pattern;

import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import java.nio.charset.Charset;

public class RequestResponseTab {

    private MontoyaApi api;
    private ArrayList<RequestResponseEditor> editors;
    private RequestResponseEditor printEditor;
    private final JPanel panel;
    private final JTextArea errorArea;
    private final Font hackFont;
    private JScrollPane scrollPane;
    private JTabbedPane tabbedPane;
    private byte[] cachedContentFromIsEnabledFor;
    private String cachedURLFromIsEnabledFor;
    private byte[] cachedContentFromSetBytes;
    private String cachedMethod, cachedUrl;
    private boolean isRequest;
    private String errorMessage;
    private Color colorMessage;
    private ReEncrypt reEncrypt;
    private boolean readOnly;
    private int tabbedPaneLastSelectedIndex, cachedCaretPosition;
    private String toolType;

    public RequestResponseTab(boolean isRequest, MontoyaApi api, ReEncrypt reEncrypt, boolean readOnly,
            String toolType) {
        this.isRequest = isRequest;
        this.api = api;
        this.reEncrypt = reEncrypt;
        this.readOnly = readOnly;
        this.toolType = toolType;

        this.editors = new ArrayList<>();
        this.tabbedPaneLastSelectedIndex = 0;
        this.errorMessage = "";
        this.panel = new JPanel(new BorderLayout());
        this.errorArea = new JTextArea(0, 0);
        this.hackFont = new Font("Hack", Font.BOLD, 13);
        mountUi();
    }

    public String caption() {
        return App.name;
    }

    public void mountUi() {
        errorArea.setLineWrap(true);
        errorArea.setFont(hackFont);
        errorArea.setFocusable(true);
        errorArea.setEditable(false);
        this.scrollPane = new JScrollPane(errorArea);
        this.tabbedPane = new JTabbedPane();
        this.tabbedPane.addChangeListener(new ChangeListener() {
            @Override
            public void stateChanged(ChangeEvent e) {
                int selectedIndex = tabbedPane.getSelectedIndex();
                tabbedPaneLastSelectedIndex = selectedIndex;
            }
        });
        scrollPane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
        panel.add(scrollPane, BorderLayout.NORTH);
        panel.add(tabbedPane, BorderLayout.CENTER);

        showMessage(this.errorMessage, this.colorMessage);
    }

    void reloadEditors() {

        // saving last select index && caret position
        int cachedLastSelectedIndex = this.tabbedPaneLastSelectedIndex;
        var lastEditor = getLastSelectedEditor();
        if (lastEditor != null) {
            cachedCaretPosition = lastEditor.caretPosition();
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
                    newEditor = new RequestResponseEditor(
                            api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY));
                }
            } else {
                if (!readOnly) {
                    newEditor = new RequestResponseEditor(api.userInterface().createHttpResponseEditor());
                } else {
                    newEditor = new RequestResponseEditor(
                            api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY));

                }
            }
            System.out.println("reloading editors 7.");
            newEditor.setPattern(pattern);
            editors.add(newEditor);

        }
        if (reEncrypt.getConfig().isPrintEditorEnabled(isRequest)) {
            if (isRequest) {
                printEditor = new RequestResponseEditor(
                        api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY));
            } else {
                printEditor = new RequestResponseEditor(
                        api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY));
            }
        }
        boolean atLeastOneTab = false;

        System.out.println("middle of reloading editors.");
        for (var editor : editors) {
            try {
                if (cachedContentFromIsEnabledFor == null) {
                    cachedContentFromIsEnabledFor = new byte[0];
                }
                if (!editor.getPattern().isTarget(cachedURLFromIsEnabledFor)) {
                    continue;
                }
                ReEncrypt.searchPattern(editor.getPattern().getPatternRegex(), cachedContentFromIsEnabledFor);
                tabbedPane.add(editor.getPattern().getName(), editor.uiComponent());
                System.out.println("adding tabs " + editor.getPattern().getName());
                atLeastOneTab = true;
            } catch (Exception e) {
                System.out.println(editors.size() + " editors found.");
                System.out.println("not adding tab " + editor + " because pattern not found." + e);
            }
        }
        if (atLeastOneTab && printEditor != null) {
            tabbedPane.add("Print Tab", printEditor.uiComponent());
        }

        // restoring the last selected tab
        this.tabbedPaneLastSelectedIndex = cachedLastSelectedIndex;
        if (getLastSelectedEditor() != null) {
            tabbedPane.setSelectedIndex(tabbedPaneLastSelectedIndex);
        }
    }

    public RequestResponseEditor getLastSelectedEditor() {
        if (tabbedPane.getTabCount() > 0 && editors.size() > 0 && tabbedPaneLastSelectedIndex >= 0
                && tabbedPaneLastSelectedIndex < tabbedPane.getTabCount()) {
            return (tabbedPaneLastSelectedIndex == tabbedPane.getTabCount() - 1) ? printEditor
                    : editors.get(tabbedPaneLastSelectedIndex);
        }
        return null;
    }

    public Component uiComponent() {
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

    public boolean isEnabledFor(HttpRequestResponse requestResponse, boolean isRequest) {
        HttpRequest request = requestResponse.request();
        String url;
        try {
            if (request == null) {
                return false;
            }
            url = request.url();
        } catch (MalformedRequestException e) {
            return false;
        }

        byte[] content = request.toByteArray().getBytes();
        if (!isRequest) {
            content = requestResponse.response().toByteArray().getBytes();
        }

        System.out.println("isEnabledFor " + (isRequest ? "Request " : "Response ") + request.method() + " "
                + url.substring(0, Math.min(url.length(), 100)) + "...");
        System.out.println("isEnabledFor " + editors.size() + " editors found.");
        System.out.println("setting cachedContentFromIsEnabledFor with " + content.length + " bytes.");
        this.cachedContentFromIsEnabledFor = content;
        this.cachedURLFromIsEnabledFor = url;

        for (var pattern : reEncrypt.getConfig().getActivePatterns(isRequest)) {
            try {
                if (pattern.isTarget(url)) {
                    ReEncrypt.searchPattern(pattern.getPatternRegex(), content);
                    System.out.println("found pattern: " + pattern.getName());
                    return true;
                }
            } catch (Exception exception) {
                System.out.println("isEnableFor Exception" + exception);
                System.out.println(url.substring(0, Math.min(url.length(), 100)) + "...");
                System.out.println(new String(content).substring(0, Math.min(content.length, 100)) + "...");
            }
        }
        return false;
    }

    public void setBytes(HttpService httpService, String method, String url, byte[] content) {
        System.out.println("calling setBytes. " + editors.size() + " editors found.");
        reloadEditors();
        if (content == null)
            return;

        this.cachedContentFromSetBytes = content;
        this.cachedMethod = method;
        this.cachedUrl = url;
        byte[] printEditorContent = content;
        ArrayList<String> regexes2Highlight = new ArrayList<>();
        for (var editor : editors) {
            System.out.println("looking for regex: " + editor.getPattern().getPatternRegex());
            System.out.println("to apply the command: " + editor.getPattern().getDecCommand());
            try {
                LogData logData = new LogData(toolType, isRequest, cachedMethod, cachedUrl);
                String plainText = reEncrypt.searchAndDecrypt(editor.getPattern(), cachedContentFromSetBytes, logData);
                editor.setBytes(httpService, plainText.getBytes("Windows-1252"));
                regexes2Highlight.add(editor.getPattern().getPatternRegex());
                if (printEditor != null) {
                    if (reEncrypt.getConfig().isEscapingDoubleQuotes(isRequest)) {
                        plainText = plainText.replace("\"", "\\\"");
                    }
                    printEditorContent = reEncrypt.matchReplace(printEditorContent, editor.getPattern(), plainText);
                }
                showMessage("");
            } catch (Exception e) {
                System.out.println("exception in setBytes: " + e);
            }
        }

        setPrintEditor(httpService, printEditorContent, regexes2Highlight);
        setFocusAndCaret();
    }

    private void setPrintEditor(HttpService httpService, byte[] printEditorContent,
            ArrayList<String> regexes2Highlight) {
        if (printEditor != null) {
            printEditor.setBytes(httpService, printEditorContent);
            Component editorComponent = printEditor.uiComponent();
            boolean isHighlighting = reEncrypt.getConfig().isHighlightingPrintEditor(isRequest);
            if (isHighlighting && regexes2Highlight.size() > 0) {
                String regexHighlight = String.join("|", regexes2Highlight);
                Pattern pattern = Pattern.compile(regexHighlight);
                var color = reEncrypt.getConfig().getPrintEditorHighlightColor(isRequest);
                Utils.highlightTextComponents(editorComponent, pattern, color);
            }
        }
    }

    private void setFocusAndCaret() {
        try {
            var editor = getLastSelectedEditor();
            if (editor != null) {
                // set caret
                editor.setCaretPosition(cachedCaretPosition);

                // set focus
                SwingUtilities.invokeLater(() -> {
                    // IMPROVEME: find and implement a way to set the focus without a timer
                    Timer timer = new Timer(100, e -> {
                        Component editorComponent = getLastSelectedEditor().uiComponent();
                        var textComponent = Utils.findFirstTextComponent(editorComponent);
                        textComponent.requestFocusInWindow();
                    });
                    timer.setRepeats(false);
                    timer.start();
                });
            }
        } catch (NoSuchMethodError e) {
            System.out.println("setCaretPosition not defined in this burp version " + e);
        }
    }

    public byte[] getBytes() {
        System.out.println("calling getBytes");
        byte[] patchedRequest = cachedContentFromSetBytes.clone();
        for (var editor : editors) {
            String plainText = new String(editor.getBytes(), Charset.forName("utf8"));
            try {
                LogData logData = new LogData(toolType, isRequest, cachedMethod, cachedUrl);
                patchedRequest = reEncrypt.encryptAndPatch(patchedRequest, editor.getPattern(), plainText, logData);
            } catch (Exception e) {
                // showMessage(e.toString());
                System.out.println("getBytes exception: " + e.getMessage());
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

    public Selection selectedData() {
        for (var editor : editors) {
            Optional<Selection> selection = editor.selection();
            if (!selection.isEmpty()) {
                return selection.get();
            }
        }
        return null;
    }

}