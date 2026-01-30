package reencrypt.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.requests.MalformedRequestException;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.EditorOptions;
import reencrypt.App;
import reencrypt.CapturePattern;
import reencrypt.CommandOutput;
import reencrypt.LogData;
import reencrypt.ReEncrypt;
import reencrypt.Utils;
import reencrypt.exception.CommandException;

import java.awt.Component;
import java.awt.BorderLayout;
import java.awt.Color;
import java.util.ArrayList;
import java.util.Optional;
import java.util.regex.Pattern;

import javax.swing.JPanel;
import javax.swing.JTabbedPane;
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
    private JTabbedPane tabbedPane;
    private byte[] cachedContentFromIsEnabledFor;
    private String cachedURLFromIsEnabledFor;
    private byte[] cachedContentFromSetBytes;
    private String cachedMethod, cachedUrl;
    private boolean isRequest;
    private ReEncrypt reEncrypt;
    private boolean readOnly;
    private int tabbedPaneLastSelectedIndex, cachedCaretPosition;
    private ToolType toolType;

    public RequestResponseTab(boolean isRequest, MontoyaApi api, ReEncrypt reEncrypt, boolean readOnly,
            ToolType toolType) {
        this.isRequest = isRequest;
        this.api = api;
        this.reEncrypt = reEncrypt;
        this.readOnly = readOnly;
        this.toolType = toolType;

        this.editors = new ArrayList<>();
        this.tabbedPaneLastSelectedIndex = 0;
        this.panel = new JPanel(new BorderLayout());
        mountUi();
    }

    public String caption() {
        return App.name;
    }

    public void mountUi() {
        tabbedPane = new JTabbedPane();
        tabbedPane.addChangeListener(new ChangeListener() {
            @Override
            public void stateChanged(ChangeEvent e) {
                int selectedIndex = tabbedPane.getSelectedIndex();
                tabbedPaneLastSelectedIndex = selectedIndex;
            }
        });
        panel.add(tabbedPane, BorderLayout.CENTER);
    }

    void reloadEditors() {
        // saving last select index && caret position
        int cachedLastSelectedIndex = this.tabbedPaneLastSelectedIndex;
        var lastEditor = getLastSelectedEditor();
        if (lastEditor != null) {
            cachedCaretPosition = lastEditor.caretPosition();
        }

        tabbedPane.removeAll();

        ArrayList<RequestResponseEditor> newEditorsList = new ArrayList<>();
        CapturePattern[] patterns = reEncrypt.getConfig().getActivePatterns(isRequest);

        for (CapturePattern pattern : patterns) {
            // Try to reuse existing editor for this pattern, to keep the alerts
            RequestResponseEditor editorToUse = null;
            for (RequestResponseEditor existing : editors) {
                if (existing.getPattern().getName().equals(pattern.getName())) {
                    editorToUse = existing;
                    editorToUse.setPattern(pattern); // Update pattern definition in case it changed
                    break;
                }
            }

            if (editorToUse == null) {
                // Create new editor if not found
                if (isRequest) {
                    if (!readOnly) {
                        editorToUse = new RequestResponseEditor(api.userInterface().createHttpRequestEditor());
                    } else {
                        editorToUse = new RequestResponseEditor(
                                api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY));
                    }
                } else {
                    if (!readOnly) {
                        editorToUse = new RequestResponseEditor(api.userInterface().createHttpResponseEditor());
                    } else {
                        editorToUse = new RequestResponseEditor(
                                api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY));
                    }
                }
                editorToUse.setPattern(pattern);
            }
            newEditorsList.add(editorToUse);
        }

        // Update the main list
        this.editors = newEditorsList;
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

        for (var editor : editors) {
            try {
                if (cachedContentFromIsEnabledFor == null) {
                    cachedContentFromIsEnabledFor = new byte[0];
                }
                if (!editor.getPattern().isTarget(cachedURLFromIsEnabledFor, api)) {
                    continue;
                }
                ReEncrypt.searchPattern(editor.getPattern().getCaptureRegex(), cachedContentFromIsEnabledFor);
                tabbedPane.add(editor.getPattern().getName(), editor.uiComponent());
                atLeastOneTab = true;
            } catch (Exception e) {
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

    // Alert colors
    private static final Color ALERT_COLOR_ERROR = Utils.hexToColor("#f14c4c");
    private static final Color ALERT_COLOR_WARNING = Utils.hexToColor("#f09e2cff");

    public boolean isEnabledFor(HttpRequestResponse requestResponse, boolean isRequest) {
        // Disable editor for Intruder if auto-encrypt/decrypt is enabled
        // (the HttpHandler already handles the transformation)
        if (ToolType.INTRUDER == toolType) {
            if (isRequest && reEncrypt.getConfig().isIntruderRequestEncryptEnabled()) {
                return false;
            }
            if (!isRequest && reEncrypt.getConfig().isIntruderResponseDecryptEnabled()) {
                return false;
            }
        }

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

        this.cachedContentFromIsEnabledFor = content;
        this.cachedURLFromIsEnabledFor = url;

        for (var pattern : reEncrypt.getConfig().getActivePatterns(isRequest)) {
            try {
                if (pattern.isTarget(url, api)) {
                    ReEncrypt.searchPattern(pattern.getCaptureRegex(), content);
                    return true;
                }
            } catch (Exception exception) {
                System.out.println("isEnableFor Exception" + exception);
            }
        }
        return false;
    }

    public void setBytes(HttpService httpService, String method, String url, byte[] content) {
        reloadEditors();
        if (content == null)
            return;
        this.cachedContentFromSetBytes = content;
        this.cachedMethod = method;
        this.cachedUrl = url;
        byte[] printEditorContent = content;
        ArrayList<String> regexes2Highlight = new ArrayList<>();
        for (var editor : editors) {
            try {
                LogData logData = new LogData(toolType.toolName(), isRequest, cachedMethod, cachedUrl);
                CommandOutput commandOutput = reEncrypt.searchAndDecrypt(editor.getPattern(), content, logData);
                String plainText = commandOutput.getOutput();

                if (commandOutput.isFailed() && !commandOutput.isCached()) {
                    // if failed and there is no cache, throw CommandException
                    commandOutput.getOutputCheckingExitCode();
                }
                editor.setBytes(httpService, plainText.getBytes("Windows-1252"));
                regexes2Highlight.add(editor.getPattern().getCaptureRegex());
                if (printEditor != null) {
                    if (reEncrypt.getConfig().isEscapingDoubleQuotes(isRequest)) {
                        plainText = plainText.replace("\"", "\\\"");
                    }
                    printEditorContent = reEncrypt.matchReplace(printEditorContent, editor.getPattern(), plainText);
                }
                // Set per-editor alert based on command result
                if (commandOutput.isCached()) {
                    editor.setDecodeAlert("[*] Using CACHED output because decrypt command failed",
                            ALERT_COLOR_WARNING);
                } else {
                    editor.setDecodeAlert("", Color.BLACK); // Clear decode alert
                }
            } catch (CommandException e) {
                editor.setDecodeAlert("[-] Decrypt command failed: " + e.getMessage(), ALERT_COLOR_ERROR);
            } catch (Exception e) {
                editor.setDecodeAlert("[-] Decode error: " + e.toString(), ALERT_COLOR_ERROR);
            }
        }

        setPrintEditor(httpService, printEditorContent, regexes2Highlight);
        if (ToolType.REPEATER == toolType && isRequest) {
            setFocusAndCaret();
        }
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
                    Timer timer = new Timer(350, e -> {
                        RequestResponseEditor currentEditor = getLastSelectedEditor();
                        if (currentEditor != null) {
                            Component editorComponent = currentEditor.editorComponent();
                            var textComponent = Utils.findMainTextComponent(editorComponent);
                            if (textComponent != null) {
                                boolean focusSuccess = textComponent.requestFocusInWindow();
                                if (!focusSuccess) {
                                    textComponent.requestFocus();
                                }
                            }
                        }
                    });
                    timer.setRepeats(false);
                    timer.start();
                });
            }
        } catch (NoSuchMethodError e) {
            api.logging().raiseErrorEvent(
                    "Please update your Burp Suite, setCaretPosition is not defined in this burp version: " + e);
        }
    }

    public byte[] getBytes() {
        byte[] patchedRequest = cachedContentFromSetBytes.clone();
        for (var editor : editors) {
            String plainText = new String(editor.getBytes(), Charset.forName("utf8"));
            try {
                LogData logData = new LogData(toolType.toolName(), isRequest, cachedMethod, cachedUrl);
                patchedRequest = reEncrypt.encryptAndPatch(patchedRequest, editor.getPattern(), plainText, logData);
                editor.setEncodeAlert("", Color.BLACK); // Clear encode alert
            } catch (CommandException e) {
                editor.setEncodeAlert("[-] Encrypt command failed: " + e.getMessage(), ALERT_COLOR_ERROR);
            } catch (Exception e) {
                editor.setEncodeAlert("[-] Encrypt error: " + e.toString(), ALERT_COLOR_ERROR);
            }
        }
        return patchedRequest;
    }

    public boolean isModified() {
        // If "encrypt only on modification" is disabled, always return true to trigger
        // encryption
        if (!reEncrypt.getConfig().isRepeaterEncryptOnlyOnModification()) {
            return true;
        }
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