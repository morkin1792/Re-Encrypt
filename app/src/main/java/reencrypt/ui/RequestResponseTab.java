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
import reencrypt.OperationResult;
import reencrypt.LogData;
import reencrypt.ReEncrypt;
import reencrypt.exception.PatternException;
import reencrypt.Utils;
import reencrypt.engine.CryptoException;
import reencrypt.exception.CommandException;

import java.awt.Component;
import java.awt.BorderLayout;
import java.awt.Color;
import java.util.ArrayList;
import java.util.Optional;

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
    private HttpService cachedHttpService;
    private int renderedPatternsVersion = -1;
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
        } else {
            // Drop it: the tab below is added whenever this field is non-null, so keeping the editor
            // built by an earlier mount would leave the Print Tab on screen after it was turned off.
            printEditor = null;
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
        if (reEncrypt.getConfig().getPatternsVersion() != renderedPatternsVersion || editors.size() == 0) {
            if (cachedContentFromSetBytes != null) {
                // Decode again, not just rebuild the tab list: after a pattern is added, edited or
                // disabled, Burp does not resend the message, so the alerts would keep describing the
                // old set of patterns and the freshly created Print Tab editor would stay empty until
                // the user clicked away and back.
                setBytes(cachedHttpService, cachedMethod, cachedUrl, cachedContentFromSetBytes);
            } else {
                reloadEditors();
            }
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

    /** What the failing search actually ran against, so a stale or unexpected message is obvious. */
    private static String describeSearched(byte[] content) {
        if (content == null) {
            return "[searched: nothing - no content]";
        }
        String text = new String(content, java.nio.charset.StandardCharsets.ISO_8859_1);
        int bodyStart = text.indexOf("\r\n\r\n");
        bodyStart = bodyStart < 0 ? text.indexOf("\n\n") : bodyStart + 4;
        String body = bodyStart < 0 || bodyStart >= text.length() ? "" : text.substring(bodyStart);
        String preview = body.length() > 80 ? body.substring(0, 80) + "..." : body;
        return "[searched " + content.length + " bytes, body " + body.length() + " bytes: " + preview + "]";
    }

    public void setBytes(HttpService httpService, String method, String url, byte[] content) {
        renderedPatternsVersion = reEncrypt.getConfig().getPatternsVersion();
        reloadEditors();
        if (content == null)
            return;
        this.cachedContentFromSetBytes = content;
        this.cachedMethod = method;
        this.cachedUrl = url;
        this.cachedHttpService = httpService;
        byte[] printEditorContent = content;
        // Exact byte ranges of each decrypted region in printEditorContent (kept in sync as later
        // replacements shift earlier ones) — so we highlight what was actually decrypted, with no
        // regex false positives.
        ArrayList<int[]> highlightSpans = new ArrayList<>();
        // Which pattern claimed which byte range, so an overlap can name the pattern it collides with.
        ArrayList<int[]> claimedSpans = new ArrayList<>();
        ArrayList<String> claimedBy = new ArrayList<>();

        for (var editor : editors) {
            try {
                LogData logData = new LogData(toolType.toolName(), isRequest, cachedMethod, cachedUrl);
                OperationResult commandOutput = reEncrypt.searchAndDecrypt(editor.getPattern(), content, logData);
                String plainText = commandOutput.getOutput();

                if (commandOutput.isFailed() && !commandOutput.isCached()) {
                    // Decrypt failed and there is no cached fallback.
                    //  - Repeater: leave the editor untouched (the user may be mid-edit).
                    //  - Otherwise: clear the editor so it doesn't show stale/ciphertext content.
                    if (ToolType.REPEATER != toolType) {
                        editor.setBytes(httpService, new byte[0]);
                    }
                    // surface the failure in the alert area (throws CommandException)
                    commandOutput.getOutputCheckingExitCode();
                }
                editor.setBytes(httpService, plainText.getBytes("Windows-1252"));

                // Two patterns capturing the same bytes both try to own that value - they overwrite
                // each other when re-encrypting and on "Patch proxy". Nothing is blocked, but the user
                // is told, and told which other pattern it is.
                String collidesWith = null;
                try {
                    int[] span = ReEncrypt.searchPattern(editor.getPattern().getCaptureRegex(), content);
                    for (int i = 0; i < claimedSpans.size(); i++) {
                        int[] claimed = claimedSpans.get(i);
                        if (span[0] < claimed[1] && claimed[0] < span[1]) {
                            collidesWith = claimedBy.get(i);
                            break;
                        }
                    }
                    claimedSpans.add(span);
                    claimedBy.add(editor.getPattern().getName());
                } catch (PatternException ignored) {
                    // Cannot happen right after a successful decrypt, and is not worth reporting twice.
                }

                if (printEditor != null) {
                    if (reEncrypt.getConfig().isEscapingDoubleQuotes(isRequest)) {
                        plainText = plainText.replace("\"", "\\\"");
                    }
                    try {
                        int[] span = new int[3]; // {newStart, newEnd, oldEnd}
                        printEditorContent = reEncrypt.matchReplace(printEditorContent, editor.getPattern(), plainText,
                                span);
                        int delta = span[1] - span[2]; // newEnd - oldEnd
                        // Shift earlier decrypted regions that sit after this replacement.
                        for (int[] prev : highlightSpans) {
                            if (prev[0] >= span[2]) {
                                prev[0] += delta;
                                prev[1] += delta;
                            }
                        }
                        highlightSpans.add(new int[] { span[0], span[1] });
                    } catch (PatternException e) {
                        // Another pattern already replaced this span in the combined view. The decrypt
                        // above still succeeded, so skip it quietly - the overlap itself is reported in
                        // the alert area, which is what the user acts on.
                        api.logging().logToOutput("Print Tab: nothing left to replace for pattern \""
                                + editor.getPattern().getName() + "\" (another pattern captures the same data)");
                    }
                }
                // Set per-editor alert based on command result (never print the garbage itself)
                if (commandOutput.isCached()) {
                    if (commandOutput.isGarbage()) {
                        editor.setDecodeAlert("[*] Using CACHED output because the new decryption looked like garbage.",
                                ALERT_COLOR_WARNING);
                    } else {
                        editor.setDecodeAlert("[*] Using CACHED output because decrypt failed:\n"
                                + commandOutput.getOriginalError(), ALERT_COLOR_WARNING);
                    }
                } else if (commandOutput.isGarbage()) {
                    editor.setDecodeAlert("[*] Output looks like garbage — likely a wrong key/config; not cached.",
                            ALERT_COLOR_WARNING);
                } else if (collidesWith != null) {
                    editor.setDecodeAlert("[!] Overlap: \"" + collidesWith + "\" captures the same data as this"
                            + " pattern. Two patterns on one value overwrite each other when re-encrypting —"
                            + " keep only one of them.", ALERT_COLOR_WARNING);
                } else {
                    editor.setDecodeAlert("", Color.BLACK); // Clear decode alert
                }
            } catch (CommandException e) {
                editor.setDecodeAlert("[-] Decrypt command failed (" + editor.getPattern().getName() + "): "
                        + e.getMessage(), ALERT_COLOR_ERROR);
            } catch (Exception e) {
                // Name the pattern: with several patterns active, an error quoting only a regex leaves
                // the user guessing which one - and which direction - actually failed. On a miss, also
                // say what was searched: the message shown is not always the one the tab was built for.
                editor.setDecodeAlert("[-] Decode error (" + editor.getPattern().getName() + "): " + e.toString()
                        + "\n" + describeSearched(content), ALERT_COLOR_ERROR);
            }
        }

        setPrintEditor(httpService, printEditorContent, highlightSpans);
        if (ToolType.REPEATER == toolType && isRequest) {
            setFocusAndCaret();
        }
    }

    private void setPrintEditor(HttpService httpService, byte[] printEditorContent,
            ArrayList<int[]> highlightSpans) {
        if (printEditor != null) {
            printEditor.setBytes(httpService, printEditorContent);
            Component editorComponent = printEditor.uiComponent();
            boolean isHighlighting = reEncrypt.getConfig().isHighlightingPrintEditor(isRequest);
            if (isHighlighting && !highlightSpans.isEmpty()) {
                var color = reEncrypt.getConfig().getPrintEditorHighlightColor(isRequest);
                Utils.highlightRanges(editorComponent, highlightSpans, color);
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
            } catch (CryptoException e) {
                editor.setEncodeAlert("[-] Encrypt failed: " + e.getMessage(), ALERT_COLOR_ERROR);
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