package reencrypt.ui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Font;
import java.util.Optional;

import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.ScrollPaneConstants;

import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import reencrypt.CapturePattern;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.core.ByteArray;

public class RequestResponseEditor {
    CapturePattern pattern;
    HttpRequestEditor httpRequestEditor;
    HttpResponseEditor httpResponseEditor;
    boolean isResponse;
    int size;

    // Alert state
    private String decodeAlertMessage = "";
    private Color decodeAlertColor = Color.BLACK;
    private String encodeAlertMessage = "";
    private Color encodeAlertColor = Color.BLACK;

    // Per-editor alert components
    private final JPanel wrapperPanel;
    private final JTextArea alertArea;
    private final JScrollPane alertScrollPane;
    private static final Font ALERT_FONT = new Font("Hack", Font.BOLD, 13);

    public RequestResponseEditor(HttpRequestEditor httpRequestEditor) {
        this.httpRequestEditor = httpRequestEditor;
        this.isResponse = false;
        this.size = 0;
        this.alertArea = createAlertArea();
        this.alertScrollPane = createAlertScrollPane(alertArea);
        this.wrapperPanel = createWrapperPanel(httpRequestEditor.uiComponent());
    }

    public RequestResponseEditor(HttpResponseEditor httpResponseEditor) {
        this.httpResponseEditor = httpResponseEditor;
        this.isResponse = true;
        this.size = 0;
        this.alertArea = createAlertArea();
        this.alertScrollPane = createAlertScrollPane(alertArea);
        this.wrapperPanel = createWrapperPanel(httpResponseEditor.uiComponent());
    }

    private JTextArea createAlertArea() {
        JTextArea area = new JTextArea(0, 0);
        area.setLineWrap(true);
        area.setFont(ALERT_FONT);
        area.setFocusable(false);
        area.setEditable(false);
        area.setVisible(false);
        return area;
    }

    private JScrollPane createAlertScrollPane(JTextArea alertArea) {
        JScrollPane scrollPane = new JScrollPane(alertArea);
        scrollPane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED);
        scrollPane.setVisible(false);
        return scrollPane;
    }

    private JPanel createWrapperPanel(Component editorComponent) {
        JPanel panel = new JPanel(new BorderLayout());
        panel.add(alertScrollPane, BorderLayout.NORTH);
        panel.add(editorComponent, BorderLayout.CENTER);
        return panel;
    }

    /**
     * Update the alert display based on priority: 1. Encode alert (if present) 2.
     * Decode alert (otherwise)
     */
    private void updateAlertDisplay() {
        String message;
        Color color;

        if (!encodeAlertMessage.isEmpty()) {
            message = encodeAlertMessage;
            color = encodeAlertColor;
        } else {
            message = decodeAlertMessage;
            color = decodeAlertColor;
        }

        alertArea.setText(message);
        alertArea.setForeground(color);
        boolean visible = message != null && !message.trim().isEmpty();
        alertArea.setVisible(visible);
        alertScrollPane.setVisible(visible);
    }

    public void setDecodeAlert(String message, Color color) {
        this.decodeAlertMessage = message == null ? "" : message;
        this.decodeAlertColor = color;
        updateAlertDisplay();
    }

    public void setEncodeAlert(String message, Color color) {
        this.encodeAlertMessage = message == null ? "" : message;
        this.encodeAlertColor = color;
        updateAlertDisplay();
    }

    /**
     * Clear all alerts
     */
    public void clearAlerts() {
        this.decodeAlertMessage = "";
        this.encodeAlertMessage = "";
        updateAlertDisplay();
    }

    public Component uiComponent() {
        return wrapperPanel;
    }

    public Component editorComponent() {
        return isResponse ? httpResponseEditor.uiComponent() : httpRequestEditor.uiComponent();
    }

    public boolean isModified() {
        return isResponse ? httpResponseEditor.isModified() : httpRequestEditor.isModified();
    }

    public int caretPosition() {
        return isResponse ? httpResponseEditor.caretPosition() : httpRequestEditor.caretPosition();
    }

    public void setCaretPosition(int position) {
        if (size <= 0 || position < 0)
            return;
        if (position > size) {
            position = size;
        }
        if (isResponse) {
            httpResponseEditor.setCaretPosition(position);
        } else {
            httpRequestEditor.setCaretPosition(position);
        }
    }

    public void setPattern(CapturePattern pattern) {
        this.pattern = pattern;
    }

    public CapturePattern getPattern() {
        return pattern;
    }

    public void setBytes(HttpService httpService, byte[] data) {
        if (isResponse) {
            httpResponseEditor.setResponse(HttpResponse.httpResponse(ByteArray.byteArray(data)));
        } else {
            httpRequestEditor.setRequest(HttpRequest.httpRequest(httpService, ByteArray.byteArray(data)));
        }
        this.size = data.length;
    }

    public byte[] getBytes() {
        if (isResponse) {
            return httpResponseEditor.getResponse().toByteArray().getBytes();
        } else {
            return httpRequestEditor.getRequest().toByteArray().getBytes();
        }
    }

    public Optional<Selection> selection() {
        return isResponse ? httpResponseEditor.selection() : httpRequestEditor.selection();
    }
}