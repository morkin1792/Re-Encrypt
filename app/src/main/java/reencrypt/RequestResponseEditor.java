package reencrypt;

import java.awt.Component;
import java.util.Optional;

import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.core.ByteArray;

public class RequestResponseEditor {
    CapturePattern pattern;
    HttpRequestEditor httpRequestEditor;
    HttpResponseEditor httpResponseEditor;
    boolean isResponse;
    int size;

    public RequestResponseEditor(HttpRequestEditor httpRequestEditor){
        this.httpRequestEditor = httpRequestEditor;
        this.isResponse = false;
        this.size = 0;
    }
    
    public RequestResponseEditor(HttpResponseEditor httpResponseEditor){
        this.httpResponseEditor = httpResponseEditor;
        this.isResponse = true;
        this.size = 0;
    }
    
    public Component uiComponent() {
        return isResponse ? httpResponseEditor.uiComponent() : httpRequestEditor.uiComponent();
    }

    public boolean isModified() {
        return isResponse ? httpResponseEditor.isModified() : httpRequestEditor.isModified();
    }

    public int caretPosition() {
        return isResponse ? httpResponseEditor.caretPosition() : httpRequestEditor.caretPosition();
    }

    public void setCaretPosition(int position) {
        System.out.println("setCaretPosition: " + position + " size: " + size);
        if (size <= 0 || position < 0 || position > size) return;
        if (isResponse) {
            httpResponseEditor.setCaretPosition(position);
        } else {
            System.out.println("setCaretPosition requestEditor: " + position);
            httpRequestEditor.setCaretPosition(position);
        }
    }

    public void setPattern(CapturePattern pattern) {
        this.pattern = pattern;
    }

    public CapturePattern getPattern() {
        return pattern;
    }

    public void setBytes(byte[] data) {
        if (isResponse) {
            httpResponseEditor.setResponse(HttpResponse.httpResponse(ByteArray.byteArray(data)));
        } else {
            httpRequestEditor.setRequest(HttpRequest.httpRequest(ByteArray.byteArray(data)));
        }
        this.size = data.length;
    }

    public byte[] getBytes() {
        if (isResponse) { 
            return httpResponseEditor.getResponse().toByteArray().getBytes();
        } else {
            return httpRequestEditor.getRequest().toByteArray().getBytes();
            // return rawEditor.getContents().getBytes();
        }
    }

    public Optional<Selection> selection() {
        return isResponse ? httpResponseEditor.selection() : httpRequestEditor.selection();
    }

    // public void setEnabled(boolean enabled) {
    //     if (isResponse) {
    //         this.httpResponseEditor.uiComponent().setEnabled(enabled);

    //     } else {
    //         this.httpRequestEditor.uiComponent().setEnabled(enabled);
    //     }
    // }
}