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

    public RequestResponseEditor(HttpRequestEditor httpRequestEditor){
        this.httpRequestEditor = httpRequestEditor;
        this.isResponse = false;
    }

    public RequestResponseEditor(HttpResponseEditor httpResponseEditor){
        this.httpResponseEditor = httpResponseEditor;
        this.isResponse = true;
    }
    
    public Component uiComponent() {
        return isResponse ? httpResponseEditor.uiComponent() : httpRequestEditor.uiComponent();
    }

    public boolean isModified() {
        return isResponse ? httpResponseEditor.isModified() : httpRequestEditor.isModified();
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