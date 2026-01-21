package reencrypt.ui;

import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import reencrypt.ReEncrypt;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.ToolType;

public class ResponseTab extends RequestResponseTab implements ExtensionProvidedHttpResponseEditor {

    public ResponseTab(MontoyaApi api, ReEncrypt reEncrypt, boolean readOnly, ToolType toolType) {
        super(false, api, reEncrypt, readOnly, toolType);
    }

    public boolean isEnabledFor(HttpRequestResponse requestResponse) {
        return super.isEnabledFor(requestResponse, false);
    }

    public HttpResponse getResponse() {
        return HttpResponse.httpResponse(ByteArray.byteArray(super.getBytes()));
    }

    public void setRequestResponse(HttpRequestResponse requestResponse) {
        super.setBytes(requestResponse.httpService(), requestResponse.request().method(),
                requestResponse.request().url(), requestResponse.response().toByteArray().getBytes());
    }

}