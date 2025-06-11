package reencrypt;

import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;

public class ResponseTab extends RequestResponseTab implements ExtensionProvidedHttpResponseEditor {

    public ResponseTab(MontoyaApi api, ReEncrypt reEncrypt, boolean readOnly) {
        super(false, api, reEncrypt, readOnly);
    }

    public boolean isEnabledFor(HttpRequestResponse requestResponse) {
        return super.isEnabledFor(requestResponse.response().toByteArray().getBytes());
    }

    public HttpResponse getResponse() {
        return HttpResponse.httpResponse(ByteArray.byteArray(super.getBytes()));
    }

    public void setRequestResponse(HttpRequestResponse requestResponse) {
        super.setBytes(requestResponse.response().toByteArray().getBytes());
    }


}