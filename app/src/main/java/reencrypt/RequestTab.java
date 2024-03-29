package reencrypt;

import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;

public class RequestTab extends RequestResponseTab implements ExtensionProvidedHttpRequestEditor {
    HttpService httpService;

    public RequestTab(MontoyaApi api, ReEncrypt reEncrypt, boolean readOnly) {
        super(new RequestResponseEditor(readOnly ? api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY) : api.userInterface().createHttpRequestEditor()), reEncrypt, readOnly);
    }

    public boolean isEnabledFor(HttpRequestResponse requestResponse) {
        return super.isEnabledFor(requestResponse.request().toByteArray().getBytes(), true);
    }

    public HttpRequest getRequest() {
        return HttpRequest.httpRequest(httpService, ByteArray.byteArray(super.getBytes()));
    }

    public void setRequestResponse(HttpRequestResponse requestResponse) {
        httpService = requestResponse.request().httpService();
        super.setBytes(requestResponse.request().toByteArray().getBytes(), true);
    }


}