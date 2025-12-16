package reencrypt;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;

public class ProxyHandler implements ProxyRequestHandler, ProxyResponseHandler {

    ReEncrypt reEncrypt;

    public ProxyHandler(ReEncrypt reEncrypt) {
        this.reEncrypt = reEncrypt;
    }

    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest requestReceived) {
        return ProxyRequestReceivedAction.continueWith(requestReceived);
    }

    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest requestToBeSent) {
        try {
            byte[] requestContent = requestToBeSent.toByteArray().getBytes();
            String url = requestToBeSent.url();
            boolean modified[] = new boolean[] { false };
            LogData logData = new LogData(ToolType.PROXY.toolName(), true, requestToBeSent.method(), url);
            requestContent = applyPatch(requestContent, url, true, logData, modified);
            if (modified[0]) {
                HttpRequest newRequest = HttpRequest.httpRequest(requestToBeSent.httpService(),
                        ByteArray.byteArray(requestContent));
                if (newRequest.hasHeader("Content-Length")) {
                    newRequest = newRequest.withUpdatedHeader("Content-Length", newRequest.body().length() + "");
                }
                return ProxyRequestToBeSentAction.continueWith(newRequest,
                        Annotations.annotations().withNotes("modified by " + App.name));
            }
        } catch (Exception e) {
            System.out.println("exception in handleRequest: " + e);
        }
        return ProxyRequestToBeSentAction.continueWith(requestToBeSent);
    }

    public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse responseReceived) {
        return ProxyResponseReceivedAction.continueWith(responseReceived);
    }

    public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse responseToBeSent) {
        try {
            byte[] responseContent = responseToBeSent.toByteArray().getBytes();
            String url = responseToBeSent.request().url();
            boolean modified[] = new boolean[] { false };

            LogData logData = new LogData(ToolType.PROXY.toolName(), false, responseToBeSent.request().method(), url);
            responseContent = applyPatch(responseContent, url, false, logData, modified);
            if (modified[0]) {
                HttpResponse newResponse = HttpResponse.httpResponse(ByteArray.byteArray(responseContent));
                if (newResponse.hasHeader("Content-Length")) {
                    newResponse = newResponse.withUpdatedHeader("Content-Length", newResponse.body().length() + "");
                }
                return ProxyResponseToBeSentAction.continueWith(newResponse,
                        Annotations.annotations().withNotes("modified by " + App.name));
            }
        } catch (Exception e) {
            System.out.println("exception in handleResponse: " + e);
        }
        return ProxyResponseToBeSentAction.continueWith(responseToBeSent);
    }

    byte[] applyPatch(byte[] content, String url, boolean isRequest, LogData logData, boolean[] refModified) {
        for (var pattern : reEncrypt.getConfig().getActivePatterns(isRequest)) {
            if (!pattern.shouldPatchProxy(url))
                continue;
            try {

                String plainText = reEncrypt.searchAndDecrypt(pattern, content, logData);
                content = reEncrypt.encryptAndPatch(content, pattern, plainText, logData);
                refModified[0] = true;
            } catch (Exception e) {
                System.out.println("Exception processing pattern " + pattern.getName() + " : " + e);
            }
        }
        return content;
    }

}