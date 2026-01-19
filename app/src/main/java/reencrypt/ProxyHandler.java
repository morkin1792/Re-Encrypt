package reencrypt;

import burp.api.montoya.MontoyaApi;
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
import reencrypt.exception.PatternException;

public class ProxyHandler implements ProxyRequestHandler, ProxyResponseHandler {

    ReEncrypt reEncrypt;
    MontoyaApi api;

    public ProxyHandler(MontoyaApi api, ReEncrypt reEncrypt) {
        this.api = api;
        this.reEncrypt = reEncrypt;
    }

    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest requestReceived) {
        return ProxyRequestReceivedAction.continueWith(requestReceived);
    }

    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest requestToBeSent) {
        try {
            byte[] requestContent = requestToBeSent.toByteArray().getBytes();
            long originalHash = Utils.getHash(requestContent);
            String url = requestToBeSent.url();

            LogData logData = new LogData(ToolType.PROXY.toolName(), true, requestToBeSent.method(), url);
            StringBuilder notes = new StringBuilder("modified by " + App.name);
            requestContent = applyPatch(requestContent, url, true, logData, notes);

            if (Utils.getHash(requestContent) != originalHash) {
                HttpRequest newRequest = HttpRequest.httpRequest(requestToBeSent.httpService(),
                        ByteArray.byteArray(requestContent));
                if (newRequest.hasHeader("Content-Length")) {
                    newRequest = newRequest.withUpdatedHeader("Content-Length", newRequest.body().length() + "");
                }
                return ProxyRequestToBeSentAction.continueWith(newRequest,
                        Annotations.annotations().withNotes(notes.toString()));
            }
        } catch (Exception e) {
            api.logging().raiseErrorEvent("Error patching proxy request: " + e.getMessage());
            return ProxyRequestToBeSentAction.continueWith(requestToBeSent,
                    Annotations.annotations().withNotes("Re:Encrypt error patching request: " + e.getMessage()));
        }
        return ProxyRequestToBeSentAction.continueWith(requestToBeSent);
    }

    public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse responseReceived) {
        return ProxyResponseReceivedAction.continueWith(responseReceived);
    }

    public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse responseToBeSent) {
        try {
            byte[] responseContent = responseToBeSent.toByteArray().getBytes();
            long originalHash = Utils.getHash(responseContent);
            String url = responseToBeSent.request().url();

            LogData logData = new LogData(ToolType.PROXY.toolName(), false, responseToBeSent.request().method(), url);
            StringBuilder notes = new StringBuilder("modified by " + App.name);
            responseContent = applyPatch(responseContent, url, false, logData, notes);

            if (Utils.getHash(responseContent) != originalHash) {
                HttpResponse newResponse = HttpResponse.httpResponse(ByteArray.byteArray(responseContent));
                if (newResponse.hasHeader("Content-Length")) {
                    newResponse = newResponse.withUpdatedHeader("Content-Length", newResponse.body().length() + "");
                }
                return ProxyResponseToBeSentAction.continueWith(newResponse,
                        Annotations.annotations().withNotes(notes.toString()));
            }
        } catch (Exception e) {
            api.logging().raiseErrorEvent("Error patching proxy response: " + e.getMessage());
            return ProxyResponseToBeSentAction.continueWith(responseToBeSent,
                    Annotations.annotations().withNotes("Re:Encrypt error patching response: " + e.getMessage()));
        }
        return ProxyResponseToBeSentAction.continueWith(responseToBeSent);
    }

    byte[] applyPatch(byte[] content, String url, boolean isRequest, LogData logData, StringBuilder notes)
            throws Exception {
        for (var pattern : reEncrypt.getConfig().getActivePatterns(isRequest)) {
            if (!pattern.shouldPatchProxy(url))
                continue;
            try {
                CommandOutput commandOutput = reEncrypt.searchAndDecrypt(pattern, content, logData);

                if (commandOutput.isFailed()) {
                    if (commandOutput.isCached()) {
                        notes.append(" (decryption failed, using cached output)");
                    } else {
                        // if the command failed and there is no cached output, throw an exception
                        commandOutput.getOutputCheckingExitCode();
                    }
                }
                content = reEncrypt.encryptAndPatch(content, pattern, commandOutput.getOutput(), logData);

            } catch (PatternException e) {
                // Pattern not found, ignore
                continue;
            }
            // Other exceptions (CommandException, IOException) propagate
        }
        return content;
    }
}