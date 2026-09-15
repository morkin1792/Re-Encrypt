package reencrypt;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.responses.HttpResponse;
import reencrypt.exception.PatternException;

/**
 * HttpHandler that decrypts Intruder responses so matches are readable.
 */
public class IntruderHandler implements HttpHandler {

    private MontoyaApi api;
    private ReEncrypt reEncrypt;

    public IntruderHandler(MontoyaApi api, ReEncrypt reEncrypt) {
        this.api = api;
        this.reEncrypt = reEncrypt;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        // Intruder requests are left alone: payloads are encrypted by IntruderPayloadProcessor, which
        // the user adds explicitly as a payload-processing rule.
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        // Only process Intruder responses
        if (!responseReceived.toolSource().isFromTool(ToolType.INTRUDER)) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }

        Config config = reEncrypt.getConfig();
        if (!config.isIntruderResponseDecryptEnabled()) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }

        try {
            byte[] responseContent = responseReceived.toByteArray().getBytes();
            long originalHash = Utils.getHash(responseContent);
            String url = responseReceived.initiatingRequest().url();

            LogData logData = new LogData(ToolType.INTRUDER.toolName(), false,
                    responseReceived.initiatingRequest().method(), url);
            // Preserve existing annotations from request if present
            String existingNotes = responseReceived.annotations().notes();
            StringBuilder notes = new StringBuilder();
            if (existingNotes != null && !existingNotes.isEmpty()) {
                notes.append(existingNotes).append(", ");
            }
            notes.append("Response decrypted by " + App.name);
            responseContent = applyDecryption(responseContent, url, logData, notes);

            if (Utils.getHash(responseContent) != originalHash) {
                HttpResponse newResponse = HttpResponse.httpResponse(ByteArray.byteArray(responseContent));
                if (newResponse.hasHeader("Content-Length")) {
                    newResponse = newResponse.withUpdatedHeader("Content-Length", newResponse.body().length() + "");
                }
                return ResponseReceivedAction.continueWith(newResponse,
                        Annotations.annotations().withNotes(notes.toString()));
            }
        } catch (Exception e) {
            api.logging().raiseErrorEvent("Intruder response decryption error: " + e.getMessage());
            return ResponseReceivedAction.continueWith(responseReceived,
                    Annotations.annotations().withNotes("Re:Encrypt error: " + e.getMessage()));
        }
        return ResponseReceivedAction.continueWith(responseReceived);
    }

    /**
     * Apply decryption to response using configured response patterns.
     */
    private byte[] applyDecryption(byte[] content, String url, LogData logData, StringBuilder notes) throws Exception {
        for (var pattern : reEncrypt.getConfig().getActivePatterns(false)) {
            if (!pattern.isTarget(url, api))
                continue;
            try {
                // Search for ciphertext and decrypt
                OperationResult commandOutput = reEncrypt.searchAndDecrypt(pattern, content, logData);

                if (commandOutput.isFailed()) {
                    if (commandOutput.isCached()) {
                        notes.append(" (decryption failed, using cached output)");
                    } else {
                        commandOutput.getOutputCheckingExitCode();
                    }
                }
                // Replace ciphertext with plaintext for reading
                content = reEncrypt.matchReplace(content, pattern, commandOutput.getOutput());
            } catch (PatternException e) {
                // Pattern not found, continue to next
                continue;
            }
        }
        return content;
    }
}
