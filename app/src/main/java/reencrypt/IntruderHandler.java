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
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import reencrypt.exception.PatternException;

/**
 * HttpHandler for Intruder-specific encryption/decryption.
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
        // Only process Intruder requests
        if (!requestToBeSent.toolSource().isFromTool(ToolType.INTRUDER)) {
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }

        Config config = reEncrypt.getConfig();
        if (!config.isIntruderRequestEncryptEnabled()) {
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }

        try {
            byte[] requestContent = requestToBeSent.toByteArray().getBytes();
            long originalHash = Utils.getHash(requestContent);
            String url = requestToBeSent.url();

            LogData logData = new LogData(ToolType.INTRUDER.toolName(), true, requestToBeSent.method(), url);

            // Preserve existing annotations from request if present
            String existingNotes = requestToBeSent.annotations().notes();
            StringBuilder notes = new StringBuilder();
            if (existingNotes != null && !existingNotes.isEmpty()) {
                notes.append(existingNotes).append(", ");
            }
            notes.append("Request encrypted by " + App.name);
            requestContent = applyEncryption(requestContent, url, logData, notes);

            if (Utils.getHash(requestContent) != originalHash) {
                HttpRequest newRequest = HttpRequest.httpRequest(requestToBeSent.httpService(),
                        ByteArray.byteArray(requestContent));
                if (newRequest.hasHeader("Content-Length")) {
                    newRequest = newRequest.withUpdatedHeader("Content-Length", newRequest.body().length() + "");
                }
                return RequestToBeSentAction.continueWith(newRequest,
                        Annotations.annotations().withNotes(notes.toString()));
            }
        } catch (Exception e) {
            api.logging().raiseErrorEvent("Intruder request encryption error: " + e.getMessage());
            return RequestToBeSentAction.continueWith(requestToBeSent,
                    Annotations.annotations().withNotes("Re:Encrypt error: " + e.getMessage()));
        }
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
     * Apply encryption to request using configured request patterns.
     */
    private byte[] applyEncryption(byte[] content, String url, LogData logData, StringBuilder notes) throws Exception {
        for (var pattern : reEncrypt.getConfig().getActivePatterns(true)) {
            if (!pattern.isTarget(url))
                continue;
            try {
                // Intruder sends plaintext requests.
                // 1. Find the match indexes using the pattern regex
                int[] indexes = ReEncrypt.searchPattern(pattern.getPatternRegex(), content);

                // 2. Extract the plaintext value
                String contentStr = new String(content);
                String plainText = contentStr.substring(indexes[0], indexes[1]);

                // 3. Encrypt the plaintext and patch the request
                content = reEncrypt.encryptAndPatch(content, pattern, plainText, logData);
            } catch (PatternException e) {
                // Pattern not found, continue to next
                continue;
            }
        }
        return content;
    }

    /**
     * Apply decryption to response using configured response patterns.
     */
    private byte[] applyDecryption(byte[] content, String url, LogData logData, StringBuilder notes) throws Exception {
        for (var pattern : reEncrypt.getConfig().getActivePatterns(false)) {
            if (!pattern.isTarget(url))
                continue;
            try {
                // Search for ciphertext and decrypt
                CommandOutput commandOutput = reEncrypt.searchAndDecrypt(pattern, content, logData);

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
