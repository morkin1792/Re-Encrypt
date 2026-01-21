package reencrypt;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.intruder.PayloadData;
import burp.api.montoya.intruder.PayloadProcessingResult;
import burp.api.montoya.intruder.PayloadProcessor;

/**
 * PayloadProcessor for Intruder that encrypts payloads using a configurable
 * command. Enabled via "Encrypt using payload processor" checkbox in Intruder
 * settings.
 */
public class IntruderPayloadProcessor implements PayloadProcessor {
    private ReEncrypt reEncrypt;
    private MontoyaApi api;

    public IntruderPayloadProcessor(MontoyaApi api, ReEncrypt reEncrypt) {
        this.api = api;
        this.reEncrypt = reEncrypt;
    }

    @Override
    public String displayName() {
        return App.name + " Shell Command";
    }

    @Override
    public PayloadProcessingResult processPayload(PayloadData payloadData) {
        Config config = reEncrypt.getConfig();

        if (!config.isIntruderPayloadProcessorEnabled()) {
            // If not enabled, pass through unchanged
            return PayloadProcessingResult.usePayload(payloadData.currentPayload());
        }

        String encryptCommand = config.getIntruderEncryptCommand();
        if (encryptCommand == null || encryptCommand.trim().isEmpty()) {
            api.logging().raiseErrorEvent("Intruder payload processor: No encrypt command configured");
            return PayloadProcessingResult.usePayload(payloadData.currentPayload());
        }

        try {
            String plainText = payloadData.currentPayload().toString();
            String cipherText = reEncrypt.encrypt(encryptCommand, plainText);
            return PayloadProcessingResult.usePayload(ByteArray.byteArray(cipherText.getBytes()));
        } catch (Exception e) {
            api.logging().raiseErrorEvent("Intruder payload processor error: " + e.getMessage());
            return PayloadProcessingResult.usePayload(payloadData.currentPayload());
        }
    }
}
