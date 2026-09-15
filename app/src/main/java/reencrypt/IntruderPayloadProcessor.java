package reencrypt;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.intruder.PayloadData;
import burp.api.montoya.intruder.PayloadProcessingResult;
import burp.api.montoya.intruder.PayloadProcessor;

/**
 * PayloadProcessor for Intruder that encrypts each payload with one of the configured patterns,
 * chosen in the Intruder tab. The pattern supplies the encryption — custom command or built-in
 * engine — so the processor has no crypto configuration of its own.
 *
 * <p>
 * Adding it under Intruder &gt; Payloads &gt; Payload processing &gt; Invoke Burp extension is what
 * switches it on; there is no separate enable flag.
 * </p>
 */
public class IntruderPayloadProcessor implements PayloadProcessor {
    private ReEncrypt reEncrypt;
    private MontoyaApi api;

    /**
     * "No pattern selected" is a static misconfiguration, but processPayload runs once per payload —
     * reporting it every time would bury the event log under thousands of identical lines. Warn on the
     * first payload of a run and stay quiet until a pattern resolves again.
     */
    private boolean warnedNoPattern;

    public IntruderPayloadProcessor(MontoyaApi api, ReEncrypt reEncrypt) {
        this.api = api;
        this.reEncrypt = reEncrypt;
    }

    @Override
    public String displayName() {
        return App.name;
    }

    @Override
    public PayloadProcessingResult processPayload(PayloadData payloadData) {
        CapturePattern pattern = reEncrypt.getConfig().getIntruderPattern();
        if (pattern == null) {
            // Either nothing is selected, or the selected pattern was renamed/deleted since.
            if (!warnedNoPattern) {
                warnedNoPattern = true;
                api.logging().raiseErrorEvent(
                        "Intruder payload processor: no pattern selected (see Re:Encrypt > Intruder)");
            }
            return PayloadProcessingResult.usePayload(payloadData.currentPayload());
        }
        warnedNoPattern = false;

        try {
            String plainText = payloadData.currentPayload().toString();
            String cipherText = reEncrypt.encrypt(pattern, plainText);
            return PayloadProcessingResult.usePayload(ByteArray.byteArray(cipherText.getBytes()));
        } catch (Exception e) {
            api.logging().raiseErrorEvent("Intruder payload processor error: " + e.getMessage());
            return PayloadProcessingResult.usePayload(payloadData.currentPayload());
        }
    }
}
