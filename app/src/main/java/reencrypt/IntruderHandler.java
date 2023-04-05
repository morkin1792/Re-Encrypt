package reencrypt;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.intruder.PayloadData;
import burp.api.montoya.intruder.PayloadProcessingResult;
import burp.api.montoya.intruder.PayloadProcessor;

public class IntruderHandler implements PayloadProcessor {
    ReEncrypt reEncrypt;

    public IntruderHandler(ReEncrypt reEncrypt) {
        this.reEncrypt = reEncrypt;
    }

    @Override
    public String displayName() {
        return App.name;
    }

    @Override
    public PayloadProcessingResult processPayload(PayloadData payloadData) {
        String cipherText = "";
        try {
            cipherText = reEncrypt.encrypt(payloadData.currentPayload().toString());
        } catch (Exception exception) {
            cipherText = exception.getMessage();
        }

        return PayloadProcessingResult.usePayload(ByteArray.byteArray(cipherText.getBytes()));
    }
}
