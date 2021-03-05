package burp;

public class IntruderPayloadProcessor implements IIntruderPayloadProcessor {
    private TabScreen tabScreen;

    public IntruderPayloadProcessor(TabScreen tabScreen) {
        this.tabScreen = tabScreen;
    }

    @Override
    public String getProcessorName() {
        return "RePost";
    }

    @Override
    public byte[] processPayload(byte[] currentPayload, byte[] originalPayload, byte[] baseValue) {
        String cipherText = BurpExtender.execCommand(tabScreen.getPostCommand(new String(currentPayload)), true);
        return cipherText.getBytes();
    }
    
}
