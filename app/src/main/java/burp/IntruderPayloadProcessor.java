package burp;

public class IntruderPayloadProcessor implements IIntruderPayloadProcessor {
    private TabScreen tabScreen;

    public IntruderPayloadProcessor(TabScreen tabScreen) {
        this.tabScreen = tabScreen;
    }

    @Override
    public String getProcessorName() {
        return BurpExtender.name;
    }

    @Override
    public byte[] processPayload(byte[] currentPayload, byte[] originalPayload, byte[] baseValue) {
        String cipherText = "";
        try {
            String[] command = Utils.patchCommand(tabScreen.getEncodeCommand(), new String(currentPayload));
            cipherText = Utils.executeCommand(command, true);
        } catch (Exception e) {
            cipherText = e.getMessage();
        }
        return cipherText.getBytes();
    }
    
}
