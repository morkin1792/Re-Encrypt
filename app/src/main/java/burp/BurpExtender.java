package burp;

import java.io.InputStream;
import java.util.Scanner;

public class BurpExtender implements IBurpExtender, IMessageEditorTabFactory {
    public static final String name = "RePost";
    private IBurpExtenderCallbacks callbacks;
    private TabScreen tabScreen;
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
       
        callbacks.setExtensionName(name);

        callbacks.registerMessageEditorTabFactory(this);
        tabScreen = new TabScreen(callbacks);
        callbacks.addSuiteTab(tabScreen);

        
        callbacks.registerIntruderPayloadProcessor(new IntruderPayloadProcessor(tabScreen));

    }

    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        return new MessageEditorTab(controller, editable, tabScreen, callbacks);
    }

    public static String execCommand(String[] command, boolean removeLastLF) throws Exception {
        String result = null;
        
        Process process = Runtime.getRuntime().exec(command);
        InputStream inputStream = process.getInputStream();
        Scanner scanner = new Scanner(inputStream).useDelimiter("\\A");
        result = scanner.hasNext() ? scanner.next() : null;
        if (result == null) {
            throw new Exception("failed running: " + String.join(" ", command));
        }
        //if ends with \n removes it
        if (removeLastLF && result.charAt(result.length() - 1) == '\n')
            result = result.substring(0, result.length() - 1);
        return result;
    }
}