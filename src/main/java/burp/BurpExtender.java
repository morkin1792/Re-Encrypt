package burp;

import java.io.IOException;
import java.io.InputStream;
import java.util.Scanner;

public class BurpExtender implements IBurpExtender, IMessageEditorTabFactory {
    private IBurpExtenderCallbacks callbacks;
    private TabScreen tabScreen;
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
       
        callbacks.setExtensionName("RePost");

        callbacks.registerMessageEditorTabFactory(this);
        tabScreen = new TabScreen();
        callbacks.addSuiteTab(tabScreen);

        
        callbacks.registerIntruderPayloadProcessor(new IntruderPayloadProcessor(tabScreen));

    }

    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        return new MessageEditorTab(editable, tabScreen, callbacks);
    }

    public static String execCommand(String[] cmd, boolean removeLastLF) {
        String result = null;
        try (InputStream inputStream = Runtime.getRuntime().exec(cmd).getInputStream();
                Scanner s = new Scanner(inputStream).useDelimiter("\\A")) {
            result = s.hasNext() ? s.next() : null;
        } catch (IOException e) {
            // System.out.println("error in execCommand: " + e);
        }
        //if ends with \n removes it
        if (removeLastLF && result.charAt(result.length() - 1) == '\n')
            result = result.substring(0, result.length() - 1);
        return result;
    }
}