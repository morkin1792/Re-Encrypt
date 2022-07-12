package burp;

public class BurpExtender implements IBurpExtender, IMessageEditorTabFactory {
    public static final String name = "Re:Encrypt";
    private IBurpExtenderCallbacks callbacks;
    private TabScreen tabScreen;
    private Config config;

    public void loadConfig() {
		config = new Config();

		String configSerialized = callbacks.loadExtensionSetting("config");
		if (configSerialized != null) {
			try {
				config = (Config) Utils.parse(configSerialized);
			} catch (Exception exception) {}
		}
	}
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        loadConfig();

        callbacks.setExtensionName(name);

        callbacks.registerMessageEditorTabFactory(this);
        tabScreen = new TabScreen(callbacks, config);
        callbacks.addSuiteTab(tabScreen);

        
        callbacks.registerIntruderPayloadProcessor(new IntruderPayloadProcessor(tabScreen));

    }

    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        return new MessageEditorTab(controller, editable, tabScreen, callbacks, config);
    }

}