package burp;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.GridLayout;
import java.awt.Font;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

public class TabScreen implements ITab {	
	
	private JTextField decodeCommand, encodeCommand, requestPattern, responsePattern;
	private Config config;
	
	public TabScreen(IBurpExtenderCallbacks callbacks, Config config) {
		this.config = config;
		CreateTextFields(callbacks);
	}

	public void CreateTextFields(IBurpExtenderCallbacks callbacks) {
		DocumentListener saveListener = new DocumentListener() {
			@Override
			public void insertUpdate(DocumentEvent e) {
				updateFieldState();
			}

			@Override
			public void removeUpdate(DocumentEvent e) {
				updateFieldState();
			}

			@Override
			public void changedUpdate(DocumentEvent e) {
				updateFieldState();
			}

			protected void updateFieldState() {
				config.decodeCommand = decodeCommand.getText();
				config.encodeCommand = encodeCommand.getText();
				config.requestPattern = requestPattern.getText();
				config.responsePattern = responsePattern.getText();
				try {
					callbacks.saveExtensionSetting("config", Utils.stringify(config));
				} catch (Exception e) {}
			}
		};
		requestPattern = CreateTextField(config.requestPattern, saveListener);
		responsePattern = CreateTextField(config.responsePattern, saveListener);
		decodeCommand = CreateTextField(config.decodeCommand, saveListener);
		encodeCommand = CreateTextField(config.encodeCommand, saveListener);
		
	}

	public JTextField CreateTextField(String text, DocumentListener saveListener) {
		var textField = new JTextField();
		textField.setText(text);
		textField.getDocument().addDocumentListener(saveListener);
		return textField;
	}

	public String getDecodeCommand() {
		return decodeCommand.getText();
	}

	public String getEncodeCommand() {
		return encodeCommand.getText();
	}

	public String getPattern(boolean isRequest) {
		return isRequest ? requestPattern.getText() : responsePattern.getText();
	}

	public boolean shouldSaveDecodeCommands() {
		return true;
	}

	@Override
	public Component getUiComponent() {
		JPanel painelBorderLayout = new JPanel(new BorderLayout());
        JPanel panel = new JPanel(new GridLayout(10, 2));
		Font hackFont = new Font("Hack", Font.BOLD, 13);
		JLabel jlabel = new JLabel();

		jlabel = new JLabel();
		jlabel.setFont(hackFont);
		jlabel.setText("  Pattern");
		panel.add(jlabel);
		panel.add(new JLabel());

		panel.add(new JLabel("  Request Regex"));
		panel.add(new JLabel("Response Regex"));
		panel.add(requestPattern);
		panel.add(responsePattern);
		
		panel.add(new JLabel());
		panel.add(new JLabel());

		jlabel = new JLabel();
		jlabel.setFont(hackFont);
		jlabel.setText("  Command");
		panel.add(jlabel);
		panel.add(new JLabel());

		panel.add(new JLabel("  Decode / Decrypt Command"));
		panel.add(new JLabel("Encode / Encrypt Command"));
		panel.add(decodeCommand);
		panel.add(encodeCommand);
				
		painelBorderLayout.add(panel, BorderLayout.NORTH);
		
		return painelBorderLayout;
	}
	
	@Override
	public String getTabCaption() {
		return BurpExtender.name;
	}
}
