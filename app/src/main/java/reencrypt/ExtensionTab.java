package reencrypt;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.GridLayout;
import java.awt.Font;

import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

public class ExtensionTab {	
	
	private JTextField decodeCommand, encodeCommand, requestPattern, responsePattern, targetPattern;
	private JCheckBox autoPatch, saveCommands;
	private Config config;
	
	public ExtensionTab(Config config) {
		this.config = config;
		createFields();
	}

	void createFields() {
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
				config.updateFields(requestPattern.getText(), responsePattern.getText(), decodeCommand.getText(), encodeCommand.getText(), targetPattern.getText());
			}
		};
		requestPattern = createTextField(config.getRequestPattern(), saveListener);
		responsePattern = createTextField(config.getResponsePattern(), saveListener);
		decodeCommand = createTextField(config.getDecodeCommand(), saveListener);
		encodeCommand = createTextField(config.getEncodeCommand(), saveListener);
		targetPattern = createTextField(config.getTargetPattern(), saveListener);
		autoPatch = new JCheckBox("Auto reencrypt proxy requests", config.shouldPatchProxy());
		targetPattern.setEnabled(autoPatch.isSelected());
		autoPatch.addItemListener(state -> {
			boolean isSelected = ((JCheckBox) state.getSource()).isSelected();
			config.updatePatchProxy(isSelected);
			targetPattern.setEnabled(isSelected);
		});

		saveCommands = new JCheckBox("Save the decode / decrypt command used in each request", config.shouldSaveCommands());
		saveCommands.addItemListener(state -> {
			boolean isSelected = ((JCheckBox) state.getSource()).isSelected();
			config.updateSaveCommands(isSelected);
		});


	}

	JTextField createTextField(String text, DocumentListener saveListener) {
		var textField = new JTextField();
		textField.setText(text);
		textField.getDocument().addDocumentListener(saveListener);
		return textField;
	}

	public Component uiComponent() {
		JPanel painelBorderLayout = new JPanel(new BorderLayout());
        JPanel panel = new JPanel(new GridLayout(15, 2));
		Font hackFont = new Font("Hack", Font.BOLD, 18);
		JLabel jlabel = new JLabel();

		jlabel = new JLabel();
		jlabel.setFont(hackFont);
		jlabel.setText(" # Defining the part of the request to be re:encrypted");
		panel.add(jlabel);
		panel.add(new JLabel());

		panel.add(new JLabel("  Request (Regex)"));
		panel.add(new JLabel("Response (Regex)"));
		panel.add(requestPattern);
		panel.add(responsePattern);
		
		panel.add(new JLabel());
		panel.add(new JLabel());

		jlabel = new JLabel();
		jlabel.setFont(hackFont);
		jlabel.setText(" # What are the commands to process the captured data?");
		panel.add(jlabel);
		panel.add(new JLabel());

		panel.add(new JLabel(" Decode / Decrypt Command"));
		panel.add(new JLabel("Encode / Encrypt Command"));
		panel.add(decodeCommand);
		panel.add(encodeCommand);
		panel.add(saveCommands);
		panel.add(new JLabel());

		panel.add(new JLabel());
		panel.add(new JLabel());

		jlabel = new JLabel();
		jlabel.setFont(hackFont);
		jlabel.setText(" # Would you like to automatically re:encrypt requests?");
		panel.add(jlabel);
		panel.add(new JLabel(""));

		panel.add(new JLabel("  - Recommended for asymmetric encryption"));
		panel.add(new JLabel("Target URL Regex "));
		panel.add(autoPatch);
		panel.add(targetPattern);
				
		painelBorderLayout.add(panel, BorderLayout.NORTH);
		
		return painelBorderLayout;
	}
	
}
