package burp;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.GridLayout;
import java.util.Arrays;
import java.util.List;

import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;

public class TabScreen implements ITab {	
	
	private JTextField preCommand, postCommand, prePattern, postPattern;
	private static final String replaceMarker = "§§";

	public TabScreen() {
		prePattern = new JTextField();
		prePattern.setText("data\":\"");
		postPattern = new JTextField();
		postPattern.setText("\"}");
		preCommand = new JTextField();
		preCommand.setText("node /home/test/crypt.js d " + replaceMarker);
		postCommand = new JTextField();
		postCommand.setText("node /home/test/crypt.js e " + replaceMarker);
	}

	public String[] getPreCommand(String payload) {
		return getCommand(preCommand.getText(), payload);
	}

	public String[] getPostCommand(String payload) {
		return getCommand(postCommand.getText(), payload);
	}

	private String[] getCommand(String command, String payload) {
		List<String> cmd = Arrays.asList(command.split(" "));
		for (int i=0; i<cmd.size();i++) {
			if (cmd.get(i).equals(replaceMarker)) {
				cmd.set(i, payload);
				break;
			}
		}
		String[] array = new String[cmd.size()];
		cmd.toArray(array);
		return array;
	}

	public String getPrePattern() {
		return prePattern.getText();
	}

	public String getPostPattern() {
		return postPattern.getText();
	}

	@Override
	public Component getUiComponent() {
		JPanel painelBorderLayout = new JPanel(new BorderLayout());
		
        JPanel panel = new JPanel(new GridLayout(6, 2));
		
		panel.add(new JLabel("Pre Text"));
		panel.add(new JLabel("Post Text"));
		panel.add(prePattern);
		panel.add(postPattern);

		panel.add(new JLabel("Dec Command"));
		panel.add(new JLabel("Enc Command"));
		panel.add(preCommand);
		panel.add(postCommand);
				
		painelBorderLayout.add(panel, BorderLayout.NORTH);
		
		return painelBorderLayout;
	}
	
	@Override
	public String getTabCaption() {
		return "RePost";
	}
}
