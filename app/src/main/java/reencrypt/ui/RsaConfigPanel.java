package reencrypt.ui;

import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.util.HashMap;
import java.util.Map;

import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.border.EmptyBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

/**
 * Configuration panel for the RSA engine.
 * Public key for encryption, private key for decryption.
 * Text source = PEM only. File source = PEM or DER.
 */
public class RsaConfigPanel extends EngineConfigPanel {

    private static final String PUB_PEM_PLACEHOLDER = "-----BEGIN PUBLIC KEY-----";
    private static final String PRIV_PEM_PLACEHOLDER = "-----BEGIN RSA PRIVATE KEY-----";
    private static final String FILE_PATH_PLACEHOLDER = "/path/to/key.pem";
    private static final String CMD_PLACEHOLDER = "Command, e.g. cat ~/key.txt";
    private static final String CMD_NOTE = "Runs every time, on each decrypt/encrypt operation";

    private Runnable onChangeListener;

    // Public key
    private JComboBox<String> publicKeySourceCombo;
    private JTextArea publicKeyTextArea;
    private JPanel publicKeyFilePanel;
    private javax.swing.JTextField publicKeyFileField;
    private javax.swing.JTextField publicKeyCommandField;
    private JComboBox<String> publicKeyFileFormatCombo;
    private JComboBox<String> publicKeyCommandFormatCombo;
    private JCheckBox publicKeyReloadCheckbox;

    // Private key
    private JComboBox<String> privateKeySourceCombo;
    private JTextArea privateKeyTextArea;
    private JPanel privateKeyFilePanel;
    private javax.swing.JTextField privateKeyFileField;
    private javax.swing.JTextField privateKeyCommandField;
    private JComboBox<String> privateKeyFileFormatCombo;
    private JComboBox<String> privateKeyCommandFormatCombo;
    private JCheckBox privateKeyReloadCheckbox;

    // Scheme
    private JComboBox<String> schemeCombo;
    private JPanel digestPanel;
    private JComboBox<String> digestCombo;

    // Encoding
    private JComboBox<String> encodingCombo;
    private JCheckBox mirrorCheckbox;
    private JPanel splitEncodingPanel;
    private JComboBox<String> inputEncodingCombo, outputEncodingCombo;

    private JLabel errorLabel;

    public RsaConfigPanel(Map<String, String> existingParams) {
        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));

        Map<String, String> params = existingParams != null ? existingParams : new HashMap<>();

        // === Public Key ===
        createKeySection("Public Key", "publicKey", params, true);

        add(Box.createVerticalStrut(5));

        // === Private Key ===
        createKeySection("Private Key", "privateKey", params, false);

        add(Box.createVerticalStrut(8));

        // === Encryption Scheme ===
        schemeCombo = new JComboBox<>(new String[] { "RSAES-PKCS1-V1_5", "RSA-OAEP", "Raw" });
        String savedScheme = params.getOrDefault("encryptionScheme", "PKCS1");
        switch (savedScheme) {
        case "OAEP": schemeCombo.setSelectedItem("RSA-OAEP"); break;
        case "Raw": schemeCombo.setSelectedItem("Raw"); break;
        default: schemeCombo.setSelectedItem("RSAES-PKCS1-V1_5"); break;
        }
        addLabelAndCombo("Encryption Scheme", schemeCombo);

        // Message Digest (only for OAEP)
        digestPanel = new JPanel();
        digestPanel.setLayout(new BoxLayout(digestPanel, BoxLayout.X_AXIS));
        digestPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        digestCombo = new JComboBox<>(new String[] { "SHA-1", "SHA-256", "SHA-384", "SHA-512" });
        digestCombo.setSelectedItem(params.getOrDefault("oaepDigest", "SHA-256"));
        digestCombo.setMaximumSize(new Dimension(200, 30));
        digestPanel.add(new JLabel("Message Digest   "));
        digestPanel.add(digestCombo);
        add(digestPanel);

        add(Box.createVerticalStrut(8));

        // === Encoding ===
        JPanel encodingRow = new JPanel();
        encodingRow.setLayout(new BoxLayout(encodingRow, BoxLayout.X_AXIS));
        encodingRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        encodingCombo = new JComboBox<>(new String[] { "Base64", "Hex", "Raw" });
        encodingCombo.setSelectedItem(params.getOrDefault("encoding", "Base64"));
        encodingCombo.setMaximumSize(new Dimension(200, 30));
        encodingRow.add(new JLabel("Input/Output Encoding  "));
        encodingRow.add(encodingCombo);
        add(encodingRow);

        mirrorCheckbox = new JCheckBox("Mirror encoding for decrypt and encrypt",
                "true".equals(params.getOrDefault("mirrorEncoding", "true")));
        mirrorCheckbox.setAlignmentX(Component.LEFT_ALIGNMENT);
        add(mirrorCheckbox);

        splitEncodingPanel = new JPanel();
        splitEncodingPanel.setLayout(new BoxLayout(splitEncodingPanel, BoxLayout.Y_AXIS));
        splitEncodingPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        JPanel inputEncRow = new JPanel();
        inputEncRow.setLayout(new BoxLayout(inputEncRow, BoxLayout.X_AXIS));
        inputEncRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        inputEncodingCombo = new JComboBox<>(new String[] { "Base64", "Hex", "Raw" });
        inputEncodingCombo.setSelectedItem(params.getOrDefault("inputEncoding", "Base64"));
        inputEncodingCombo.setMaximumSize(new Dimension(200, 30));
        inputEncRow.add(new JLabel("Input Encoding   "));
        inputEncRow.add(inputEncodingCombo);
        splitEncodingPanel.add(inputEncRow);

        JPanel outputEncRow = new JPanel();
        outputEncRow.setLayout(new BoxLayout(outputEncRow, BoxLayout.X_AXIS));
        outputEncRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        outputEncodingCombo = new JComboBox<>(new String[] { "Base64", "Hex", "Raw" });
        outputEncodingCombo.setSelectedItem(params.getOrDefault("outputEncoding", "Base64"));
        outputEncodingCombo.setMaximumSize(new Dimension(200, 30));
        outputEncRow.add(new JLabel("Output Encoding  "));
        outputEncRow.add(outputEncodingCombo);
        splitEncodingPanel.add(outputEncRow);

        add(splitEncodingPanel);

        // === Error label ===
        add(Box.createVerticalStrut(8));
        errorLabel = new JLabel(" ");
        errorLabel.setForeground(new Color(200, 50, 50));
        errorLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        add(errorLabel);

        // === Wire listeners ===
        schemeCombo.addActionListener(e -> updateVisibility());
        mirrorCheckbox.addActionListener(e -> updateVisibility());

        DocumentListener docListener = new DocumentListener() {
            public void changedUpdate(DocumentEvent e) { fireChange(); }
            public void removeUpdate(DocumentEvent e) { fireChange(); }
            public void insertUpdate(DocumentEvent e) { fireChange(); }
        };
        publicKeyTextArea.getDocument().addDocumentListener(docListener);
        privateKeyTextArea.getDocument().addDocumentListener(docListener);
        publicKeyFileField.getDocument().addDocumentListener(docListener);
        privateKeyFileField.getDocument().addDocumentListener(docListener);
        publicKeyCommandField.getDocument().addDocumentListener(docListener);
        privateKeyCommandField.getDocument().addDocumentListener(docListener);

        schemeCombo.addActionListener(e -> fireChange());
        digestCombo.addActionListener(e -> fireChange());
        encodingCombo.addActionListener(e -> fireChange());
        publicKeyCommandFormatCombo.addActionListener(e -> fireChange());
        privateKeyCommandFormatCombo.addActionListener(e -> fireChange());

        updateVisibility();
    }

    private void createKeySection(String label, String prefix, Map<String, String> params, boolean isPublic) {
        JPanel headerRow = new JPanel();
        headerRow.setLayout(new BoxLayout(headerRow, BoxLayout.X_AXIS));
        headerRow.setAlignmentX(Component.LEFT_ALIGNMENT);

        String savedSourceVal = params.getOrDefault(prefix + "Source", "text");
        JComboBox<String> sourceCombo = new JComboBox<>(new String[] { "Text", "File", "Command" });
        sourceCombo.setSelectedItem(sourceToDisplay(savedSourceVal));
        sourceCombo.setMaximumSize(new Dimension(110, 30));

        headerRow.add(new JLabel(label + "  "));
        headerRow.add(sourceCombo);
        add(headerRow);

        // Text area (for PEM pasting)
        JTextArea textArea = new JTextArea(3, 40);
        textArea.setLineWrap(true);
        JScrollPane scrollPane = new JScrollPane(textArea);
        scrollPane.setAlignmentX(Component.LEFT_ALIGNMENT);
        scrollPane.setMaximumSize(new Dimension(Integer.MAX_VALUE, 80));

        // Text area uses the text value only if source was text
        String savedSource = params.getOrDefault(prefix + "Source", "text");
        String existingValue = params.getOrDefault(prefix, "");
        // Only populate textarea with existing value if source was text and it's not a file path
        String textValue = "text".equals(savedSource) ? existingValue : "";

        // Set placeholder for empty text areas
        String pemPlaceholder = isPublic ? PUB_PEM_PLACEHOLDER : PRIV_PEM_PLACEHOLDER;
        if (textValue.isEmpty()) {
            textArea.setForeground(Color.GRAY);
            textArea.setText(pemPlaceholder);
            textArea.addFocusListener(new java.awt.event.FocusAdapter() {
                @Override
                public void focusGained(java.awt.event.FocusEvent e) {
                    if (textArea.getText().equals(pemPlaceholder)) {
                        textArea.setText("");
                        textArea.setForeground(null);
                    }
                }
                @Override
                public void focusLost(java.awt.event.FocusEvent e) {
                    if (textArea.getText().isEmpty()) {
                        textArea.setForeground(Color.GRAY);
                        textArea.setText(pemPlaceholder);
                    }
                }
            });
        } else {
            textArea.setText(textValue);
        }
        add(scrollPane);

        // File panel
        JPanel filePanel = new JPanel();
        filePanel.setLayout(new BoxLayout(filePanel, BoxLayout.X_AXIS));
        filePanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        JComboBox<String> fileFormatCombo = new JComboBox<>(new String[] { "PEM", "DER" });
        fileFormatCombo.setSelectedItem(params.getOrDefault(prefix + "FileFormat", "PEM"));
        fileFormatCombo.setMaximumSize(new Dimension(80, 30));

        // File field uses the value only if source was file
        String filePath = "file".equals(savedSource) ? existingValue : "";
        javax.swing.JTextField fileField = new javax.swing.JTextField();
        fileField.setMaximumSize(new Dimension(Integer.MAX_VALUE, 30));
        if (filePath.isEmpty()) {
            // Set placeholder
            fileField.setForeground(Color.GRAY);
            fileField.setText(FILE_PATH_PLACEHOLDER);
            fileField.addFocusListener(new java.awt.event.FocusAdapter() {
                @Override
                public void focusGained(java.awt.event.FocusEvent e) {
                    if (fileField.getText().equals(FILE_PATH_PLACEHOLDER)) {
                        fileField.setText("");
                        fileField.setForeground(null);
                    }
                }
                @Override
                public void focusLost(java.awt.event.FocusEvent e) {
                    if (fileField.getText().isEmpty()) {
                        fileField.setForeground(Color.GRAY);
                        fileField.setText(FILE_PATH_PLACEHOLDER);
                    }
                }
            });
        } else {
            fileField.setText(filePath);
        }

        javax.swing.JButton browseBtn = new javax.swing.JButton("...");
        browseBtn.setMaximumSize(new Dimension(40, 30));
        browseBtn.setToolTipText("Browse for file");
        browseBtn.addActionListener(e -> {
            JFileChooser fc = new JFileChooser();
            if (fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
                fileField.setText(fc.getSelectedFile().getAbsolutePath());
                fileField.setForeground(null);
            }
        });

        filePanel.add(fileFormatCombo);
        filePanel.add(Box.createHorizontalStrut(5));
        filePanel.add(fileField);
        filePanel.add(browseBtn);
        add(filePanel);

        JCheckBox reloadCheckbox = new JCheckBox("Reload file on every operation",
                "true".equals(params.getOrDefault(prefix + "ReloadFile", "true")));
        reloadCheckbox.setAlignmentX(Component.LEFT_ALIGNMENT);
        reloadCheckbox.setBorder(new EmptyBorder(0, 20, 0, 0));
        add(reloadCheckbox);

        // Command panel: a PEM/DER format combo + single-line command field
        // (accepts {DATA}/{FILE}) + note
        JPanel commandPanel = new JPanel();
        commandPanel.setLayout(new BoxLayout(commandPanel, BoxLayout.Y_AXIS));
        commandPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        JPanel commandRow = new JPanel();
        commandRow.setLayout(new BoxLayout(commandRow, BoxLayout.X_AXIS));
        commandRow.setAlignmentX(Component.LEFT_ALIGNMENT);

        JComboBox<String> commandFormatCombo = new JComboBox<>(new String[] { "PEM", "DER" });
        commandFormatCombo.setSelectedItem(params.getOrDefault(prefix + "FileFormat", "PEM"));
        commandFormatCombo.setMaximumSize(new Dimension(80, 30));

        String commandValue = "command".equals(savedSource) ? existingValue : "";
        javax.swing.JTextField commandField = new javax.swing.JTextField();
        commandField.setMaximumSize(new Dimension(Integer.MAX_VALUE, 30));
        commandField.setAlignmentX(Component.LEFT_ALIGNMENT);
        if (commandValue.isEmpty()) {
            applyPlaceholder(commandField, CMD_PLACEHOLDER);
        } else {
            commandField.setText(commandValue);
        }
        commandRow.add(commandFormatCombo);
        commandRow.add(Box.createHorizontalStrut(5));
        commandRow.add(commandField);
        commandPanel.add(commandRow);

        JLabel commandNote = new JLabel(CMD_NOTE);
        commandNote.setForeground(Color.GRAY);
        commandNote.setAlignmentX(Component.LEFT_ALIGNMENT);
        commandPanel.add(commandNote);
        add(commandPanel);

        // Store references
        if (isPublic) {
            publicKeySourceCombo = sourceCombo;
            publicKeyTextArea = textArea;
            publicKeyFilePanel = filePanel;
            publicKeyFileField = fileField;
            publicKeyCommandField = commandField;
            publicKeyFileFormatCombo = fileFormatCombo;
            publicKeyCommandFormatCombo = commandFormatCombo;
            publicKeyReloadCheckbox = reloadCheckbox;
        } else {
            privateKeySourceCombo = sourceCombo;
            privateKeyTextArea = textArea;
            privateKeyFilePanel = filePanel;
            privateKeyFileField = fileField;
            privateKeyCommandField = commandField;
            privateKeyFileFormatCombo = fileFormatCombo;
            privateKeyCommandFormatCombo = commandFormatCombo;
            privateKeyReloadCheckbox = reloadCheckbox;
        }

        // Source toggle listeners
        sourceCombo.addActionListener(e -> {
            applySourceVisibility(sourceCombo, scrollPane, filePanel, reloadCheckbox, commandPanel);
            revalidate();
            repaint();
            java.awt.Window window = javax.swing.SwingUtilities.getWindowAncestor(this);
            if (window != null) {
                window.pack();
            }
            fireChange();
        });

        // Initial state
        applySourceVisibility(sourceCombo, scrollPane, filePanel, reloadCheckbox, commandPanel);
    }

    private void applySourceVisibility(JComboBox<String> sourceCombo, JScrollPane scrollPane, JPanel filePanel,
            JCheckBox reloadCheckbox, JPanel commandPanel) {
        String sel = (String) sourceCombo.getSelectedItem();
        boolean isFile = "File".equals(sel);
        boolean isCommand = "Command".equals(sel);
        scrollPane.setVisible(!isFile && !isCommand);
        filePanel.setVisible(isFile);
        reloadCheckbox.setVisible(isFile);
        commandPanel.setVisible(isCommand);
    }

    /** Add a gray placeholder to a text field that clears on focus. */
    private void applyPlaceholder(javax.swing.JTextField field, String placeholder) {
        field.setForeground(Color.GRAY);
        field.setText(placeholder);
        field.addFocusListener(new java.awt.event.FocusAdapter() {
            @Override
            public void focusGained(java.awt.event.FocusEvent e) {
                if (field.getText().equals(placeholder)) {
                    field.setText("");
                    field.setForeground(null);
                }
            }

            @Override
            public void focusLost(java.awt.event.FocusEvent e) {
                if (field.getText().isEmpty()) {
                    field.setForeground(Color.GRAY);
                    field.setText(placeholder);
                }
            }
        });
    }

    private String sourceToDisplay(String source) {
        if ("file".equals(source)) return "File";
        if ("command".equals(source)) return "Command";
        return "Text";
    }

    private String displayToSource(String display) {
        if ("File".equals(display)) return "file";
        if ("Command".equals(display)) return "command";
        return "text";
    }

    private void updateVisibility() {
        boolean isOaep = "RSA-OAEP".equals(schemeCombo.getSelectedItem());
        digestPanel.setVisible(isOaep);

        boolean isMirror = mirrorCheckbox.isSelected();
        encodingCombo.getParent().setVisible(isMirror);
        splitEncodingPanel.setVisible(!isMirror);

        revalidate();
        repaint();

        // Resize parent dialog to fit content
        java.awt.Window window = javax.swing.SwingUtilities.getWindowAncestor(this);
        if (window != null) {
            window.pack();
        }

        fireChange();
    }

    private void fireChange() {
        if (onChangeListener != null) {
            onChangeListener.run();
        }
    }

    @Override
    public void setOnChangeListener(Runnable listener) {
        this.onChangeListener = listener;
    }

    @Override
    public HashMap<String, String> getParams() {
        HashMap<String, String> params = new HashMap<>();

        // Public key
        String pubSourceDisplay = (String) publicKeySourceCombo.getSelectedItem();
        params.put("publicKeySource", displayToSource(pubSourceDisplay));
        params.put("publicKey", keyValueFor(pubSourceDisplay, publicKeyFileField, publicKeyCommandField,
                publicKeyTextArea));
        if ("File".equals(pubSourceDisplay)) {
            params.put("publicKeyFileFormat", (String) publicKeyFileFormatCombo.getSelectedItem());
        } else if ("Command".equals(pubSourceDisplay)) {
            params.put("publicKeyFileFormat", (String) publicKeyCommandFormatCombo.getSelectedItem());
        }
        params.put("publicKeyReloadFile", String.valueOf(publicKeyReloadCheckbox.isSelected()));

        // Private key
        String privSourceDisplay = (String) privateKeySourceCombo.getSelectedItem();
        params.put("privateKeySource", displayToSource(privSourceDisplay));
        params.put("privateKey", keyValueFor(privSourceDisplay, privateKeyFileField, privateKeyCommandField,
                privateKeyTextArea));
        if ("File".equals(privSourceDisplay)) {
            params.put("privateKeyFileFormat", (String) privateKeyFileFormatCombo.getSelectedItem());
        } else if ("Command".equals(privSourceDisplay)) {
            params.put("privateKeyFileFormat", (String) privateKeyCommandFormatCombo.getSelectedItem());
        }
        params.put("privateKeyReloadFile", String.valueOf(privateKeyReloadCheckbox.isSelected()));

        // Scheme
        String schemeDisplay = (String) schemeCombo.getSelectedItem();
        switch (schemeDisplay) {
        case "RSA-OAEP": params.put("encryptionScheme", "OAEP"); break;
        case "Raw": params.put("encryptionScheme", "Raw"); break;
        default: params.put("encryptionScheme", "PKCS1"); break;
        }
        params.put("oaepDigest", (String) digestCombo.getSelectedItem());

        // Encoding
        params.put("mirrorEncoding", String.valueOf(mirrorCheckbox.isSelected()));
        params.put("encoding", (String) encodingCombo.getSelectedItem());
        params.put("inputEncoding", (String) inputEncodingCombo.getSelectedItem());
        params.put("outputEncoding", (String) outputEncodingCombo.getSelectedItem());

        return params;
    }

    public JLabel getErrorLabel() {
        return errorLabel;
    }

    private void addLabelAndCombo(String label, JComboBox<?> combo) {
        JPanel row = new JPanel();
        row.setLayout(new BoxLayout(row, BoxLayout.X_AXIS));
        row.setAlignmentX(Component.LEFT_ALIGNMENT);
        combo.setMaximumSize(new Dimension(250, 30));
        row.add(new JLabel(label + "  "));
        row.add(combo);
        add(row);
        add(Box.createVerticalStrut(3));
    }

    /**
     * Returns textarea value, or empty string if it contains a known placeholder.
     */
    private String getTextAreaValue(JTextArea area) {
        String text = area.getText();
        if (PUB_PEM_PLACEHOLDER.equals(text) || PRIV_PEM_PLACEHOLDER.equals(text)) {
            return "";
        }
        return text;
    }

    /**
     * Returns file field value, or empty string if it contains the file path placeholder.
     */
    private String getFileFieldValue(javax.swing.JTextField field) {
        String text = field.getText();
        if (FILE_PATH_PLACEHOLDER.equals(text)) {
            return "";
        }
        return text;
    }

    /**
     * Returns command field value, or empty string if it contains the placeholder.
     */
    private String getCommandFieldValue(javax.swing.JTextField field) {
        String text = field.getText();
        if (CMD_PLACEHOLDER.equals(text)) {
            return "";
        }
        return text;
    }

    /** Resolve the stored key value for the selected source. */
    private String keyValueFor(String sourceDisplay, javax.swing.JTextField fileField,
            javax.swing.JTextField commandField, JTextArea textArea) {
        if ("File".equals(sourceDisplay)) {
            return getFileFieldValue(fileField);
        }
        if ("Command".equals(sourceDisplay)) {
            return getCommandFieldValue(commandField);
        }
        return getTextAreaValue(textArea);
    }
}
