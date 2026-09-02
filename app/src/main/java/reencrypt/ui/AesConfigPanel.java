package reencrypt.ui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.HashMap;
import java.util.Map;

import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.border.EmptyBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

/**
 * Configuration panel for the AES engine.
 * Dynamically shows/hides fields based on Captured Data Structure and Mode.
 */
public class AesConfigPanel extends EngineConfigPanel {

    private static final String KEY_TEXT_PLACEHOLDER = "Enter key value...";
    private static final String IV_TEXT_PLACEHOLDER = "Enter IV value...";
    private static final String FILE_PATH_PLACEHOLDER = "/path/to/file";
    private static final String CMD_PLACEHOLDER = "Command, e.g. tail -1 ~/data.txt";
    private static final String CMD_NOTE = "Runs every time, on each decrypt/encrypt operation";

    // Separate storage for text vs file vs command values
    private String keyTextValue, keyFileValue, keyCommandValue;
    private String ivTextValue, ivFileValue, ivCommandValue;
    // Previously selected source (display string) per field, for value save/restore
    private String keyPrevSource, ivPrevSource;

    private Runnable onChangeListener;

    // UI components
    private JComboBox<String> structureCombo;
    private JComboBox<String> keySourceCombo, keyFormatCombo;
    private JTextField keyField;
    private JCheckBox keyReloadCheckbox;
    private JLabel keyCommandNote;
    private JPanel keyFilePanel;

    private JPanel ivPanel;
    private JComboBox<String> ivSourceCombo, ivFormatCombo;
    private JTextField ivField;
    private JCheckBox ivReloadCheckbox;
    private JLabel ivCommandNote;
    private JPanel ivFilePanel;
    private JLabel ivDisabledLabel;
    private JPanel ivLengthPanel;
    private JComboBox<String> ivLengthCombo;

    private JComboBox<String> modeCombo;
    private JPanel paddingPanel;
    private JComboBox<String> paddingCombo;

    private JPanel tagLengthPanel;
    private JComboBox<String> tagLengthCombo;

    private JPanel keyDerivationPanel;
    private JComboBox<String> keyDerivationCombo;
    private JPanel pbkdf2Panel;
    private JTextField pbkdf2IterationsField;

    private JPanel encodingPanel;
    private JComboBox<String> encodingCombo;
    private JCheckBox mirrorCheckbox;
    private JPanel splitEncodingPanel;
    private JComboBox<String> inputEncodingCombo, outputEncodingCombo;

    private JLabel jweInfoLabel;
    private JLabel errorLabel;

    public AesConfigPanel(Map<String, String> existingParams) {
        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));

        Map<String, String> params = existingParams != null ? existingParams : new HashMap<>();

        // === Ciphertext Structure (FIRST FIELD) ===
        structureCombo = new JComboBox<>(new String[] { "Ciphertext only", "IV + Ciphertext", "IV + Ciphertext + Tag",
                "OpenSSL enc", "JWE Compact Serialization" });
        structureCombo.setSelectedItem(mapStructureToDisplay(params.getOrDefault("ciphertextStructure", "raw")));
        addLabelAndCombo("Captured Data Structure", structureCombo, 250);
        add(Box.createVerticalStrut(8));

        // === Mode === (before Key/IV: the mode determines whether an IV is needed)
        modeCombo = new JComboBox<>(new String[] { "CBC", "ECB", "GCM", "CTR", "CFB", "OFB" });
        modeCombo.setSelectedItem(params.getOrDefault("mode", "CBC"));
        addLabelAndCombo("Mode", modeCombo, 100);

        // === Padding ===
        paddingPanel = new JPanel();
        paddingPanel.setLayout(new BoxLayout(paddingPanel, BoxLayout.X_AXIS));
        paddingPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        paddingCombo = new JComboBox<>(new String[] { "PKCS5Padding", "NoPadding", "ISO10126Padding" });
        paddingCombo.setSelectedItem(params.getOrDefault("padding", "PKCS5Padding"));
        paddingCombo.setMaximumSize(new Dimension(200, 30));
        paddingPanel.add(new JLabel("Padding      "));
        paddingPanel.add(paddingCombo);
        add(paddingPanel);

        // === GCM Tag Length ===
        tagLengthPanel = new JPanel();
        tagLengthPanel.setLayout(new BoxLayout(tagLengthPanel, BoxLayout.X_AXIS));
        tagLengthPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        tagLengthCombo = new JComboBox<>(new String[] { "128", "120", "112", "104", "96" });
        tagLengthCombo.setSelectedItem(params.getOrDefault("gcmTagLength", "128"));
        tagLengthCombo.setMaximumSize(new Dimension(200, 30));
        tagLengthPanel.add(new JLabel("Tag Length   "));
        tagLengthPanel.add(tagLengthCombo);
        add(tagLengthPanel);

        add(Box.createVerticalStrut(8));

        // === Key ===
        JPanel keyRow = new JPanel();
        keyRow.setLayout(new BoxLayout(keyRow, BoxLayout.X_AXIS));
        keyRow.setAlignmentX(Component.LEFT_ALIGNMENT);

        String keySource = params.getOrDefault("keySource", "text");
        keySourceCombo = new JComboBox<>(new String[] { "Text", "File", "Command" });
        keySourceCombo.setSelectedItem(sourceToDisplay(keySource));
        keySourceCombo.setMaximumSize(new Dimension(110, 30));
        keyPrevSource = sourceToDisplay(keySource);

        keyFormatCombo = createFormatCombo(params.getOrDefault("keyFormat", "UTF-8"));

        keyField = new JTextField();
        keyField.setMaximumSize(new Dimension(Integer.MAX_VALUE, 30));
        boolean keyIsFile = "file".equals(keySource);
        boolean keyIsCommand = "command".equals(keySource);
        // Load separate values
        keyTextValue = "text".equals(keySource) ? params.getOrDefault("key", "") : "";
        keyFileValue = params.getOrDefault("keyFilePath", keyIsFile ? params.getOrDefault("key", "") : "");
        keyCommandValue = params.getOrDefault("keyCommand", keyIsCommand ? params.getOrDefault("key", "") : "");
        String keyInitVal = keyIsCommand ? keyCommandValue : (keyIsFile ? keyFileValue : keyTextValue);
        if (keyInitVal.isEmpty()) {
            setPlaceholder(keyField, placeholderFor(keyPrevSource, KEY_TEXT_PLACEHOLDER));
        } else {
            keyField.setText(keyInitVal);
        }

        JLabel keyLabel = new JLabel("Key   ");
        keyRow.add(keyLabel);
        keyRow.add(keySourceCombo);
        keyRow.add(Box.createHorizontalStrut(5));
        keyRow.add(keyFormatCombo);
        keyRow.add(Box.createHorizontalStrut(5));
        keyRow.add(keyField);

        // File chooser button (only visible in File mode)
        javax.swing.JButton keyFileBrowse = new javax.swing.JButton("...");
        keyFileBrowse.setMaximumSize(new Dimension(40, 30));
        keyFileBrowse.setToolTipText("Browse for file");
        keyFileBrowse.addActionListener(e -> {
            JFileChooser fc = new JFileChooser();
            if (fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
                keyField.setText(fc.getSelectedFile().getAbsolutePath());
            }
        });

        keyFilePanel = new JPanel();
        keyFilePanel.setLayout(new BoxLayout(keyFilePanel, BoxLayout.X_AXIS));
        keyFilePanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        keyFilePanel.add(keyFileBrowse);
        keyRow.add(keyFilePanel);

        add(keyRow);

        // Key reload checkbox
        keyReloadCheckbox = new JCheckBox("Reload file on every operation",
                "true".equals(params.getOrDefault("keyReloadFile", "true")));
        keyReloadCheckbox.setAlignmentX(Component.LEFT_ALIGNMENT);
        keyReloadCheckbox.setBorder(new EmptyBorder(0, 50, 0, 0));
        add(keyReloadCheckbox);

        keyCommandNote = new JLabel(CMD_NOTE);
        keyCommandNote.setForeground(Color.GRAY);
        keyCommandNote.setAlignmentX(Component.LEFT_ALIGNMENT);
        keyCommandNote.setBorder(new EmptyBorder(0, 50, 0, 0));
        add(keyCommandNote);
        add(Box.createVerticalStrut(3));

        // === IV ===
        ivPanel = new JPanel();
        ivPanel.setLayout(new BoxLayout(ivPanel, BoxLayout.Y_AXIS));
        ivPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        JPanel ivRow = new JPanel();
        ivRow.setLayout(new BoxLayout(ivRow, BoxLayout.X_AXIS));
        ivRow.setAlignmentX(Component.LEFT_ALIGNMENT);

        String ivSource = params.getOrDefault("ivSource", "text");
        ivSourceCombo = new JComboBox<>(new String[] { "Text", "File", "Command" });
        ivSourceCombo.setSelectedItem(sourceToDisplay(ivSource));
        ivSourceCombo.setMaximumSize(new Dimension(110, 30));
        ivPrevSource = sourceToDisplay(ivSource);

        ivFormatCombo = createFormatCombo(params.getOrDefault("ivFormat", "UTF-8"));

        ivField = new JTextField();
        ivField.setMaximumSize(new Dimension(Integer.MAX_VALUE, 30));
        boolean ivIsFile = "file".equals(ivSource);
        boolean ivIsCommand = "command".equals(ivSource);
        // Load separate values
        ivTextValue = "text".equals(ivSource) ? params.getOrDefault("iv", "") : "";
        ivFileValue = params.getOrDefault("ivFilePath", ivIsFile ? params.getOrDefault("iv", "") : "");
        ivCommandValue = params.getOrDefault("ivCommand", ivIsCommand ? params.getOrDefault("iv", "") : "");
        String ivInitVal = ivIsCommand ? ivCommandValue : (ivIsFile ? ivFileValue : ivTextValue);
        if (ivInitVal.isEmpty()) {
            setPlaceholder(ivField, placeholderFor(ivPrevSource, IV_TEXT_PLACEHOLDER));
        } else {
            ivField.setText(ivInitVal);
        }

        ivRow.add(new JLabel("IV      "));
        ivRow.add(ivSourceCombo);
        ivRow.add(Box.createHorizontalStrut(5));
        ivRow.add(ivFormatCombo);
        ivRow.add(Box.createHorizontalStrut(5));
        ivRow.add(ivField);

        javax.swing.JButton ivFileBrowse = new javax.swing.JButton("...");
        ivFileBrowse.setMaximumSize(new Dimension(40, 30));
        ivFileBrowse.setToolTipText("Browse for file");
        ivFileBrowse.addActionListener(e -> {
            JFileChooser fc = new JFileChooser();
            if (fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
                ivField.setText(fc.getSelectedFile().getAbsolutePath());
            }
        });

        ivFilePanel = new JPanel();
        ivFilePanel.setLayout(new BoxLayout(ivFilePanel, BoxLayout.X_AXIS));
        ivFilePanel.add(ivFileBrowse);
        ivRow.add(ivFilePanel);

        ivPanel.add(ivRow);

        ivReloadCheckbox = new JCheckBox("Reload file on every operation",
                "true".equals(params.getOrDefault("ivReloadFile", "true")));
        ivReloadCheckbox.setAlignmentX(Component.LEFT_ALIGNMENT);
        ivReloadCheckbox.setBorder(new EmptyBorder(0, 50, 0, 0));
        ivPanel.add(ivReloadCheckbox);

        ivCommandNote = new JLabel(CMD_NOTE);
        ivCommandNote.setForeground(Color.GRAY);
        ivCommandNote.setAlignmentX(Component.LEFT_ALIGNMENT);
        ivCommandNote.setBorder(new EmptyBorder(0, 50, 0, 0));
        ivPanel.add(ivCommandNote);

        add(ivPanel);

        // IV disabled label (shown when structure extracts IV)
        ivDisabledLabel = new JLabel("IV      (extracted from data)");
        ivDisabledLabel.setForeground(Color.GRAY);
        ivDisabledLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        add(ivDisabledLabel);

        // IV Length (shown when structure extracts IV)
        ivLengthPanel = new JPanel();
        ivLengthPanel.setLayout(new BoxLayout(ivLengthPanel, BoxLayout.X_AXIS));
        ivLengthPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        ivLengthCombo = new JComboBox<>(
                new String[] { "Auto (16 bytes)", "Auto (12 bytes)", "12", "16", "24", "32" });
        ivLengthCombo.setSelectedItem(mapIvLength(params.getOrDefault("ivLength", "auto"),
                params.getOrDefault("mode", "CBC")));
        ivLengthCombo.setMaximumSize(new Dimension(200, 30));
        ivLengthPanel.add(new JLabel("IV Length    "));
        ivLengthPanel.add(ivLengthCombo);
        add(ivLengthPanel);

        add(Box.createVerticalStrut(8));

        // === Key Derivation (OpenSSL) ===
        keyDerivationPanel = new JPanel();
        keyDerivationPanel.setLayout(new BoxLayout(keyDerivationPanel, BoxLayout.X_AXIS));
        keyDerivationPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        keyDerivationCombo = new JComboBox<>(new String[] { "EVP_BytesToKey (MD5)", "PBKDF2-SHA256" });
        keyDerivationCombo
                .setSelectedItem("pbkdf2_sha256".equals(params.getOrDefault("keyDerivation", "evp_md5"))
                        ? "PBKDF2-SHA256"
                        : "EVP_BytesToKey (MD5)");
        keyDerivationCombo.setMaximumSize(new Dimension(250, 30));
        keyDerivationPanel.add(new JLabel("Key Derivation  "));
        keyDerivationPanel.add(keyDerivationCombo);
        add(keyDerivationPanel);

        // PBKDF2 iterations
        pbkdf2Panel = new JPanel();
        pbkdf2Panel.setLayout(new BoxLayout(pbkdf2Panel, BoxLayout.X_AXIS));
        pbkdf2Panel.setAlignmentX(Component.LEFT_ALIGNMENT);
        pbkdf2IterationsField = new JTextField(params.getOrDefault("pbkdf2Iterations", "10000"));
        pbkdf2IterationsField.setMaximumSize(new Dimension(120, 30));
        pbkdf2Panel.add(new JLabel("PBKDF2 Iterations  "));
        pbkdf2Panel.add(pbkdf2IterationsField);
        add(pbkdf2Panel);

        add(Box.createVerticalStrut(8));

        // === Encoding ===
        encodingPanel = new JPanel();
        encodingPanel.setLayout(new BoxLayout(encodingPanel, BoxLayout.Y_AXIS));
        encodingPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        JPanel encodingRow = new JPanel();
        encodingRow.setLayout(new BoxLayout(encodingRow, BoxLayout.X_AXIS));
        encodingRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        encodingCombo = new JComboBox<>(new String[] { "Base64", "Hex", "Raw" });
        encodingCombo.setSelectedItem(params.getOrDefault("encoding", "Base64"));
        encodingCombo.setMaximumSize(new Dimension(200, 30));
        encodingRow.add(new JLabel("Input/Output Encoding  "));
        encodingRow.add(encodingCombo);
        encodingPanel.add(encodingRow);

        mirrorCheckbox = new JCheckBox("Mirror encoding for decrypt and encrypt",
                "true".equals(params.getOrDefault("mirrorEncoding", "true")));
        mirrorCheckbox.setAlignmentX(Component.LEFT_ALIGNMENT);
        encodingPanel.add(mirrorCheckbox);

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

        encodingPanel.add(splitEncodingPanel);
        add(encodingPanel);

        // === JWE info label ===
        jweInfoLabel = new JLabel(
                "ⓘ IV, tag, and encoding are determined by the JWE token format (Base64URL).");
        jweInfoLabel.setForeground(Color.GRAY);
        jweInfoLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        add(jweInfoLabel);

        // === Error label ===
        add(Box.createVerticalStrut(8));
        errorLabel = new JLabel(" ");
        errorLabel.setForeground(new Color(200, 50, 50));
        errorLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        add(errorLabel);

        // === Wire up listeners ===
        ActionListener updateVisibility = e -> updateFieldVisibility();
        structureCombo.addActionListener(updateVisibility);
        modeCombo.addActionListener(updateVisibility);
        mirrorCheckbox.addActionListener(updateVisibility);
        keyDerivationCombo.addActionListener(updateVisibility);

        // Key source toggle: save current value into the previous source's slot and
        // restore the value for the newly selected source.
        keySourceCombo.addActionListener(e -> {
            String newSource = (String) keySourceCombo.getSelectedItem();
            String currentVal = getFieldValue(keyField);
            switch (keyPrevSource) {
            case "File": keyFileValue = currentVal; break;
            case "Command": keyCommandValue = currentVal; break;
            default: keyTextValue = currentVal; break;
            }
            String restore;
            switch (newSource) {
            case "File": restore = keyFileValue; break;
            case "Command": restore = keyCommandValue; break;
            default: restore = keyTextValue; break;
            }
            if (restore == null || restore.isEmpty()) {
                setPlaceholder(keyField, placeholderFor(newSource, KEY_TEXT_PLACEHOLDER));
            } else {
                keyField.setForeground(null);
                keyField.setText(restore);
            }
            keyPrevSource = newSource;
            updateFieldVisibility();
        });

        // IV source toggle: same 3-way save/restore as the key field.
        ivSourceCombo.addActionListener(e -> {
            String newSource = (String) ivSourceCombo.getSelectedItem();
            String currentVal = getFieldValue(ivField);
            switch (ivPrevSource) {
            case "File": ivFileValue = currentVal; break;
            case "Command": ivCommandValue = currentVal; break;
            default: ivTextValue = currentVal; break;
            }
            String restore;
            switch (newSource) {
            case "File": restore = ivFileValue; break;
            case "Command": restore = ivCommandValue; break;
            default: restore = ivTextValue; break;
            }
            if (restore == null || restore.isEmpty()) {
                setPlaceholder(ivField, placeholderFor(newSource, IV_TEXT_PLACEHOLDER));
            } else {
                ivField.setForeground(null);
                ivField.setText(restore);
            }
            ivPrevSource = newSource;
            updateFieldVisibility();
        });

        DocumentListener docListener = new DocumentListener() {
            public void changedUpdate(DocumentEvent e) { fireChange(); }
            public void removeUpdate(DocumentEvent e) { fireChange(); }
            public void insertUpdate(DocumentEvent e) { fireChange(); }
        };
        keyField.getDocument().addDocumentListener(docListener);
        ivField.getDocument().addDocumentListener(docListener);

        ActionListener changeListener = e -> fireChange();
        keyFormatCombo.addActionListener(changeListener);
        ivFormatCombo.addActionListener(changeListener);
        encodingCombo.addActionListener(changeListener);
        inputEncodingCombo.addActionListener(changeListener);
        outputEncodingCombo.addActionListener(changeListener);
        paddingCombo.addActionListener(changeListener);
        tagLengthCombo.addActionListener(changeListener);

        // Initial visibility
        updateFieldVisibility();
    }

    private void updateFieldVisibility() {
        String structure = mapDisplayToStructure((String) structureCombo.getSelectedItem());
        String mode = (String) modeCombo.getSelectedItem();
        boolean isEcb = "ECB".equals(mode);
        boolean isGcm = "GCM".equals(mode);
        boolean structureExtractsIv = !"raw".equals(structure);
        boolean isJwe = "jwe".equals(structure);
        boolean isOpenSsl = "openssl".equals(structure);
        boolean isFileSrcKey = "File".equals(keySourceCombo.getSelectedItem());
        boolean isCmdSrcKey = "Command".equals(keySourceCombo.getSelectedItem());
        boolean isFileSrcIv = "File".equals(ivSourceCombo.getSelectedItem());
        boolean isCmdSrcIv = "Command".equals(ivSourceCombo.getSelectedItem());
        boolean isMirror = mirrorCheckbox.isSelected();
        boolean isPbkdf2 = "PBKDF2-SHA256".equals(keyDerivationCombo.getSelectedItem());

        // Key source
        keyFilePanel.setVisible(isFileSrcKey);
        keyReloadCheckbox.setVisible(isFileSrcKey);
        keyCommandNote.setVisible(isCmdSrcKey);

        // IV visibility
        if (isEcb || isJwe) {
            ivPanel.setVisible(false);
            ivDisabledLabel.setVisible(isJwe);
            if (isJwe) {
                ivDisabledLabel.setText("IV      (extracted from JWE token)");
            }
            ivLengthPanel.setVisible(false);
        } else if (structureExtractsIv) {
            ivPanel.setVisible(false);
            ivDisabledLabel.setVisible(true);
            ivDisabledLabel.setText("IV      (extracted from data)");
            ivLengthPanel.setVisible(!isJwe);
        } else {
            ivPanel.setVisible(true);
            ivDisabledLabel.setVisible(false);
            ivLengthPanel.setVisible(false);
            ivFilePanel.setVisible(isFileSrcIv);
            ivReloadCheckbox.setVisible(isFileSrcIv);
            ivCommandNote.setVisible(isCmdSrcIv);
        }

        // Padding: only for ECB and CBC
        paddingPanel.setVisible(isEcb || "CBC".equals(mode));

        // GCM Tag Length: only for GCM with tag-aware structure (but not JWE)
        boolean showTagLength = isGcm && ("iv_ct_tag".equals(structure) || "raw".equals(structure)) && !isJwe;
        tagLengthPanel.setVisible(showTagLength);

        // Key Derivation: only for OpenSSL
        keyDerivationPanel.setVisible(isOpenSsl);
        pbkdf2Panel.setVisible(isOpenSsl && isPbkdf2);

        // Encoding: hidden for JWE
        encodingPanel.setVisible(!isJwe);
        jweInfoLabel.setVisible(isJwe);

        // Mirror encoding
        if (!isJwe) {
            encodingCombo.getParent().setVisible(isMirror);
            splitEncodingPanel.setVisible(!isMirror);
        }

        // Key format (UTF-8/Hex/Base64) applies to every structure, including OpenSSL
        // where it decodes the key material before key derivation.
        keyFormatCombo.setVisible(true);

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

        String structure = mapDisplayToStructure((String) structureCombo.getSelectedItem());
        params.put("ciphertextStructure", structure);

        String keySourceDisplay = (String) keySourceCombo.getSelectedItem();
        boolean keyIsFile = "File".equals(keySourceDisplay);
        boolean keyIsCommand = "Command".equals(keySourceDisplay);
        params.put("keySource", displayToSource(keySourceDisplay));
        String keyVal = getFieldValue(keyField);
        params.put("key", keyVal);
        // Also save the inactive slots separately so they can be restored later
        params.put("keyFilePath", keyIsFile ? keyVal : (keyFileValue != null ? keyFileValue : ""));
        params.put("keyCommand", keyIsCommand ? keyVal : (keyCommandValue != null ? keyCommandValue : ""));
        params.put("keyFormat", (String) keyFormatCombo.getSelectedItem());
        params.put("keyReloadFile", String.valueOf(keyReloadCheckbox.isSelected()));

        String ivSourceDisplay = (String) ivSourceCombo.getSelectedItem();
        boolean ivIsFile = "File".equals(ivSourceDisplay);
        boolean ivIsCommand = "Command".equals(ivSourceDisplay);
        params.put("ivSource", displayToSource(ivSourceDisplay));
        String ivVal = getFieldValue(ivField);
        params.put("iv", ivVal);
        params.put("ivFilePath", ivIsFile ? ivVal : (ivFileValue != null ? ivFileValue : ""));
        params.put("ivCommand", ivIsCommand ? ivVal : (ivCommandValue != null ? ivCommandValue : ""));
        params.put("ivFormat", (String) ivFormatCombo.getSelectedItem());
        params.put("ivReloadFile", String.valueOf(ivReloadCheckbox.isSelected()));

        String ivLenDisplay = (String) ivLengthCombo.getSelectedItem();
        if (ivLenDisplay != null && ivLenDisplay.startsWith("Auto")) {
            params.put("ivLength", "auto");
        } else if (ivLenDisplay != null) {
            params.put("ivLength", ivLenDisplay);
        }

        params.put("mode", (String) modeCombo.getSelectedItem());
        params.put("padding", (String) paddingCombo.getSelectedItem());
        params.put("gcmTagLength", (String) tagLengthCombo.getSelectedItem());

        String derivDisplay = (String) keyDerivationCombo.getSelectedItem();
        params.put("keyDerivation", "PBKDF2-SHA256".equals(derivDisplay) ? "pbkdf2_sha256" : "evp_md5");
        params.put("pbkdf2Iterations", pbkdf2IterationsField.getText());

        params.put("mirrorEncoding", String.valueOf(mirrorCheckbox.isSelected()));
        params.put("encoding", (String) encodingCombo.getSelectedItem());
        params.put("inputEncoding", (String) inputEncodingCombo.getSelectedItem());
        params.put("outputEncoding", (String) outputEncodingCombo.getSelectedItem());

        return params;
    }

    public JLabel getErrorLabel() {
        return errorLabel;
    }

    // === Helpers ===

    private void addLabelAndCombo(String label, JComboBox<?> combo, int maxWidth) {
        JPanel row = new JPanel();
        row.setLayout(new BoxLayout(row, BoxLayout.X_AXIS));
        row.setAlignmentX(Component.LEFT_ALIGNMENT);
        combo.setMaximumSize(new Dimension(maxWidth, 30));
        row.add(new JLabel(label + "  "));
        row.add(combo);
        add(row);
        add(Box.createVerticalStrut(3));
    }

    /**
     * Returns the field value, or empty string if it contains a known placeholder.
     */
    private String getFieldValue(JTextField field) {
        String text = field.getText();
        if (KEY_TEXT_PLACEHOLDER.equals(text) || IV_TEXT_PLACEHOLDER.equals(text) || FILE_PATH_PLACEHOLDER.equals(text)
                || CMD_PLACEHOLDER.equals(text)) {
            return "";
        }
        return text;
    }

    /** Create the shared key/IV format dropdown (UTF-8 / Hex / Base64). */
    private JComboBox<String> createFormatCombo(String selected) {
        JComboBox<String> combo = new JComboBox<>(new String[] { "UTF-8", "Hex", "Base64" });
        combo.setSelectedItem(selected);
        combo.setMaximumSize(new Dimension(100, 30));
        return combo;
    }

    /** Map a stored source ("text"/"file"/"command") to its dropdown display string. */
    private String sourceToDisplay(String source) {
        if ("file".equals(source)) return "File";
        if ("command".equals(source)) return "Command";
        return "Text";
    }

    /** Map a dropdown display string back to the stored source value. */
    private String displayToSource(String display) {
        if ("File".equals(display)) return "file";
        if ("Command".equals(display)) return "command";
        return "text";
    }

    /** Pick the placeholder text for the given source display string. */
    private String placeholderFor(String sourceDisplay, String textPlaceholder) {
        if ("File".equals(sourceDisplay)) return FILE_PATH_PLACEHOLDER;
        if ("Command".equals(sourceDisplay)) return CMD_PLACEHOLDER;
        return textPlaceholder;
    }

    private String mapStructureToDisplay(String structure) {
        switch (structure) {
        case "iv_ct": return "IV + Ciphertext";
        case "iv_ct_tag": return "IV + Ciphertext + Tag";
        case "openssl": return "OpenSSL enc";
        case "jwe": return "JWE Compact Serialization";
        default: return "Ciphertext only";
        }
    }

    private String mapDisplayToStructure(String display) {
        switch (display) {
        case "IV + Ciphertext": return "iv_ct";
        case "IV + Ciphertext + Tag": return "iv_ct_tag";
        case "OpenSSL enc": return "openssl";
        case "JWE Compact Serialization": return "jwe";
        default: return "raw";
        }
    }

    private String mapIvLength(String ivLength, String mode) {
        if ("auto".equals(ivLength)) {
            return "GCM".equals(mode) ? "Auto (12 bytes)" : "Auto (16 bytes)";
        }
        return ivLength;
    }

    private void setPlaceholder(JTextField textField, String placeholder) {
        textField.setForeground(Color.GRAY);
        textField.setText(placeholder);
        textField.addFocusListener(new java.awt.event.FocusAdapter() {
            @Override
            public void focusGained(java.awt.event.FocusEvent e) {
                if (textField.getText().equals(placeholder)) {
                    textField.setText("");
                    textField.setForeground(null);
                }
            }

            @Override
            public void focusLost(java.awt.event.FocusEvent e) {
                if (textField.getText().isEmpty()) {
                    textField.setForeground(Color.GRAY);
                    textField.setText(placeholder);
                }
            }
        });
    }
}
