package reencrypt.ui;

import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableColumnModel;

import reencrypt.CapturePattern;
import reencrypt.Config;
import reencrypt.PatternType;

import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.GridLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.IOException;
import java.util.Arrays;

import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.JComboBox;
import javax.swing.border.EmptyBorder;

public class SettingsTab {
    private Font hackFont = new Font("Hack", Font.BOLD, 18);
    private Config config;

    public SettingsTab(Config config) {
        this.config = config;
    }

    public Component uiComponent() {
        JTabbedPane tabbedPane = new JTabbedPane();

        tabbedPane.add("Capturing + Processing", createCaptureDataScreen());
        tabbedPane.add("Intruder Settings", createIntruderScreen());

        tabbedPane.add("(TODO) WebSockets ", null);
        tabbedPane.setEnabledAt(2, false);

        tabbedPane.add("Extra Settings", createSettingsScreen());

        return tabbedPane;
    }

    private JPanel createCaptureDataScreen() {
        JPanel subpanel = new JPanel(new GridLayout(2, 1));
        subpanel.add(createCaptureDataTable("• Request Patterns", true));
        subpanel.add(createCaptureDataTable("• Response Patterns", false));
        return addPanelInternalText("Set regexs to define what will be re:encrypted / re:encoded", subpanel);
    }

    private JPanel createIntruderScreen() {
        JPanel mainPanel = new JPanel(new BorderLayout());
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));

        // Section title
        JLabel titleLabel = new JLabel("• Intruder Settings");
        titleLabel.setFont(hackFont);
        titleLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        titleLabel.setBorder(new EmptyBorder(0, 0, 15, 0));
        panel.add(titleLabel);

        // Decrypt responses checkbox
        JCheckBox decryptResponsesCheckbox = new JCheckBox("Auto-decrypt intruder responses");
        decryptResponsesCheckbox.setSelected(config.isIntruderResponseDecryptEnabled());
        decryptResponsesCheckbox.setAlignmentX(Component.LEFT_ALIGNMENT);
        decryptResponsesCheckbox
                .addActionListener(e -> config.setIntruderResponseDecrypt(decryptResponsesCheckbox.isSelected()));
        panel.add(decryptResponsesCheckbox);

        // Explanation for decrypt responses
        JLabel decryptExplanation = new JLabel(
                "Automatically DECRYPT using RESPONSE decrypt commands. Respecting targets defined in each pattern. Also disables Re:Encrypt custom tab for Intruder Responses");
        decryptExplanation.setFont(decryptExplanation.getFont().deriveFont(11f));
        decryptExplanation.setForeground(Color.GRAY);
        decryptExplanation.setAlignmentX(Component.LEFT_ALIGNMENT);
        decryptExplanation.setBorder(new EmptyBorder(0, 24, 15, 0));
        panel.add(decryptExplanation);

        // Encrypt requests checkbox
        JCheckBox encryptRequestsCheckbox = new JCheckBox(
                "Auto-encrypt intruder requests (You HAVE to send payloads in PLAINTEXT)");
        encryptRequestsCheckbox.setSelected(config.isIntruderRequestEncryptEnabled());
        encryptRequestsCheckbox.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(encryptRequestsCheckbox);

        // Explanation for encrypt requests
        JLabel encryptExplanation = new JLabel(
                "Automatically ENCRYPT using REQUEST encrypt commands. Respecting targets defined in each pattern. Also disables Re:Encrypt custom tab for Intruder Requests");
        encryptExplanation.setFont(encryptExplanation.getFont().deriveFont(11f));
        encryptExplanation.setForeground(Color.GRAY);
        encryptExplanation.setAlignmentX(Component.LEFT_ALIGNMENT);
        encryptExplanation.setBorder(new EmptyBorder(0, 24, 2, 0));
        panel.add(encryptExplanation);

        JLabel encryptExplanation2 = new JLabel(
                "If you want to see the ciphertext, use Burp Suite Logger (CTRL+SHIFT+L)");
        encryptExplanation2.setFont(encryptExplanation2.getFont().deriveFont(11f));
        encryptExplanation2.setForeground(Color.GRAY);
        encryptExplanation2.setAlignmentX(Component.LEFT_ALIGNMENT);
        encryptExplanation2.setBorder(new EmptyBorder(0, 24, 15, 0));
        panel.add(encryptExplanation2);

        // Payload processor checkbox
        JCheckBox payloadProcessorCheckbox = new JCheckBox("Encrypt using payload processor");
        payloadProcessorCheckbox.setSelected(config.isIntruderPayloadProcessorEnabled());
        payloadProcessorCheckbox.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(payloadProcessorCheckbox);

        // Encrypt command text field
        JPanel commandPanel = new JPanel(new BorderLayout(5, 0));
        commandPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        commandPanel.setBorder(new EmptyBorder(5, 24, 5, 5));
        commandPanel.setMaximumSize(new Dimension(800, 45));

        JLabel commandLabel = new JLabel("Encrypt Command:");
        Color enabledLabelColor = commandLabel.getForeground();
        boolean payloadProcessorEnabled = config.isIntruderPayloadProcessorEnabled();
        commandLabel.setForeground(payloadProcessorEnabled ? enabledLabelColor : Color.GRAY);

        JTextField commandField = new JTextField(config.getIntruderEncryptCommand());
        commandField.setEnabled(payloadProcessorEnabled);
        commandField.setToolTipText(
                "Command to use in Intruder Payload Processor. Use {DATA} to refer to the captured data, or {FILE} to refer to a temporary file containing the captured data.");
        String commandFieldPlaceholder = "python /tmp/script.js --encrypt --file {FILE}";
        setPlaceholder(commandField, commandFieldPlaceholder);
        commandField.getDocument().addDocumentListener(new DocumentListener() {
            public void changedUpdate(DocumentEvent e) {
                save();
            }

            public void removeUpdate(DocumentEvent e) {
                save();
            }

            public void insertUpdate(DocumentEvent e) {
                save();
            }

            private void save() {
                String text = commandField.getText();
                if (!text.equals(commandFieldPlaceholder)) {
                    config.setIntruderEncryptCommand(text);
                }
            }
        });

        commandPanel.add(commandLabel, BorderLayout.WEST);
        commandPanel.add(commandField, BorderLayout.CENTER);
        panel.add(commandPanel);

        // Explanation for payload processor
        JLabel payloadExplanation = new JLabel(
                "In Intruder, go to \"Payload processing\" > \"Add\" > \"Invoke Burp extension\" to use the command above");
        payloadExplanation.setFont(payloadExplanation.getFont().deriveFont(11f));
        payloadExplanation.setForeground(Color.GRAY);
        payloadExplanation.setAlignmentX(Component.LEFT_ALIGNMENT);
        payloadExplanation.setBorder(new EmptyBorder(0, 24, 15, 0));
        panel.add(payloadExplanation);

        // Mutual exclusion logic
        encryptRequestsCheckbox.addActionListener(e -> {
            if (encryptRequestsCheckbox.isSelected()) {
                payloadProcessorCheckbox.setSelected(false);
                config.setIntruderPayloadProcessor(false);
                commandField.setEnabled(false);
                commandLabel.setForeground(Color.GRAY);
            }
            config.setIntruderRequestEncrypt(encryptRequestsCheckbox.isSelected());
        });

        payloadProcessorCheckbox.addActionListener(e -> {
            if (payloadProcessorCheckbox.isSelected()) {
                encryptRequestsCheckbox.setSelected(false);
                config.setIntruderRequestEncrypt(false);
            }
            boolean enabled = payloadProcessorCheckbox.isSelected();
            commandField.setEnabled(enabled);
            commandLabel.setForeground(enabled ? enabledLabelColor : Color.GRAY);
            config.setIntruderPayloadProcessor(enabled);
        });

        mainPanel.add(panel, BorderLayout.NORTH);
        return addPanelInternalText("Optionally, adjust intruder-specific settings", mainPanel);
    }

    private JPanel createCaptureDataTable(String title, boolean isRequest) {

        JPanel panel = new JPanel(new BorderLayout());
        JLabel jlabel = new JLabel();
        jlabel.setFont(hackFont);
        jlabel.setText(title);
        jlabel.setBorder(new EmptyBorder(isRequest ? 0 : 20, 0, 5, 0));
        panel.add(jlabel, BorderLayout.NORTH);

        Object[] tableColumnName = new Object[] { "Enabled", "Name", "Capture Regex", "Target", "Patch Proxy",
                "Decrypt Command", "Encrypt Command" };

        // Creating tables
        DefaultTableModel model = new DefaultTableModel(null, tableColumnName) {
            @Override
            public Class<?> getColumnClass(int columnIndex) {
                switch (getColumnName(columnIndex)) {
                case "Enabled":
                    return Boolean.class;
                case "Patch Proxy":
                    return Boolean.class;
                }
                return super.getColumnClass(columnIndex);
            };

            @Override
            public boolean isCellEditable(int row, int col) {
                return false;
            }
        };
        // Loading saved patterns
        updateTable(model, config, isRequest);
        JTable table = new JTable(model);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        table.setFillsViewportHeight(true);

        // Defined actions
        ActionListener addAction = new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                var newPattern = createOrEditPatternPopup(isRequest);
                if (newPattern == null) {
                    return; // User cancelled the dialog
                }
                config.addPattern(newPattern, isRequest);
                updateTable(model, config, isRequest);
            }
        };

        ActionListener editAction = new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int index = table.getSelectedRow();
                if (index != -1) {
                    var modifiedPattern = createOrEditPatternPopup(config.getPatterns(isRequest).get(index), isRequest);
                    if (modifiedPattern == null) {
                        return; // User cancelled the dialog
                    }
                    config.editPattern(index, modifiedPattern, isRequest);
                    updateTable(model, config, isRequest);
                }
            }
        };

        ActionListener cloneAction = new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int index = table.getSelectedRow();
                if (index != -1) {
                    config.clonePattern(index, isRequest);
                    updateTable(model, config, isRequest);

                    int wishedIndex = index + 1;
                    int currentIndex = model.getRowCount() - 1;
                    while (currentIndex > wishedIndex) {
                        config.movePattern(currentIndex, currentIndex - 1, isRequest);
                        int newRow = moveRow(model, currentIndex, currentIndex - 1);
                        table.addRowSelectionInterval(newRow, newRow);
                        currentIndex--;
                    }
                }
            }
        };

        ActionListener removeAction = new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int[] selectedRows = table.getSelectedRows();
                Arrays.sort(selectedRows);
                for (int auxIndex = selectedRows.length - 1; auxIndex >= 0; auxIndex--) {
                    int selectedRowIndex = selectedRows[auxIndex];
                    config.removePattern(selectedRowIndex, isRequest);
                }
                updateTable(model, config, isRequest);
            }
        };

        ActionListener upAction = new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int[] selectedRows = table.getSelectedRows();
                Arrays.sort(selectedRows);
                for (int selectedRow : selectedRows) {
                    config.movePattern(selectedRow, selectedRow - 1, isRequest);
                    int newRow = moveRow(model, selectedRow, selectedRow - 1);
                    table.addRowSelectionInterval(newRow, newRow);
                }
            }
        };

        ActionListener downAction = new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int[] selectedRows = table.getSelectedRows();
                Arrays.sort(selectedRows);
                for (int auxIndex = selectedRows.length - 1; auxIndex >= 0; auxIndex--) {
                    int selectedRow = selectedRows[auxIndex];
                    config.movePattern(selectedRow, selectedRow + 1, isRequest);
                    int newRow = moveRow(model, selectedRow, selectedRow + 1);
                    table.addRowSelectionInterval(newRow, newRow);
                }
            }
        };

        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && !e.isConsumed()) {
                    e.consume();
                    int index = table.getSelectedRow();
                    if (index != -1) {
                        editAction
                                .actionPerformed(new ActionEvent(e.getSource(), ActionEvent.ACTION_PERFORMED, "edit"));
                    }
                }
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                checkPopup(e);
            }

            @Override
            public void mousePressed(MouseEvent e) {
                checkPopup(e);
            }

            private void checkPopup(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    int r = table.rowAtPoint(e.getPoint());
                    if (r != -1 && !table.isRowSelected(r)) {
                        table.setRowSelectionInterval(r, r);
                    }

                    JPopupMenu popup = new JPopupMenu();

                    if (r != -1) {
                        JMenuItem editItem = new JMenuItem("Edit");
                        editItem.addActionListener(editAction);
                        popup.add(editItem);

                        JMenuItem cloneItem = new JMenuItem("Clone");
                        cloneItem.addActionListener(cloneAction);
                        popup.add(cloneItem);

                        JMenuItem removeItem = new JMenuItem("Remove");
                        removeItem.addActionListener(removeAction);
                        popup.add(removeItem);

                        popup.addSeparator();

                        JMenuItem upItem = new JMenuItem("Up");
                        upItem.addActionListener(upAction);
                        popup.add(upItem);

                        JMenuItem downItem = new JMenuItem("Down");
                        downItem.addActionListener(downAction);
                        popup.add(downItem);
                    } else {
                        JMenuItem addItem = new JMenuItem("Add");
                        addItem.addActionListener(addAction);
                        popup.add(addItem);
                    }
                    popup.show(e.getComponent(), e.getX(), e.getY());
                }
            }
        });
        TableColumnModel columnModel = table.getColumnModel();
        columnModel.getColumn(0).setPreferredWidth(70); // "Enabled"
        columnModel.getColumn(1).setPreferredWidth(100); // "Name"
        columnModel.getColumn(2).setPreferredWidth(150); // "Capture Regex"
        columnModel.getColumn(3).setPreferredWidth(150); // "Target"
        columnModel.getColumn(4).setPreferredWidth(100); // "Patch Proxy"
        columnModel.getColumn(5).setPreferredWidth(500); // "Decrypt Command"
        columnModel.getColumn(6).setPreferredWidth(500); // "Encrypt Command"

        JScrollPane scrollPane = new JScrollPane(table);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        panel.add(scrollPane);

        // Adding buttons

        // Adding buttons
        JButton addButton = new JButton("Add");
        addButton.addActionListener(addAction);

        JButton editButton = new JButton("Edit");
        editButton.addActionListener(editAction);

        JButton cloneButton = new JButton("Clone");
        cloneButton.addActionListener(cloneAction);

        JButton removeButton = new JButton("Remove");
        removeButton.addActionListener(removeAction);

        JButton upButton = new JButton("Up");
        upButton.addActionListener(upAction);

        JButton downButton = new JButton("Down");
        downButton.addActionListener(downAction);

        JPanel buttonPanel = new JPanel(new GridLayout(6, 1, 0, 5));
        buttonPanel.add(addButton);
        buttonPanel.add(cloneButton);
        buttonPanel.add(editButton);
        buttonPanel.add(removeButton);
        buttonPanel.add(upButton);
        buttonPanel.add(downButton);
        buttonPanel.setBorder(new EmptyBorder(1, 5, 1, 1));

        JPanel buttonWrapper = new JPanel(new BorderLayout());
        buttonWrapper.add(buttonPanel, BorderLayout.NORTH);
        panel.add(buttonWrapper, BorderLayout.EAST);

        return panel;
    }

    private CapturePattern createOrEditPatternPopup(boolean isRequest) {
        return createOrEditPatternPopup(null, isRequest);
    }

    private CapturePattern createOrEditPatternPopup(CapturePattern existingPattern, boolean isRequest) {
        CapturePattern pattern = null;

        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));

        // === Tab Name ===
        JTextField nameField = new JTextField();
        nameField.setToolTipText("Enter a name for the pattern.");
        addLabelAndField(panel, "Tab Name", nameField);

        // === Capture Pattern Section (horizontal layout) ===
        JLabel patternLabel = new JLabel("Capture Pattern");
        patternLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(patternLabel);

        JPanel patternRow = new JPanel();
        patternRow.setLayout(new BoxLayout(patternRow, BoxLayout.X_AXIS));
        patternRow.setAlignmentX(Component.LEFT_ALIGNMENT);

        JComboBox<String> patternTypeCombo = new JComboBox<>(PatternType.getDisplayNames());
        patternTypeCombo.setMaximumSize(new Dimension(250, 30));
        patternRow.add(patternTypeCombo);
        patternRow.add(Box.createHorizontalStrut(10));

        // Dynamic input field panel (next to dropdown)
        JLabel patternInputLabel = new JLabel("Header Name");
        JTextField patternInputField = new JTextField();
        patternInputField.setMaximumSize(new Dimension(Integer.MAX_VALUE, 30));

        JPanel patternInputPanel = new JPanel();
        patternInputPanel.setLayout(new BoxLayout(patternInputPanel, BoxLayout.X_AXIS));
        patternInputPanel.add(patternInputLabel);
        patternInputPanel.add(Box.createHorizontalStrut(5));
        patternInputPanel.add(patternInputField);

        patternRow.add(patternInputPanel);
        panel.add(patternRow);
        panel.add(Box.createVerticalStrut(5));

        // Hint label for Custom Regex (hidden by default)
        JLabel regexHintLabel = new JLabel();
        regexHintLabel.setFont(regexHintLabel.getFont().deriveFont(11f));
        regexHintLabel.setForeground(Color.GRAY);
        regexHintLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        regexHintLabel.setVisible(true);
        panel.add(regexHintLabel);
        panel.add(Box.createVerticalStrut(5));

        // Update input field label based on selection
        patternTypeCombo.addActionListener(e -> {
            PatternType selected = PatternType.fromDisplayName((String) patternTypeCombo.getSelectedItem());
            switch (selected) {
            case HEADER:
                patternInputLabel.setText("Header Name");
                patternInputPanel.setVisible(true);
                regexHintLabel.setText("Case insensitive");
                break;
            case PARAMETER_URL_ENCODED:
            case PARAMETER_JSON:
                patternInputLabel.setText("Parameter Name");
                patternInputPanel.setVisible(true);
                regexHintLabel.setText("Case sensitive");
                break;
            case WHOLE_BODY:
                patternInputPanel.setVisible(false);
                regexHintLabel.setText(" ");
                break;
            case CUSTOM_REGEX:
            default:
                patternInputLabel.setText("Capture Regex");
                patternInputPanel.setVisible(true);
                regexHintLabel.setText("Case sensitive. Use (.*) or (.*?) to define which part should be captured");
                break;
            }
            panel.revalidate();
        });

        // === Target Scope Section (horizontal layout) ===
        JLabel scopeLabel = new JLabel("Target URL Scope");
        scopeLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(scopeLabel);

        JPanel scopeRow = new JPanel();
        scopeRow.setLayout(new BoxLayout(scopeRow, BoxLayout.X_AXIS));
        scopeRow.setAlignmentX(Component.LEFT_ALIGNMENT);

        String[] scopeTypes = { "Any", "Project In-Scope", "Custom Scope" };
        JComboBox<String> scopeTypeCombo = new JComboBox<>(scopeTypes);
        scopeTypeCombo.setMaximumSize(new Dimension(200, 30));
        scopeRow.add(scopeTypeCombo);
        scopeRow.add(Box.createHorizontalStrut(10));

        // Dynamic scope input field (next to dropdown)
        JLabel scopeInputLabel = new JLabel("URL Regex");
        JTextField scopeInputField = new JTextField();
        scopeInputField.setMaximumSize(new Dimension(Integer.MAX_VALUE, 30));

        JPanel scopeInputPanel = new JPanel();
        scopeInputPanel.setLayout(new BoxLayout(scopeInputPanel, BoxLayout.X_AXIS));
        scopeInputPanel.add(scopeInputLabel);
        scopeInputPanel.add(Box.createHorizontalStrut(5));
        scopeInputPanel.add(scopeInputField);
        scopeInputPanel.setVisible(false); // Hidden by default ("Any" selected)

        scopeRow.add(scopeInputPanel);
        panel.add(scopeRow);
        panel.add(Box.createVerticalStrut(5));

        scopeTypeCombo.addActionListener(e -> {
            String selected = (String) scopeTypeCombo.getSelectedItem();
            scopeInputPanel.setVisible("Custom Scope".equals(selected));
            panel.revalidate();
        });

        // === Commands Section ===
        JTextField decCommand = new JTextField();
        decCommand.setToolTipText(
                "Command to decrypt/decode. Use {DATA} to refer to the captured data, or {FILE} to refer to a temporary file containing the captured data.");
        addLabelAndField(panel, "Decrypt Command", decCommand);
        addGrayLabel(panel, "{FILE} will be replaced by a file that has the captured data as content");

        JTextField encCommand = new JTextField();
        encCommand.setToolTipText(
                "Command to encrypt/encode. Use {DATA} to refer to the captured data, or {FILE} to refer to a temporary file containing the captured data.");
        addLabelAndField(panel, "Encrypt Command", encCommand);
        addGrayLabel(panel, "{FILE} will be replaced by a file that has the captured data as content");

        // === Checkboxes ===
        JCheckBox enabledCheckbox = new JCheckBox("Pattern enabled", true);
        addComponent(panel, enabledCheckbox);

        JCheckBox cacheCommandsCheckbox = new JCheckBox("Use cache system for decrypting", true);
        addComponent(panel, cacheCommandsCheckbox);
        addGrayLabel(panel, "Save decrypted outputs, and load them when a decrypt command fails");

        JCheckBox saveToLogCheckbox = new JCheckBox("Log data to the file defined in Extra Settings", true);
        addComponent(panel, saveToLogCheckbox);
        addGrayLabel(panel,
                "Later you can open the file and easily search for plaintext data. Proxy data will also be logged if the option below is enabled");

        JCheckBox patchProxyCheckbox = new JCheckBox("Patch proxy " + (isRequest ? "requests" : "responses"), false);
        addComponent(panel, patchProxyCheckbox);

        addGrayLabel(panel, "Automatically re-encrypt proxy data.");

        // === Populate fields for editing or set defaults for new ===
        if (existingPattern != null) {
            nameField.setText(existingPattern.getName());
            decCommand.setText(existingPattern.getDecCommand());
            encCommand.setText(existingPattern.getEncCommand());
            enabledCheckbox.setSelected(existingPattern.isEnabled());
            patchProxyCheckbox.setSelected(existingPattern.shouldPatchProxy());
            cacheCommandsCheckbox.setSelected(existingPattern.shouldUseCacheSystem());
            saveToLogCheckbox.setSelected(existingPattern.shouldSaveToLog());

            // Set pattern type and input from stored values
            patternTypeCombo.setSelectedItem(existingPattern.getPatternType().getDisplayName());
            patternInputField.setText(existingPattern.getPatternInput());
            String urlRegex = existingPattern.getURLTargetRegex();
            // Parse scope
            if (existingPattern.usesProjectScope()) {
                scopeTypeCombo.setSelectedItem("Project In-Scope");
            } else if (urlRegex == null || urlRegex.isEmpty()) {
                scopeTypeCombo.setSelectedItem("Any");
            } else {
                scopeTypeCombo.setSelectedItem("Custom Scope");
                scopeInputField.setText(urlRegex);
                scopeInputPanel.setVisible(true);
            }
        } else {
            // New pattern - auto-generate name
            nameField.setText(config.generateUniqueName(isRequest));
            setPlaceholder(decCommand, "cat {FILE} ");
            setPlaceholder(encCommand, "cat {FILE} ");
            // Default to Parameter JSON for new patterns
            patternTypeCombo.setSelectedItem(PatternType.PARAMETER_JSON.getDisplayName());
        }

        // Trigger initial visibility update
        patternTypeCombo.getActionListeners()[0]
                .actionPerformed(new ActionEvent(patternTypeCombo, ActionEvent.ACTION_PERFORMED, "init"));
        scopeTypeCombo.getActionListeners()[0]
                .actionPerformed(new ActionEvent(scopeTypeCombo, ActionEvent.ACTION_PERFORMED, "init"));

        String[] options = { "OK", "Cancel" };

        JOptionPane optionPane = new JOptionPane(panel, JOptionPane.PLAIN_MESSAGE, JOptionPane.OK_CANCEL_OPTION, null,
                options, options[0]);

        JDialog dialog = optionPane.createDialog(existingPattern == null ? "Adding Pattern" : "Editing Pattern");

        while (true) {
            dialog.setVisible(true);
            Object selectedValue = optionPane.getValue();

            if (!"OK".equals(selectedValue)) {
                return null; // Cancelled
            }

            // Build regex from dropdown selection
            PatternType selectedPatternType = PatternType.fromDisplayName((String) patternTypeCombo.getSelectedItem());
            String patternInput = patternInputField.getText();
            String regex = selectedPatternType.buildRegex(patternInput);
            if (regex == null || regex.trim().isEmpty()) {
                JOptionPane.showMessageDialog(null, "You HAVE TO define a pattern.", "Error",
                        JOptionPane.ERROR_MESSAGE);
                continue;
            }

            // Build scope from dropdown selection
            String scopeSelection = (String) scopeTypeCombo.getSelectedItem();
            boolean useProjectScope = "Project In-Scope".equals(scopeSelection);
            String scopeRegex = "Custom Scope".equals(scopeSelection) ? scopeInputField.getText() : "";

            String name = nameField.getText();
            if (name == null || name.isEmpty()) {
                name = config.generateUniqueName(isRequest);
            }

            boolean duplicate = false;
            for (CapturePattern p : config.getPatterns(isRequest)) {
                if (p.getName().equals(name)) {
                    if (existingPattern != null && p == existingPattern) {
                        continue;
                    }
                    duplicate = true;
                    break;
                }
            }

            if (duplicate) {
                JOptionPane.showMessageDialog(null,
                        "A pattern with this name already exists.\nPlease choose a unique name.", "Error",
                        JOptionPane.ERROR_MESSAGE);
                continue;
            }

            pattern = new CapturePattern(name, regex, scopeRegex, decCommand.getText(), encCommand.getText(),
                    enabledCheckbox.isSelected(), patchProxyCheckbox.isSelected(), cacheCommandsCheckbox.isSelected(),
                    saveToLogCheckbox.isSelected(), useProjectScope, selectedPatternType, patternInput);
            break;
        }
        return pattern;
    }

    private void addLabelAndField(JPanel panel, String labelText, JTextField field) {
        JLabel label = new JLabel(labelText);
        label.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(label);

        field.setAlignmentX(Component.LEFT_ALIGNMENT);
        field.setMaximumSize(new Dimension(Integer.MAX_VALUE, 30));
        panel.add(field);

        panel.add(Box.createVerticalStrut(5));
    }

    private void addComponent(JPanel panel, JComponent comp) {
        comp.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(comp);
        panel.add(Box.createVerticalStrut(2));
    }

    private void addGrayLabel(JPanel panel, String text) {
        JLabel label = new JLabel(text);
        label.setFont(label.getFont().deriveFont(11f));
        label.setForeground(Color.GRAY);
        label.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(label);
        panel.add(Box.createVerticalStrut(1));
    }

    private JPanel createSettingsScreen() {
        JPanel painelBorderLayout = new JPanel(new BorderLayout());
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));

        createRepeaterSettings(panel);
        createLogFileSettings(panel);
        createPrintTabSettings(panel, true);
        createPrintTabSettings(panel, false);
        createCacheSettings(panel);

        painelBorderLayout.add(panel, BorderLayout.NORTH);

        return addPanelInternalText("Optionally, adjust extra settings", painelBorderLayout);
    }

    private void createRepeaterSettings(JPanel panel) {
        JLabel jlabel = new JLabel();
        jlabel.setFont(hackFont);
        jlabel.setText("• Repeater");
        jlabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        jlabel.setBorder(new EmptyBorder(0, 0, 10, 0));
        panel.add(jlabel);

        JCheckBox encryptOnModificationCheckbox = new JCheckBox("Encrypt only when the plaintext is modified",
                config.isRepeaterEncryptOnlyOnModification());
        encryptOnModificationCheckbox.setAlignmentX(Component.LEFT_ALIGNMENT);
        encryptOnModificationCheckbox.addActionListener(e -> {
            config.setRepeaterEncryptOnlyOnModification(encryptOnModificationCheckbox.isSelected());
        });
        panel.add(encryptOnModificationCheckbox);

        JLabel explanation = new JLabel("When disabled, always runs the encrypt command before sending to the server");
        explanation.setFont(explanation.getFont().deriveFont(11f));
        explanation.setForeground(Color.GRAY);
        explanation.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(explanation);
    }

    private void createLogFileSettings(JPanel panel) {
        JLabel jlabel = new JLabel();
        jlabel.setFont(hackFont);
        jlabel.setText("• Log File");
        jlabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        jlabel.setBorder(new EmptyBorder(20, 0, 10, 0));
        panel.add(jlabel);

        // File chooser row panel
        JPanel fileChooserPanel = new JPanel(new BorderLayout(5, 0));
        fileChooserPanel.setBorder(new EmptyBorder(5, 0, 5, 5));
        fileChooserPanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, 30));
        fileChooserPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel logFileLabel = new JLabel("Log File:");

        // Default file path in user's home directory (cross-platform)
        JTextField logFileField = new JTextField(config.getLogFilePath());
        logFileField.setEditable(false);

        JButton button = new JButton("Choose file...");

        button.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                JFileChooser fileChooser = new JFileChooser();
                String currentPath = logFileField.getText();
                if (currentPath != null && !currentPath.isEmpty()) {
                    File currentFile = new File(currentPath);
                    if (currentFile.getParentFile() != null && currentFile.getParentFile().exists()) {
                        fileChooser.setCurrentDirectory(currentFile.getParentFile());
                    }
                    if (currentFile.exists()) {
                        fileChooser.setSelectedFile(currentFile);
                    }
                }
                int returnValue = fileChooser.showOpenDialog(null);

                if (returnValue == JFileChooser.APPROVE_OPTION) {
                    String path = fileChooser.getSelectedFile().getAbsolutePath();
                    try {
                        config.updateLogFilePath(path);
                        logFileField.setText(path);
                    } catch (IOException ex) {
                        JOptionPane.showMessageDialog(null, "Failed to update log file path: " + ex.getMessage(),
                                "Error", JOptionPane.ERROR_MESSAGE);
                    }
                }
            }
        });

        fileChooserPanel.add(logFileLabel, BorderLayout.WEST);
        fileChooserPanel.add(logFileField, BorderLayout.CENTER);
        fileChooserPanel.add(button, BorderLayout.EAST);

        panel.add(fileChooserPanel);

        JLabel explanation = new JLabel("To disable logging, uncheck 'Log data' for each pattern");
        explanation.setFont(explanation.getFont().deriveFont(11f));
        explanation.setForeground(Color.GRAY);
        explanation.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(explanation);
    }

    private void createCacheSettings(JPanel panel) {
        JLabel jlabel = new JLabel();
        jlabel.setFont(hackFont);
        jlabel.setText("• Cache System for Decryption");
        jlabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        jlabel.setBorder(new EmptyBorder(20, 0, 10, 0));
        panel.add(jlabel);

        JPanel cachePanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        cachePanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        cachePanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        cachePanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel sizeLabel = new JLabel("Cache Size: " + getCacheSizeFormatted());
        // Add some space after label
        sizeLabel.setBorder(new EmptyBorder(0, 0, 0, 10));

        JButton clearButton = new JButton("Clear Cache");
        JButton refreshButton = new JButton("Refresh Size");

        clearButton.addActionListener(e -> {
            int result = JOptionPane.showConfirmDialog(null,
                    "Are you sure you want to clear the decryption cache?\nYou may lose important data!!!\nThis action cannot be undone.",
                    "Clear Cache", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
            if (result == JOptionPane.YES_OPTION) {
                config.getDecryptionCache().clear();
                sizeLabel.setText("Cache Size: " + getCacheSizeFormatted());
                JOptionPane.showMessageDialog(null, "Cache cleared successfully.");
            }
        });

        refreshButton.addActionListener(e -> {
            sizeLabel.setText("Cache Size: " + getCacheSizeFormatted());
        });

        cachePanel.add(sizeLabel);
        cachePanel.add(clearButton);
        // Add space between buttons
        cachePanel.add(Box.createHorizontalStrut(5));
        cachePanel.add(refreshButton);

        panel.add(cachePanel);

        JLabel descriptionLabel = new JLabel("Cache data is stored in the Burp project file.");
        descriptionLabel.setFont(descriptionLabel.getFont().deriveFont(11f));
        descriptionLabel.setForeground(Color.GRAY);
        descriptionLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        descriptionLabel.setBorder(new EmptyBorder(5, 0, 0, 0));
        panel.add(descriptionLabel);
    }

    private String getCacheSizeFormatted() {
        long bytes = config.getDecryptionCache().getCacheSizeInBytes();
        if (bytes < 1024) {
            return bytes + " B";
        } else if (bytes < 1024 * 1024) {
            return String.format("%.2f KiB", bytes / 1024.0);
        } else if (bytes < 1024 * 1024 * 1024) {
            return String.format("%.2f MiB", bytes / (1024.0 * 1024.0));
        } else {
            return String.format("%.2f GiB", bytes / (1024.0 * 1024.0 * 1024.0));
        }
    }

    private void createPrintTabSettings(JPanel panel, boolean isRequest) {
        String currentString = isRequest ? "requests" : "responses";

        JLabel jlabel = new JLabel();
        jlabel.setFont(hackFont);
        jlabel.setText("• Print Tab for " + currentString);
        jlabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        jlabel.setBorder(new EmptyBorder(20, 0, 10, 0));
        panel.add(jlabel);

        // Enable Print Tab checkbox
        JCheckBox enablePrintTab = new JCheckBox(String.format("Enable a read-only Print Tab for %s", currentString),
                config.isPrintEditorEnabled(isRequest));
        enablePrintTab.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(enablePrintTab);

        // Explanation for enable print tab
        JLabel enableExplanation = new JLabel("Useful for taking screenshots");
        enableExplanation.setFont(enableExplanation.getFont().deriveFont(11f));
        enableExplanation.setForeground(Color.GRAY);
        enableExplanation.setAlignmentX(Component.LEFT_ALIGNMENT);
        enableExplanation.setBorder(new EmptyBorder(0, 24, 10, 0));
        panel.add(enableExplanation);

        // Escape double quotes checkbox
        JCheckBox escapeDoubleQuotes = new JCheckBox(
                String.format("Escape double quotes in decoded values within the Print Tab for %s", currentString),
                config.isEscapingDoubleQuotes(isRequest));
        escapeDoubleQuotes.setAlignmentX(Component.LEFT_ALIGNMENT);
        escapeDoubleQuotes.setEnabled(enablePrintTab.isSelected());
        escapeDoubleQuotes.setBorder(new EmptyBorder(0, 20, 0, 0));
        panel.add(escapeDoubleQuotes);

        // Explanation for escape double quotes
        JLabel escapeExplanation = new JLabel("This may improve how the content is displayed");
        escapeExplanation.setFont(escapeExplanation.getFont().deriveFont(11f));
        escapeExplanation.setForeground(Color.GRAY);
        escapeExplanation.setAlignmentX(Component.LEFT_ALIGNMENT);
        escapeExplanation.setBorder(new EmptyBorder(0, 44, 10, 0));
        panel.add(escapeExplanation);

        // Highlight patterns checkbox
        JCheckBox highlightPrintTab = new JCheckBox("Highlight patterns found in Print Tab for " + currentString,
                config.isHighlightingPrintEditor(isRequest));
        highlightPrintTab.setAlignmentX(Component.LEFT_ALIGNMENT);
        highlightPrintTab.setEnabled(enablePrintTab.isSelected());
        highlightPrintTab.setBorder(new EmptyBorder(0, 20, 5, 0));
        panel.add(highlightPrintTab);

        // Color button
        CircularColorButton colorButton = new CircularColorButton("▪ Select a color:", null,
                config.getPrintEditorHighlightColor(isRequest), 20);
        colorButton.setAlignmentX(Component.LEFT_ALIGNMENT);
        colorButton.setEnabled(enablePrintTab.isSelected() && highlightPrintTab.isSelected());
        colorButton.setBorder(new EmptyBorder(0, 20, 0, 0));
        panel.add(colorButton);

        enablePrintTab.addItemListener(state -> {
            boolean isSelected = ((JCheckBox) state.getSource()).isSelected();
            config.updateShowPrintEditor(isSelected, isRequest);
            escapeDoubleQuotes.setEnabled(isSelected);
            highlightPrintTab.setEnabled(isSelected);
            colorButton.setEnabled(isSelected && highlightPrintTab.isSelected());
        });

        escapeDoubleQuotes.addItemListener(state -> {
            boolean isSelected = ((JCheckBox) state.getSource()).isSelected();
            config.updateShouldEscapeDoubleQuotes(isSelected, isRequest);
        });

        highlightPrintTab.addItemListener(state -> {
            boolean isSelected = ((JCheckBox) state.getSource()).isSelected();
            config.updateHighlightPrintEditor(isSelected, isRequest);
            colorButton.setEnabled(isSelected);
        });

        colorButton.setColorAction((color) -> {
            config.updatePrintEditorHighlightColor(color, isRequest);
            return null;
        });
    }

    private int moveRow(DefaultTableModel model, int fromIndex, int toIndex) {
        if (toIndex < 0 || toIndex > model.getRowCount() - 1)
            return fromIndex;
        // Save the row data
        Object[] rowData = new Object[model.getColumnCount()];
        for (int col = 0; col < model.getColumnCount(); col++) {
            rowData[col] = model.getValueAt(fromIndex, col);
        }

        // Remove the row from the current position
        model.removeRow(fromIndex);

        // Insert the row at the new position
        model.insertRow(toIndex, rowData);
        return toIndex;
    }

    private void setPlaceholder(JTextField textField, String placeholder) {
        if (textField.getText().isEmpty()) {
            textField.setText(placeholder); // Placeholder text
            textField.setForeground(Color.GRAY); // Set placeholder text color
        }
        textField.addFocusListener(new FocusAdapter() {
            @Override
            public void focusGained(FocusEvent e) {
                if (textField.getText().equals(placeholder)) {
                    textField.setText("");
                    textField.setForeground(Color.BLACK); // Reset text color
                }
            }

            @Override
            public void focusLost(FocusEvent e) {
                if (textField.getText().isEmpty()) {
                    textField.setText(placeholder);
                    textField.setForeground(Color.GRAY); // Set placeholder text color
                }
            }
        });
    }

    private void updateTable(DefaultTableModel model, Config config, boolean isRequest) {
        // Clear the table and reload all patterns from the config
        model.setRowCount(0);
        var updatedPatterns = config.getPatterns(isRequest);
        for (var updatedPattern : updatedPatterns) {
            // Display human-readable scope value
            String scopeDisplay;
            if (updatedPattern.usesProjectScope()) {
                scopeDisplay = "Project In-Scope";
            } else if (updatedPattern.getURLTargetRegex() == null || updatedPattern.getURLTargetRegex().isEmpty()) {
                scopeDisplay = "Any";
            } else {
                scopeDisplay = updatedPattern.getURLTargetRegex();
            }
            model.addRow(new Object[] { updatedPattern.isEnabled(), updatedPattern.getName(),
                    updatedPattern.getCaptureRegex(), scopeDisplay, updatedPattern.shouldPatchProxy(),
                    updatedPattern.getDecCommand(), updatedPattern.getEncCommand() });
        }

    }

    private JPanel addPanelInternalText(String text, JPanel subpanel) {
        JPanel panel = new JPanel(new GridBagLayout());
        JLabel jlabel = new JLabel();
        jlabel.setFont(hackFont);
        jlabel.setText(text);

        GridBagConstraints constraints = new GridBagConstraints();
        constraints.fill = GridBagConstraints.HORIZONTAL;
        constraints.weightx = 1;
        constraints.gridx = 0;
        constraints.gridy = 0;
        constraints.anchor = GridBagConstraints.NORTH;
        constraints.insets = new Insets(10, 10, 10, 10);

        panel.add(jlabel, constraints);

        constraints.weighty = 1;
        constraints.gridy = 1;
        constraints.insets = new Insets(10, 10, 10, 10);

        panel.add(subpanel, constraints);

        return panel;
    }

}