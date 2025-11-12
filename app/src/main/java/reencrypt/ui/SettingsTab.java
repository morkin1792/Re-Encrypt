package reencrypt.ui;

import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableColumnModel;

import reencrypt.CapturePattern;
import reencrypt.Config;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.GridLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Arrays;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextField;
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

        tabbedPane.add("(TODO) WebSockets ", null);
        tabbedPane.setEnabledAt(1, false);

        tabbedPane.add("Extra Settings", createSettingsScreen());

        return tabbedPane;
    }

    private JPanel createCaptureDataScreen() {
        JPanel subpanel = new JPanel(new GridLayout(1, 3));
        subpanel.add(createCaptureDataTable("Request", true));
        subpanel.add(createCaptureDataTable("Response", false));
        return addPanelInternalText("• Set regexs to define what will be re:encrypted / re:encoded", subpanel);
    }

    private JPanel createCaptureDataTable(String title, boolean isRequest) {

        JPanel panel = new JPanel(new BorderLayout());
        JLabel jlabel = new JLabel();
        jlabel.setFont(hackFont);
        jlabel.setText(title);
        panel.add(jlabel, BorderLayout.NORTH);

        Object[] tableColumnName = new Object[] { "Enabled", "Name", "Pattern Regex", "Target", "Patch Proxy",
                "Dec(ode|rypt) Command", "Enc(ode|rypt) Command" };

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
        updateTable(
                model,
                config,
                isRequest);
        JTable table = new JTable(model);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        TableColumnModel columnModel = table.getColumnModel();
        columnModel.getColumn(0).setPreferredWidth(60); // "Enabled"
        columnModel.getColumn(1).setPreferredWidth(70); // "Name"
        columnModel.getColumn(2).setPreferredWidth(100); // "Pattern Regex"
        columnModel.getColumn(3).setPreferredWidth(50); // "Target"
        columnModel.getColumn(4).setPreferredWidth(50); // "Patch Proxy"
        columnModel.getColumn(5).setPreferredWidth(300); // "Decode|Crypt"
        columnModel.getColumn(6).setPreferredWidth(300); // "Encode|Crypt"

        JScrollPane scrollPane = new JScrollPane(table);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        panel.add(scrollPane);

        // Adding buttons
        JButton addButton = new JButton("Add");
        addButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {

                var newPattern = createOrEditPatternPopup(isRequest);
                if (newPattern == null) {
                    return; // User cancelled the dialog
                }
                config.addPattern(newPattern, isRequest);

                updateTable(
                        model,
                        config,
                        isRequest);
            }
        });

        JButton editButton = new JButton("Edit");
        editButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int index = table.getSelectedRow();
                if (index != -1) {
                    var modifiedPattern = createOrEditPatternPopup(
                            config.getPatterns(isRequest).get(index), isRequest);
                    if (modifiedPattern == null) {
                        return; // User cancelled the dialog
                    }

                    config.editPattern(index, modifiedPattern, isRequest);
                    updateTable(
                            model,
                            config,
                            isRequest);
                }
            }
        });

        JButton cloneButton = new JButton("Clone");
        cloneButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {

                int index = table.getSelectedRow();
                if (index != -1) {
                    // cloning the selected pattern
                    config.clonePattern(index, isRequest);
                    updateTable(
                            model,
                            config,
                            isRequest);

                    // moving the cloned pattern
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
        });

        JButton removeButton = new JButton("Remove");
        removeButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int[] selectedRows = table.getSelectedRows();
                Arrays.sort(selectedRows);
                for (int auxIndex = selectedRows.length - 1; auxIndex >= 0; auxIndex--) {
                    int selectedRowIndex = selectedRows[auxIndex];
                    config.removePattern(selectedRowIndex, isRequest);
                }
                updateTable(
                        model,
                        config,
                        isRequest);
            }
        });

        JButton upButton = new JButton("Up");
        upButton.addActionListener(new ActionListener() {
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
        });

        JButton downButton = new JButton("Down");
        downButton.addActionListener(new ActionListener() {
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
        });

        JPanel buttonPanel = new JPanel(new GridLayout(8, 2));
        buttonPanel.add(addButton);
        buttonPanel.add(cloneButton);
        buttonPanel.add(editButton);
        buttonPanel.add(removeButton);
        buttonPanel.add(upButton);
        buttonPanel.add(downButton);
        buttonPanel.setBorder(new EmptyBorder(1, 1, 1, 1));

        panel.add(buttonPanel, BorderLayout.EAST);

        return panel;
    }

    private CapturePattern createOrEditPatternPopup(boolean isRequest) {
        return createOrEditPatternPopup(null, isRequest);
    }

    private CapturePattern createOrEditPatternPopup(CapturePattern existingPattern, boolean isRequest) {
        CapturePattern pattern = null;

        JPanel panel = new JPanel(new GridLayout(0, 1));

        JTextField nameField = new JTextField();
        nameField.setToolTipText("Enter a name for the pattern.");
        panel.add(new JLabel("Tab Name"));
        panel.add(nameField);

        JTextField regexField = new JTextField();
        regexField.setToolTipText("Enter the regex to match the part of the data you want to capture.");
        panel.add(new JLabel("Pattern Regex (then, case sensitive)"));
        panel.add(regexField);

        JTextField scopeField = new JTextField();
        scopeField.setToolTipText(
                "Enter a regex to filter the URLs where this pattern will be applied. Leave empty to apply to all URLs.");
        panel.add(new JLabel("Target URL Regex "));
        panel.add(scopeField);

        JTextField decCommand = new JTextField();
        decCommand.setToolTipText(
                "Enter the command to decrypt/decode the captured data. Use {DATA} to refer to the captured group, or {FILE} to refer to a temporary file containing the captured group.");
        panel.add(new JLabel("Decode Command"));
        panel.add(decCommand);

        JTextField encCommand = new JTextField();
        encCommand.setToolTipText(
                "Enter the command to encrypt/encode the captured data. Use {DATA} to refer to the captured group, or {FILE} to refer to a temporary file containing the captured group.");
        panel.add(new JLabel("Encode Command"));
        panel.add(encCommand);

        JCheckBox enabledCheckbox = new JCheckBox("Pattern enabled", true);
        panel.add(enabledCheckbox);

        JCheckBox patchProxyCheckbox = new JCheckBox(
                "Automatically patch proxy " + (isRequest ? "requests" : "responses")
                        + " (Content-Length will be updated when a patch happens)",
                false);
        panel.add(patchProxyCheckbox);

        if (existingPattern != null) {
            // If editing an existing pattern, populate the fields with its data
            regexField.setText(existingPattern.getPatternRegex());
            scopeField.setText(existingPattern.getURLTargetRegex());
            nameField.setText(existingPattern.getName());
            encCommand.setText(existingPattern.getEncCommand());
            decCommand.setText(existingPattern.getDecCommand());
            enabledCheckbox.setSelected(existingPattern.isEnabled());
            patchProxyCheckbox.setSelected(existingPattern.getPatchProxy());
        } else {
            // If creating a new pattern, set placeholders
            // setPlaceholder(regexField, "data\":\"(.*?)\"");
            setPlaceholder(nameField, "UA");
            setPlaceholder(regexField, "User-Agent: (.*)");
            setPlaceholder(scopeField, "^http[s]?\\:\\/\\/.*");
            setPlaceholder(encCommand, "cat {FILE} ");
            setPlaceholder(decCommand, "cat {FILE} ");
        }

        String[] options = { "OK", "Cancel" };

        JOptionPane optionPane = new JOptionPane(panel,
                JOptionPane.PLAIN_MESSAGE,
                JOptionPane.OK_CANCEL_OPTION,
                null,
                options,
                options[0]);

        JDialog dialog = optionPane.createDialog("Add New Pattern");
        dialog.setVisible(true);

        Object selectedValue = optionPane.getValue();

        if ("OK".equals(selectedValue)) {
            String regex = regexField.getText();
            if (regex != null && !regex.isEmpty()) {
                String name = nameField.getText();
                if (name == null || name.isEmpty()) {
                    name = "Pattern " + (config.getPatterns(isRequest).size() + 1);
                }
                pattern = new CapturePattern(
                        name,
                        regex,
                        scopeField.getText(),
                        decCommand.getText(),
                        encCommand.getText(),
                        enabledCheckbox.isSelected(),
                        patchProxyCheckbox.isSelected());
            } else {
                JOptionPane.showMessageDialog(null, "You HAVE TO define a pattern regex.", "Error",
                        JOptionPane.ERROR_MESSAGE);
            }
        }
        return pattern;
    }

    private JPanel createSettingsScreen() {
        JPanel painelBorderLayout = new JPanel(new BorderLayout());
        JPanel panel = new JPanel(new GridLayout(15, 1));

        // TODO: remove this setting?
        JCheckBox saveCommands = new JCheckBox(
                "Save the commands used to decrypt / decode. Recommended if you need to update them often.",
                config.shouldSaveCommands());
        saveCommands.addItemListener(state -> {
            boolean isSelected = ((JCheckBox) state.getSource()).isSelected();
            config.updateSaveCommands(isSelected);
        });
        saveCommands.setEnabled(false);
        panel.add(saveCommands);

        createPrintTabSettings(panel, true);
        createPrintTabSettings(panel, false);

        painelBorderLayout.add(panel, BorderLayout.NORTH);

        return addPanelInternalText("• Optionally, adjust the settings", painelBorderLayout);
    }

    private void createPrintTabSettings(JPanel panel, boolean isRequest) {
        String currentString = isRequest ? "requests" : "responses";
        panel.add(new JLabel(), BorderLayout.NORTH);
        JLabel jlabel = new JLabel();
        jlabel.setFont(hackFont);
        jlabel.setText("Print Tab for " + currentString);
        panel.add(jlabel, BorderLayout.NORTH);
        JCheckBox enablePrintTab = new JCheckBox(
                String.format("Enable a read-only Print Tab for %s. Useful for taking screenshots.", currentString),
                config.isPrintEditorEnabled(isRequest));
        JCheckBox escapeDoubleQuotes = new JCheckBox(
                String.format("Escape double quotes in decoded values within the Print Tab for %s. This may improve how the content is displayed.", currentString),
                config.isEscapingDoubleQuotes(isRequest));
        escapeDoubleQuotes.setEnabled(enablePrintTab.isSelected());
        JCheckBox highlightPrintTab = new JCheckBox(
                "Highlight patterns found in Print Tab for " + currentString,
                config.isHighlightingPrintEditor(isRequest));
        highlightPrintTab.setEnabled(enablePrintTab.isSelected());
        CircularColorButton colorButton = new CircularColorButton("▪ Select a color:", null, config.getPrintEditorHighlightColor(isRequest), 20);
        colorButton.setEnabled(enablePrintTab.isSelected() && highlightPrintTab.isSelected());

        enablePrintTab.addItemListener(state -> {
            boolean isSelected = ((JCheckBox) state.getSource()).isSelected();
            config.updateShowPrintEditor(isSelected, isRequest);
            escapeDoubleQuotes.setEnabled(isSelected);
            highlightPrintTab.setEnabled(isSelected);
            colorButton.setEnabled(isSelected && highlightPrintTab.isSelected());
        });
        panel.add(enablePrintTab);

        escapeDoubleQuotes.addItemListener(state -> {
            boolean isSelected = ((JCheckBox) state.getSource()).isSelected();
            config.updateShouldEscapeDoubleQuotes(isSelected, isRequest);
        });
        escapeDoubleQuotes.setBorder(BorderFactory.createEmptyBorder(0, 20, 0, 0));
        panel.add(escapeDoubleQuotes);
        
        highlightPrintTab.addItemListener(state -> {
            boolean isSelected = ((JCheckBox) state.getSource()).isSelected();
            config.updateHighlightPrintEditor(isSelected, isRequest);
            colorButton.setEnabled(isSelected);
        });
        
        highlightPrintTab.setBorder(BorderFactory.createEmptyBorder(0, 20, 0, 0));
        panel.add(highlightPrintTab);

        colorButton.setColorAction((color) -> {
            config.updatePrintEditorHighlightColor(color, isRequest);
            return null;
        });
        colorButton.setBorder(BorderFactory.createEmptyBorder(0, 20, 0, 0));
        panel.add(colorButton);
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
        textField.setText(placeholder); // Placeholder text
        textField.setForeground(Color.GRAY); // Set placeholder text color
        textField.addFocusListener(new java.awt.event.FocusAdapter() {
            @Override
            public void focusGained(java.awt.event.FocusEvent e) {
                if (textField.getText().equals(placeholder)) {
                    textField.setText("");
                    textField.setForeground(Color.BLACK); // Reset text color
                }
            }

            @Override
            public void focusLost(java.awt.event.FocusEvent e) {
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
            model.addRow(new Object[] {
                    updatedPattern.isEnabled(),
                    updatedPattern.getName(),
                    updatedPattern.getPatternRegex(),
                    updatedPattern.getURLTargetRegex(),
                    updatedPattern.getPatchProxy(),
                    updatedPattern.getDecCommand(),
                    updatedPattern.getEncCommand()
            });
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