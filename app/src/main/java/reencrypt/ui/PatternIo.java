package reencrypt.ui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.swing.BorderFactory;
import javax.swing.ButtonGroup;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.DefaultTableModel;

import reencrypt.App;
import reencrypt.CapturePattern;
import reencrypt.Config;
import reencrypt.ConfigJson;

/** Export/import of patterns and settings as JSON, for sharing configuration between installs. */
public class PatternIo {

    private PatternIo() {
    }

    private static final DateTimeFormatter STAMP = DateTimeFormatter.ofPattern("yyyyMMdd");

    /** How to handle an imported pattern whose name already exists. One choice for the whole file. */
    private enum Collision {
        REPLACE, KEEP_BOTH, SKIP
    }

    // ------------------------------------------------------------------ export

    /** Export the given patterns, or the whole config when {@code settings} is non-null. */
    public static void export(Component parent, List<CapturePattern> items, Map<String, Object> settings) {
        if (items.isEmpty() && settings == null) {
            JOptionPane.showMessageDialog(parent, "Nothing to export.", App.name, JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        JCheckBox stripSecrets = new JCheckBox("Strip engine secrets (keys, passphrases) from exported patterns");
        JPanel accessory = new JPanel(new BorderLayout());
        accessory.add(stripSecrets, BorderLayout.NORTH);

        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle(settings == null ? "Export patterns" : "Export all settings");
        chooser.setFileFilter(new FileNameExtensionFilter("JSON files", "json"));
        chooser.setSelectedFile(new File((settings == null ? "reencrypt-patterns-" : "reencrypt-config-")
                + LocalDate.now().format(STAMP) + ".json"));
        chooser.setAccessory(accessory);

        if (chooser.showSaveDialog(parent) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        File file = withJsonExtension(chooser.getSelectedFile());
        try {
            Files.write(file.toPath(),
                    ConfigJson.toFile(items, settings, stripSecrets.isSelected()).getBytes(StandardCharsets.UTF_8));
            JOptionPane.showMessageDialog(parent, "Exported " + items.size() + " pattern(s) to " + file.getName(),
                    App.name, JOptionPane.INFORMATION_MESSAGE);
        } catch (IOException e) {
            JOptionPane.showMessageDialog(parent, "Could not write the file:\n" + e.getMessage(), App.name,
                    JOptionPane.ERROR_MESSAGE);
        }
    }

    /** Every pattern, in table order. */
    public static List<CapturePattern> allPatterns(Config config) {
        return new ArrayList<>(config.getPatterns());
    }

    // ------------------------------------------------------------------ import

    /** What an import actually changed, so the caller refreshes only what needs it. */
    public static class Outcome {
        public boolean patternsChanged;
        public boolean settingsChanged;
    }

    /**
     * Prompt for a file, show what it contains, and apply it.
     *
     * @param withSettings whether the file's settings block is applied by default ("Import all"). The
     *                     dialog offers a checkbox either way when the file carries one.
     */
    public static Outcome importFrom(Component parent, Config config, boolean withSettings) {
        Outcome outcome = new Outcome();
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Import");
        chooser.setFileFilter(new FileNameExtensionFilter("JSON files", "json"));
        if (chooser.showOpenDialog(parent) != JFileChooser.APPROVE_OPTION) {
            return outcome;
        }
        File file = chooser.getSelectedFile();

        ConfigJson.ImportResult result;
        try {
            result = ConfigJson.fromFile(new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8));
        } catch (Exception e) {
            JOptionPane.showMessageDialog(parent, "Could not read the file:\n" + e.getMessage(), App.name,
                    JOptionPane.ERROR_MESSAGE);
            return outcome;
        }

        if (result.patterns.isEmpty() && !result.hasSettings) {
            JOptionPane.showMessageDialog(parent, "The file contains nothing to import.", App.name,
                    JOptionPane.WARNING_MESSAGE);
            return outcome;
        }

        List<String> collisions = collisionNames(config, result.patterns);
        JCheckBox enableImported = new JCheckBox("Enable imported patterns", true);
        // Off by default outside "Import all": a file picked to add patterns should not quietly
        // rewrite the whole configuration. Ticking it makes the settings match the file exactly.
        JCheckBox importSettings = new JCheckBox(
                "Also apply the settings in this file (anything it leaves out goes back to its default)",
                withSettings);
        ButtonGroup group = new ButtonGroup();
        JRadioButton replace = new JRadioButton("Replace existing", true);
        JRadioButton keepBoth = new JRadioButton("Keep both (imported gets a new name)");
        JRadioButton skip = new JRadioButton("Skip imported");

        JPanel panel = new JPanel(new BorderLayout(0, 8));
        panel.add(new JLabel("Import " + result.patterns.size() + " pattern(s) from " + file.getName()),
                BorderLayout.NORTH);
        panel.add(new JScrollPane(previewTable(result.patterns)), BorderLayout.CENTER);

        // Everything in this column is left-aligned explicitly: BoxLayout centres a child that does
        // not say otherwise, which pushes short rows towards the middle of a wide dialog.
        JPanel south = new JPanel();
        south.setLayout(new javax.swing.BoxLayout(south, javax.swing.BoxLayout.Y_AXIS));
        if (!collisions.isEmpty()) {
            JPanel collisionPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
            collisionPanel.setBorder(BorderFactory.createTitledBorder(
                    collisions.size() + " name(s) already exist: " + String.join(", ", collisions)));
            for (JRadioButton b : new JRadioButton[] { replace, keepBoth, skip }) {
                group.add(b);
                collisionPanel.add(b);
            }
            addLeftAligned(south, collisionPanel);
        }
        if (result.hasSettings) {
            addLeftAligned(south, importSettings);
        }
        if (!result.errors.isEmpty()) {
            addLeftAligned(south,
                    new JLabel(result.errors.size() + " entry(ies) could not be read and will be skipped."));
        }
        addLeftAligned(south, enableImported);
        JLabel warning = new JLabel("Review the JSON before importing: files can contain malicious shell commands.");
        warning.setForeground(new Color(0xB0, 0x30, 0x00));
        addLeftAligned(south, warning);
        panel.add(south, BorderLayout.SOUTH);
        panel.setPreferredSize(new Dimension(900, 380));

        int choice = JOptionPane.showConfirmDialog(parent, panel, App.name + " - import",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (choice != JOptionPane.OK_OPTION) {
            return outcome;
        }

        Collision policy = keepBoth.isSelected() ? Collision.KEEP_BOTH : skip.isSelected() ? Collision.SKIP
                : Collision.REPLACE;
        int applied = apply(config, result.patterns, policy, enableImported.isSelected());
        outcome.patternsChanged = applied > 0;

        if (result.hasSettings && importSettings.isSelected()) {
            try {
                config.importSettings(result.settings);
                outcome.settingsChanged = true;
            } catch (Exception e) {
                JOptionPane.showMessageDialog(parent, "Patterns imported, but the settings failed:\n" + e.getMessage(),
                        App.name, JOptionPane.WARNING_MESSAGE);
            }
        }

        String message = "Imported " + applied + " pattern(s)." + (outcome.settingsChanged ? " Settings applied." : "");
        if (!result.errors.isEmpty()) {
            message += "\n\nSkipped:\n" + String.join("\n", result.errors);
        }
        JOptionPane.showMessageDialog(parent, message, App.name, JOptionPane.INFORMATION_MESSAGE);
        return outcome;
    }

    private static void addLeftAligned(JPanel column, javax.swing.JComponent child) {
        child.setAlignmentX(Component.LEFT_ALIGNMENT);
        column.add(child);
    }

    private static int apply(Config config, List<CapturePattern> items, Collision policy, boolean enable) {
        int applied = 0;
        for (CapturePattern pattern : items) {
            // The dialog's checkbox decides this, not the file - an exchange file carries no enabled
            // state. patchProxy is left alone: it is inert while disabled, and overwriting it would
            // discard the author's setting for whenever the user does enable the pattern.
            pattern.setEnabled(enable);
            int existing = indexOfName(config, pattern.getName());
            if (existing >= 0) {
                switch (policy) {
                    case SKIP:
                        continue;
                    case REPLACE:
                        // In place, so a replaced pattern keeps the row it had.
                        config.editPattern(existing, pattern);
                        applied++;
                        continue;
                    case KEEP_BOTH:
                        pattern.setName(uniqueName(config, pattern.getName()));
                        break;
                }
            }
            config.addPattern(pattern);
            applied++;
        }
        return applied;
    }

    private static List<String> collisionNames(Config config, List<CapturePattern> items) {
        List<String> names = new ArrayList<>();
        for (CapturePattern item : items) {
            if (indexOfName(config, item.getName()) >= 0 && !names.contains(item.getName())) {
                names.add(item.getName());
            }
        }
        return names;
    }

    private static int indexOfName(Config config, String name) {
        List<CapturePattern> patterns = config.getPatterns();
        for (int i = 0; i < patterns.size(); i++) {
            if (patterns.get(i).getName().equals(name)) {
                return i;
            }
        }
        return -1;
    }

    private static String uniqueName(Config config, String base) {
        for (int n = 2;; n++) {
            String candidate = base + " (" + n + ")";
            if (indexOfName(config, candidate) < 0) {
                return candidate;
            }
        }
    }

    /**
     * The last column is the point of this table: it is the only place the user sees what code an
     * imported pattern will run, or which local file it will read, before it lands.
     */
    private static JTable previewTable(List<CapturePattern> items) {
        DefaultTableModel model = new DefaultTableModel(
                new Object[] { "Name", "Location", "Target", "Commands / files it will use" }, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        for (CapturePattern p : items) {
            String target = p.usesProjectScope() ? "Project In-Scope"
                    : (p.getURLTargetRegex() == null || p.getURLTargetRegex().isEmpty() ? "Everything"
                            : p.getURLTargetRegex());
            model.addRow(new Object[] { p.getName(), p.isRequest() ? "Request" : "Response", target,
                    riskDisplay(p) });
        }
        JTable table = new JTable(model);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        table.getColumnModel().getColumn(0).setPreferredWidth(140);
        table.getColumnModel().getColumn(1).setPreferredWidth(80);
        table.getColumnModel().getColumn(2).setPreferredWidth(150);
        table.getColumnModel().getColumn(3).setPreferredWidth(500);
        return table;
    }

    /** Engine params whose value is a command or a path when the matching "…Source" says so. */
    private static final String[] SOURCED_PARAMS = { "key", "iv", "publicKey", "privateKey" };

    /**
     * What this pattern will execute or read, e.g. {@code key command: cat ~/.k}. Shared with the
     * settings table's Configuration column so both places describe a pattern the same way.
     *
     * <p>
     * Plain key material is deliberately left out: it is data, not something that runs, and printing
     * a PEM blob per row would bury the entries that can actually do damage.
     * </p>
     */
    static List<String> sourcedInputs(CapturePattern p) {
        List<String> parts = new ArrayList<>();
        Map<String, String> params = p.getEngineParams();
        if (!p.usesEngine() || params == null) {
            return parts;
        }
        for (String name : SOURCED_PARAMS) {
            String source = params.get(name + "Source");
            if ("command".equals(source) || "file".equals(source)) {
                addIfPresent(parts, name + " " + source + ": ", params.get(name));
            }
        }
        return parts;
    }

    /** The same information as one cell, for the import preview. */
    private static String riskDisplay(CapturePattern p) {
        List<String> parts = new ArrayList<>();
        if (!p.usesEngine()) {
            addIfPresent(parts, "decrypt: ", p.getDecCommand());
            addIfPresent(parts, "encrypt: ", p.getEncCommand());
        } else {
            parts.add("engine: " + p.getEngineId());
            parts.addAll(sourcedInputs(p));
        }
        return parts.isEmpty() ? "" : String.join("   |   ", parts);
    }

    private static void addIfPresent(List<String> parts, String label, String value) {
        if (value != null && !value.isBlank()) {
            parts.add(label + value.replace("\n", " "));
        }
    }

    private static File withJsonExtension(File file) {
        return file.getName().toLowerCase().endsWith(".json") ? file : new File(file.getPath() + ".json");
    }
}
