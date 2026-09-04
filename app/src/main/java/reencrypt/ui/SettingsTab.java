package reencrypt.ui;

import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableColumnModel;

import burp.api.montoya.MontoyaApi;
import reencrypt.CapturePattern;
import reencrypt.AutoLoader;
import reencrypt.Config;
import reencrypt.PatternType;
import reencrypt.engine.CryptoEngine;
import reencrypt.engine.CryptoEngineRegistry;

import javax.swing.event.DocumentEvent;
import javax.swing.event.TableModelEvent;
import javax.swing.event.DocumentListener;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Frame;
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
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.WindowConstants;
import javax.swing.JSpinner;
import javax.swing.SpinnerNumberModel;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.JComboBox;
import javax.swing.JRadioButton;
import javax.swing.ButtonGroup;
import javax.swing.KeyStroke;
import javax.swing.JSplitPane;
import javax.swing.JTextArea;
import javax.swing.BorderFactory;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.UIManager;
import javax.swing.border.EmptyBorder;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import reencrypt.analysis.CipherAnalyzer;
import reencrypt.analysis.Suggestion;

public class SettingsTab {
    private static final Color ERROR_COLOR = new Color(200, 50, 50);
    // Exact same color used for the cache-fallback ("Using CACHED output...") info alert
    private static final Color INFO_COLOR = reencrypt.Utils.hexToColor("#f09e2cff");
    private Font hackFont = new Font("Hack", Font.BOLD, 18);
    private MontoyaApi api;
    private Config config;
    // Guards the table's model listener against programmatic rebuilds in updateTable
    private boolean suppressTableEvents;
    // Single combined patterns table, kept so the Analyze tab can refresh it
    private DefaultTableModel patternModel;
    private JTable patternTable;
    // Analyze tab wiring (set in createAnalyzeScreen)
    private static final String SETTINGS_TAB_TITLE = "General Settings";
    private JTabbedPane mainTabbedPane;
    private JFrame analyzeWindow;
    private MarkerEditor analyzeEditor;
    private JPanel analyzeResultsPanel;
    private AutoLoader autoLoader;
    private char currentSplitDelimiter; // delimiter of the split currently shown, or '\0'
    private String analyzeUrl; // URL the analyzer's content came from, for seeding a pattern's target
    private javax.swing.Timer autoLoadStatusTimer;

    public SettingsTab(MontoyaApi api, Config config) {
        this.api = api;
        this.config = config;
    }

    public void setAutoLoader(AutoLoader autoLoader) {
        this.autoLoader = autoLoader;
        // Auto-load runs on its own thread, so the table has to be told; Swing work goes to the EDT.
        autoLoader.setOnReload(() -> SwingUtilities.invokeLater(this::reloadPatternTable));
    }

    /**
     * The tab tree, built once. Rebuilding it would re-point patternModel/patternTable at a fresh,
     * invisible table, so every later refresh would update a discarded copy - this is also the dialog
     * parent for the export/import prompts.
     */
    public Component uiComponent() {
        if (mainTabbedPane != null) {
            return mainTabbedPane;
        }
        JTabbedPane tabbedPane = new JTabbedPane();
        this.mainTabbedPane = tabbedPane;

        tabbedPane.add("Capturing + Processing", createCaptureDataScreen());

        tabbedPane.add("Intruder Settings", createIntruderScreen());

        tabbedPane.add("(TODO) WebSockets ", null);
        tabbedPane.setEnabledAt(tabbedPane.getTabCount() - 1, false);

        tabbedPane.add(SETTINGS_TAB_TITLE, createSettingsScreen());

        return tabbedPane;
    }

    // ===== Analyze Ciphertext tab =====

    private Component createAnalyzeScreen() {
        JPanel panel = new JPanel(new BorderLayout());

        JPanel header = new JPanel();
        header.setLayout(new BoxLayout(header, BoxLayout.Y_AXIS));
        header.setBorder(new EmptyBorder(10, 10, 6, 10));
        JLabel title = new JLabel("• Identify which Encryption Mode + config to use");
        title.setFont(hackFont);
        title.setAlignmentX(Component.LEFT_ALIGNMENT);
        title.setBorder(new EmptyBorder(0, 0, 8, 0));
        header.add(title);
        JLabel hint = new JLabel("Paste a ciphertext below, or right-click a request/response (or a selection) "
                + "in any Burp tool and choose \"Analyze ciphertext using Re:Encrypt\".");
        hint.setFont(hint.getFont().deriveFont(11f));
        hint.setForeground(Color.GRAY);
        hint.setAlignmentX(Component.LEFT_ALIGNMENT);
        header.add(hint);
        panel.add(header, BorderLayout.NORTH);

        analyzeEditor = new MarkerEditor(config);
        analyzeEditor.setOnAnalyze(this::runAnalysis);

        analyzeResultsPanel = new JPanel();
        analyzeResultsPanel.setLayout(new BoxLayout(analyzeResultsPanel, BoxLayout.Y_AXIS));
        JScrollPane resultsScroll = new JScrollPane(analyzeResultsPanel);
        resultsScroll.setBorder(BorderFactory.createTitledBorder("Analysis"));
        // Keep both sides usable: the empty results panel must not collapse to zero width
        resultsScroll.setMinimumSize(new Dimension(300, 0));
        analyzeEditor.setMinimumSize(new Dimension(320, 0));
        analyzeEditor.setBorder(BorderFactory.createTitledBorder("Ciphertext")); // gray contour, like Analysis

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, analyzeEditor, resultsScroll);
        split.setResizeWeight(0.55);
        split.setBorder(new EmptyBorder(0, 10, 10, 10));
        // Set the initial divider once the split actually has a width (ratios are ignored before that)
        split.addComponentListener(new java.awt.event.ComponentAdapter() {
            private boolean done;

            @Override
            public void componentResized(java.awt.event.ComponentEvent e) {
                if (!done && split.getWidth() > 0) {
                    done = true;
                    split.setDividerLocation(0.55);
                }
            }
        });
        panel.add(split, BorderLayout.CENTER);

        return panel;
    }

    /** Re-run analysis on the editor's current ciphertext and rebuild the results panel. */
    private void runAnalysis() {
        if (analyzeEditor == null || analyzeResultsPanel == null) {
            return;
        }
        String ct = analyzeEditor.getCurrentCiphertext();
        analyzeResultsPanel.removeAll();

        // Nothing marked → don't analyze the whole text; prompt the user to mark a region
        if (ct == null || ct.isBlank()) {
            JLabel hint = new JLabel("Mark the ciphertext with Add or Auto to analyze it.");
            hint.setForeground(Color.GRAY);
            hint.setAlignmentX(Component.LEFT_ALIGNMENT);
            hint.setBorder(new EmptyBorder(6, 6, 6, 6));
            analyzeResultsPanel.add(hint);
            analyzeResultsPanel.add(Box.createVerticalGlue());
            analyzeResultsPanel.revalidate();
            analyzeResultsPanel.repaint();
            return;
        }

        CipherAnalyzer.AnalysisResult result = CipherAnalyzer.analyze(ct);
        boolean actionable = result.suggestions.stream().anyMatch(Suggestion::isActionable);

        // If a single value yields nothing useful, it may be several ciphertexts concatenated.
        CipherAnalyzer.SplitResult sr = actionable ? null : CipherAnalyzer.bestSplit(ct);
        currentSplitDelimiter = (sr != null && sr.parts.size() >= 2) ? sr.delimiter : '\0';
        if (sr != null && sr.parts.size() >= 2) {
            JTabbedPane parts = new JTabbedPane();
            int cipherCount = 0;
            for (int i = 0; i < sr.parts.size(); i++) {
                String seg = sr.parts.get(i);
                CipherAnalyzer.AnalysisResult pr = CipherAnalyzer.analyze(seg);
                boolean isCipher = pr.suggestions.stream().anyMatch(Suggestion::isActionable);
                if (isCipher) {
                    cipherCount++;
                }
                JPanel pc = new JPanel();
                pc.setLayout(new BoxLayout(pc, BoxLayout.Y_AXIS));
                renderAnalysisInto(pc, seg, pr, i, sr.parts.size(), isCipher);
                parts.addTab("Part " + (i + 1) + (isCipher ? " ✓" : ""), pc);
                parts.setToolTipTextAt(i, segmentPreview(seg));
            }

            String cipherNote = cipherCount == 0 ? "none clearly look like ciphertext"
                    : cipherCount == 1 ? "1 part looks like ciphertext"
                            : cipherCount + " parts look like ciphertext";
            JTextArea note = new JTextArea("This value splits into " + sr.parts.size() + " parts ("
                    + sr.reason + "); " + cipherNote + ". Analyzing each part below.");
            note.setEditable(false);
            note.setLineWrap(true);
            note.setWrapStyleWord(true);
            note.setOpaque(false);
            note.setBorder(new EmptyBorder(6, 6, 2, 6));
            note.setForeground(Color.GRAY);
            note.setFont(note.getFont().deriveFont(11f));

            // BorderLayout keeps the note at its natural height (no vertical stretch) above the tabs
            JPanel multi = new JPanel(new BorderLayout(0, 2));
            multi.setAlignmentX(Component.LEFT_ALIGNMENT);
            multi.add(note, BorderLayout.NORTH);
            multi.add(parts, BorderLayout.CENTER);
            analyzeResultsPanel.add(multi);
        } else {
            renderAnalysisInto(analyzeResultsPanel, ct, result, -1, 0, false);
        }

        analyzeResultsPanel.revalidate();
        analyzeResultsPanel.repaint();
    }

    /**
     * Render the analysis of {@code ct} into {@code container}; partTotal &gt; 1 marks one segment
     * of a split value. Layout: the header (part info + summary) takes only the height it needs
     * at the top; the guesses share the remaining height equally; the AI button sits at the
     * bottom.
     */
    private void renderAnalysisInto(JPanel container, String ct, CipherAnalyzer.AnalysisResult result,
            int partIndex, int partTotal, boolean isCiphertext) {
        JPanel body = new JPanel(new BorderLayout(0, 4));
        body.setAlignmentX(Component.LEFT_ALIGNMENT);

        // NORTH: header (only as tall as it needs to be)
        JPanel top = new JPanel();
        top.setLayout(new BoxLayout(top, BoxLayout.Y_AXIS));
        if (partTotal > 1 && ct != null) {
            String shown = ct.length() > 140 ? ct.substring(0, 140) + "… (" + ct.length() + " chars)" : ct;
            String tag = isCiphertext ? "ciphertext" : "not detected as ciphertext";
            JTextArea seg = new JTextArea(
                    "Part " + (partIndex + 1) + " of " + partTotal + " — " + tag + ":  " + shown);
            seg.setEditable(false);
            seg.setFocusable(false);
            seg.setLineWrap(true);
            seg.setWrapStyleWord(false);
            seg.setOpaque(false);
            seg.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
            seg.setForeground(new Color(110, 110, 110));
            seg.setBorder(new EmptyBorder(6, 6, 4, 6));
            seg.setAlignmentX(Component.LEFT_ALIGNMENT);
            top.add(seg);
        }
        JLabel summary = new JLabel(String.format("Encoding: %s  ·  length: %d  ·  decoded: %s",
                result.outerEncoding, result.rawLength,
                result.decodedLength < 0 ? "n/a" : String.valueOf(result.decodedLength)));
        summary.setFont(summary.getFont().deriveFont(11f));
        summary.setForeground(Color.GRAY);
        summary.setAlignmentX(Component.LEFT_ALIGNMENT);
        summary.setBorder(new EmptyBorder(6, 6, 6, 6));
        top.add(summary);
        body.add(top, BorderLayout.NORTH);

        // CENTER: the guesses, sharing the remaining height equally
        if (result.suggestions.isEmpty()) {
            JLabel none = new JLabel("No confident match — try selecting a different region, or Copy AI prompt.");
            none.setForeground(Color.GRAY);
            none.setBorder(new EmptyBorder(0, 6, 6, 6));
            body.add(none, BorderLayout.CENTER);
        } else {
            JPanel cards = new JPanel(new GridLayout(0, 1, 0, 6));
            for (Suggestion s : result.suggestions) {
                cards.add(buildSuggestionCard(s, partIndex, partTotal));
            }
            body.add(cards, BorderLayout.CENTER);
        }

        // SOUTH: AI prompt
        JPanel aiRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        JButton copyPrompt = new JButton("Copy AI prompt");
        copyPrompt.setToolTipText("Copy a ready-made analysis prompt to paste into any external LLM");
        copyPrompt.addActionListener(e -> {
            String prompt = CipherAnalyzer.buildAiPrompt(ct, result);
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(prompt), null);
            copyPrompt.setText("Copied!");
            Timer t = new Timer(1200, ev -> copyPrompt.setText("Copy AI prompt"));
            t.setRepeats(false);
            t.start();
        });
        aiRow.add(copyPrompt);
        body.add(aiRow, BorderLayout.SOUTH);

        container.add(body);
    }

    private JComponent buildSuggestionCard(Suggestion s, int partIndex, int partTotal) {
        JPanel card = new JPanel();
        card.setLayout(new BoxLayout(card, BoxLayout.Y_AXIS));
        card.setAlignmentX(Component.LEFT_ALIGNMENT);
        card.setBorder(BorderFactory.createTitledBorder(s.getTitle() + "  (" + s.getConfidence() + "%)"));

        JTextArea expl = new JTextArea(s.getExplanation());
        expl.setEditable(false);
        expl.setLineWrap(true);
        expl.setWrapStyleWord(true);
        expl.setOpaque(false);
        expl.setBorder(null);
        expl.setFocusable(true); // allow the user to select & copy the text
        expl.setFont(UIManager.getFont("Label.font"));
        expl.setAlignmentX(Component.LEFT_ALIGNMENT);
        card.add(expl);

        if (s.isActionable()) {
            card.add(Box.createVerticalStrut(4));
            JButton create = new JButton("Create pattern");
            create.setAlignmentX(Component.LEFT_ALIGNMENT);
            create.addActionListener(e -> createPatternFromSuggestion(s, partIndex, partTotal));
            card.add(create);
        }
        return card;
    }

    /** A compact one-line preview of a segment, used as the Part tab tooltip. */
    private static String segmentPreview(String s) {
        if (s == null) {
            return "";
        }
        String one = s.replaceAll("\\s+", "");
        return one.length() > 90 ? one.substring(0, 90) + "… (" + one.length() + " chars)" : one;
    }

    private void createPatternFromSuggestion(Suggestion s, int partIndex, int partTotal) {
        if (!s.isActionable()) {
            return;
        }
        // Default the location to whatever the editor is showing; seed a Custom Regex from the selection.
        boolean isRequest = analyzeEditor == null || !analyzeEditor.isShowingResponse();
        String seedRegex = null;
        if (analyzeEditor != null) {
            seedRegex = partTotal > 1
                    ? analyzeEditor.getCaptureRegexForPart(partIndex, partTotal, currentSplitDelimiter)
                    : analyzeEditor.getCaptureRegex();
        }
        String seedName = config.generateUniqueName("Analyzed pattern");
        CapturePattern r = createOrEditPatternPopup(null, isRequest, s.getEngineId(), s.getEngineParams(), seedRegex,
                seedName, seedTarget());
        if (r != null) {
            config.addPattern(r);
            reloadPatternTable();
        }
    }

    /**
     * A target-scope regex for a pattern built in the analyzer: the host of the message the window was
     * filled from, dots escaped. It works for a response too, since the host comes from the URL rather
     * than from the text on screen.
     *
     * <p>
     * The window is reused, so its content can outlive that URL - if the text on screen is an HTTP
     * request naming a different Host, the two disagree and nothing is pre-filled rather than
     * scoping the pattern to the wrong site.
     * </p>
     */
    private String seedTarget() {
        return targetRegexFor(analyzeUrl, analyzeEditor == null ? null : analyzeEditor.getVisibleText());
    }

    /** @see #seedTarget() */
    static String targetRegexFor(String url, String shownText) {
        String host = hostOf(url);
        if (host == null) {
            return null;
        }
        String shown = hostHeaderIn(shownText);
        if (shown != null && !shown.equalsIgnoreCase(host)) {
            return null;
        }
        return host.replace(".", "\\.");
    }

    private static String hostOf(String url) {
        try {
            String host = url == null ? null : java.net.URI.create(url).getHost();
            return host == null || host.isEmpty() ? null : host;
        } catch (Exception e) {
            return null;
        }
    }

    /** The Host header of an HTTP request in the given text, port stripped, or null. */
    private static String hostHeaderIn(String text) {
        if (text == null) {
            return null;
        }
        Matcher m = Pattern.compile("(?im)^Host:[ \\t]*([^\\r\\n:]+)").matcher(text);
        return m.find() ? m.group(1).trim() : null;
    }

    /**
     * Show the ciphertext analyzer in its own window. Built once and reused, so the analysis state
     * survives being closed and reopened.
     */
    private void showAnalyzeWindow() {
        if (analyzeWindow == null) {
            analyzeWindow = new JFrame("Re:Encrypt - Analyze Ciphertext");
            analyzeWindow.setDefaultCloseOperation(WindowConstants.HIDE_ON_CLOSE);
            analyzeWindow.setContentPane((JComponent) createAnalyzeScreen());
            analyzeWindow.setSize(1100, 700);
            analyzeWindow.setLocationRelativeTo(mainTabbedPane);
        }
        analyzeWindow.setVisible(true);
        analyzeWindow.setExtendedState(analyzeWindow.getExtendedState() & ~Frame.ICONIFIED);
        analyzeWindow.toFront();
        analyzeWindow.requestFocus();
    }

    /** Entry point used by the context-menu provider for a sent request (+ optional response). */
    public void analyzeRequestResponse(String requestText, boolean hasResponse, String responseText, String url) {
        SwingUtilities.invokeLater(() -> {
            showAnalyzeWindow();
            analyzeUrl = url;
            if (analyzeEditor != null) {
                analyzeEditor.setContent(requestText, hasResponse, responseText);
            }
        });
    }

    /** Entry point for a pasted/selected ciphertext string. */
    public void analyzePasted(String text, String url) {
        SwingUtilities.invokeLater(() -> {
            showAnalyzeWindow();
            analyzeUrl = url;
            if (analyzeEditor != null) {
                analyzeEditor.setPastedContent(text);
            }
        });
    }

    private JPanel createCaptureDataScreen() {
        return addPanelInternalText("Add patterns to define what will be re:encrypted / re:encoded",
                createCombinedPatternTable());
    }


    /** Start, restart or stop the poll thread to match the stored auto-load settings. */
    private void syncAutoLoader() {
        if (autoLoader == null) {
            return;
        }
        if (config.isAutoLoadEnabled()) {
            autoLoader.start(config.getAutoLoadPath(), config.getAutoLoadIntervalSeconds());
        } else {
            autoLoader.stop();
        }
    }

    /** Refresh whichever part of the UI the import actually touched. */
    private void applyImport(PatternIo.Outcome outcome) {
        if (outcome.patternsChanged) {
            reloadPatternTable();
        }
        if (outcome.settingsChanged) {
            reloadSettingsScreen();
            // An imported config can switch auto-load on, off, or onto another file.
            syncAutoLoader();
        }
    }

    /** Rows are the pattern list itself: one table, request and response patterns freely mixed. */
    private void reloadPatternTable() {
        if (patternModel == null) {
            return;
        }
        suppressTableEvents = true;
        try {
            patternModel.setRowCount(0);
            for (CapturePattern p : config.getPatterns()) {
                patternModel.addRow(new Object[] { p.isEnabled(), p.getName(),
                        p.isRequest() ? "Request" : "Response", p.getCaptureRegex(), scopeDisplay(p),
                        p.shouldPatchProxy() ? "Yes" : "No", configDisplay(p) });
            }
        } finally {
            suppressTableEvents = false;
        }
    }

    /**
     * Rebuild the General Settings tab so its fields show the imported values. The widgets read config
     * only while being created, so there is nothing lighter than recreating them.
     */
    private void reloadSettingsScreen() {
        if (mainTabbedPane == null) {
            return;
        }
        int index = mainTabbedPane.indexOfTab(SETTINGS_TAB_TITLE);
        if (index < 0) {
            return;
        }
        // Deferred: this runs from a listener on a component inside the panel being replaced.
        SwingUtilities.invokeLater(() -> mainTabbedPane.setComponentAt(index, createSettingsScreen()));
    }

    private String scopeDisplay(CapturePattern p) {
        if (p.usesProjectScope()) {
            return "Project In-Scope";
        }
        String u = p.getURLTargetRegex();
        if (u == null || u.isEmpty()) {
            return "Everything";
        }
        return u;
    }

    /** Single "Configuration" column: engine details (or both custom commands), with a warning prefix
     *  when something required is missing (empty commands, missing key/iv/public/private, ...). */
    private String configDisplay(CapturePattern p) {
        String base;
        String warn = null;
        if (p.usesEngine()) {
            CryptoEngine engine = CryptoEngineRegistry.get(p.getEngineId());
            String engineName = engine != null ? engine.getDisplayName() : p.getEngineId();
            HashMap<String, String> ep = p.getEngineParams();
            StringBuilder d = new StringBuilder("[").append(engineName).append("] ");
            if (ep != null && "aes".equals(p.getEngineId())) {
                String mode = ep.getOrDefault("mode", "");
                if (!mode.isEmpty()) {
                    d.append(mode);
                }
                String padding = ep.getOrDefault("padding", "");
                if (!padding.isEmpty() && ("CBC".equals(mode) || "ECB".equals(mode))) {
                    d.append("/").append(padding.replace("Padding", ""));
                }
                switch (ep.getOrDefault("ciphertextStructure", "raw")) {
                case "iv_ct": d.append(" (IV+CT)"); break;
                case "iv_ct_tag": d.append(" (IV+CT+Tag)"); break;
                case "openssl": d.append(" (OpenSSL)"); break;
                case "jwe": d.append(" (JWE)"); break;
                default: break;
                }
            } else if (ep != null && "rsa".equals(p.getEngineId())) {
                d.append(ep.getOrDefault("encryptionScheme", "PKCS1"));
            }
            base = d.toString();
            // Same detail the import dialog shows: what this pattern runs or reads to get its keys.
            List<String> sourced = PatternIo.sourcedInputs(p);
            if (!sourced.isEmpty()) {
                base = base + "  ·  " + String.join("  ·  ", sourced);
            }
            warn = warningFor(true, engine, ep, null, null);
        } else {
            String dec = p.getDecCommand() == null ? "" : p.getDecCommand();
            String enc = p.getEncCommand() == null ? "" : p.getEncCommand();
            base = dec.equals(enc) ? dec : "decrypt: " + dec + "    encrypt: " + enc;
            warn = warningFor(false, null, null, dec, enc);
        }
        return warn != null ? "⚠ " + warn + "  ·  " + base : base;
    }

    /**
     * The configuration warning for a pattern (missing key/IV/public/private key for engines, or
     * empty decrypt/encrypt commands for Custom Command), or {@code null} when nothing is wrong.
     * Shared by the Configuration column and the Add/Edit Pattern dialog so the wording matches.
     */
    private static String warningFor(boolean usesEngine, CryptoEngine engine, HashMap<String, String> ep, String dec,
            String enc) {
        if (usesEngine) {
            return engine != null ? engine.validate(ep) : "unknown engine";
        }
        boolean db = dec == null || dec.isBlank();
        boolean eb = enc == null || enc.isBlank();
        if (db && eb) {
            return "decrypt/encrypt commands are empty";
        }
        if (db) {
            return "decrypt command is empty";
        }
        if (eb) {
            return "encrypt command is empty";
        }
        return null;
    }

    private static String capitalize(String s) {
        return (s == null || s.isEmpty()) ? s : Character.toUpperCase(s.charAt(0)) + s.substring(1);
    }

    private JPanel createCombinedPatternTable() {
        JPanel panel = new JPanel(new BorderLayout());

        Object[] columns = { "Enabled", "Name", "Location", "Capture Regex", "Target", "Patch Proxy",
                "Configuration" };
        DefaultTableModel model = new DefaultTableModel(null, columns) {
            @Override
            public Class<?> getColumnClass(int columnIndex) {
                if ("Enabled".equals(getColumnName(columnIndex))) {
                    return Boolean.class;
                }
                return super.getColumnClass(columnIndex);
            };

            @Override
            public boolean isCellEditable(int row, int col) {
                return "Enabled".equals(getColumnName(col));
            }
        };
        this.patternModel = model;
        // Configuration cells can be long (commands, key sources): show the full text on hover
        // instead of widening the column past the rest.
        JTable table = new JTable(model) {
            @Override
            public String getToolTipText(java.awt.event.MouseEvent event) {
                int row = rowAtPoint(event.getPoint());
                int column = columnAtPoint(event.getPoint());
                if (row < 0 || column < 0) {
                    return null;
                }
                Object value = getValueAt(row, column);
                return value instanceof String text && !text.isEmpty() ? text : null;
            }
        };
        this.patternTable = table;
        table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        table.setFillsViewportHeight(true);
        reloadPatternTable();

        // Clicking the "Enabled" checkbox toggles the pattern on/off and persists it
        model.addTableModelListener(e -> {
            if (suppressTableEvents) {
                return;
            }
            if (e.getType() == TableModelEvent.UPDATE && e.getColumn() >= 0
                    && "Enabled".equals(model.getColumnName(e.getColumn()))) {
                int row = e.getFirstRow();
                if (row < 0 || row >= model.getRowCount()) {
                    return;
                }
                var patterns = config.getPatterns();
                if (row >= patterns.size()) {
                    return;
                }
                CapturePattern toggled = patterns.get(row);
                toggled.setEnabled(Boolean.TRUE.equals(model.getValueAt(row, e.getColumn())));
                config.editPattern(row, toggled);
            }
        });

        ActionListener exportAction = e -> PatternIo.export(uiComponent(), selectedPatternsOrAll(), null);
        ActionListener importAction = e -> applyImport(PatternIo.importFrom(uiComponent(), config, false));

        ActionListener addAction = e -> {
            CapturePattern r = createOrEditPatternPopup(true);
            if (r == null) {
                return;
            }
            config.addPattern(r);
            reloadPatternTable();
        };

        ActionListener editAction = e -> {
            int row = table.getSelectedRow();
            if (row < 0) {
                return;
            }
            CapturePattern existing = config.getPatterns().get(row);
            CapturePattern r = createOrEditPatternPopup(existing, existing.isRequest());
            if (r == null) {
                return;
            }
            // The row may have moved while the dialog was open (auto-load replaces patterns by name),
            // so find the target again instead of writing back to a stale index.
            int target = config.indexOf(existing);
            if (target < 0) {
                target = config.indexOfName(existing.getName());
            }
            // Flipping Request/Response is now just a field, so the pattern keeps its row either way.
            if (target < 0) {
                config.addPattern(r);
            } else {
                config.editPattern(target, r);
            }
            reloadPatternTable();
        };

        ActionListener cloneAction = e -> {
            int row = table.getSelectedRow();
            if (row < 0) {
                return;
            }
            config.clonePattern(row);
            reloadPatternTable();
        };

        ActionListener removeAction = e -> {
            List<Integer> rows = new ArrayList<>();
            for (int row : table.getSelectedRows()) {
                rows.add(row);
            }
            // Bottom-up, so each removal leaves the rows still to go at the index we recorded.
            rows.sort(Collections.reverseOrder());
            for (int row : rows) {
                config.removePattern(row);
            }
            reloadPatternTable();
        };

        ActionListener upAction = e -> moveSelected(table, -1);
        ActionListener downAction = e -> moveSelected(table, 1);

        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && !e.isConsumed()) {
                    e.consume();
                    if (table.getSelectedRow() != -1) {
                        editAction.actionPerformed(new ActionEvent(e.getSource(), ActionEvent.ACTION_PERFORMED, "edit"));
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
                        // Edit and Clone act on one pattern; with several rows picked they would
                        // silently touch only the first, so they are not offered at all.
                        if (table.getSelectedRowCount() == 1) {
                            addMenuItem(popup, "Edit", editAction);
                            addMenuItem(popup, "Clone", cloneAction);
                        }
                        addMenuItem(popup, "Remove", removeAction);
                        popup.addSeparator();
                        if (canMoveSelection(table, -1)) {
                            addMenuItem(popup, "Up", upAction);
                        }
                        if (canMoveSelection(table, 1)) {
                            addMenuItem(popup, "Down", downAction);
                        }
                        popup.addSeparator();
                        addMenuItem(popup, "Export", exportAction);
                    } else {
                        addMenuItem(popup, "Add", addAction);
                        addMenuItem(popup, "Import", importAction);
                    }
                    popup.show(e.getComponent(), e.getX(), e.getY());
                }
            }
        });

        TableColumnModel cm = table.getColumnModel();
        cm.getColumn(0).setPreferredWidth(60); // Enabled
        cm.getColumn(1).setPreferredWidth(140); // Name
        cm.getColumn(2).setPreferredWidth(80); // Location
        cm.getColumn(3).setPreferredWidth(170); // Capture Regex
        cm.getColumn(4).setPreferredWidth(150); // Target
        cm.getColumn(5).setPreferredWidth(80); // Patch Proxy
        cm.getColumn(6).setPreferredWidth(1000); // Configuration

        JScrollPane scrollPane = new JScrollPane(table);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        panel.add(scrollPane, BorderLayout.CENTER);

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
        JButton exportButton = new JButton("Export");
        exportButton.addActionListener(exportAction);
        JButton importButton = new JButton("Import");
        importButton.addActionListener(importAction);

        // Add and Import always apply. The rest need something to act on: Export needs a non-empty
        // table (a file holding "patterns": [] is a trap for whoever imports it), Remove works on a
        // multi-selection, Edit/Clone act on one pattern so they need exactly one row, and Up/Down
        // are on only while the selection has somewhere to go inside its own list.
        Runnable updateButtons = () -> {
            int selected = table.getSelectedRowCount();
            boolean one = selected == 1;
            editButton.setEnabled(one);
            cloneButton.setEnabled(one);
            upButton.setEnabled(canMoveSelection(table, -1));
            downButton.setEnabled(canMoveSelection(table, 1));
            removeButton.setEnabled(selected > 0);
            exportButton.setEnabled(model.getRowCount() > 0);
        };
        updateButtons.run();
        model.addTableModelListener(e -> updateButtons.run());
        table.getSelectionModel().addListSelectionListener(e -> updateButtons.run());

        JPanel buttonPanel = new JPanel(new GridLayout(8, 1, 0, 5));
        buttonPanel.add(addButton);
        buttonPanel.add(importButton);
        buttonPanel.add(cloneButton);
        buttonPanel.add(editButton);
        buttonPanel.add(removeButton);
        buttonPanel.add(upButton);
        buttonPanel.add(downButton);
        buttonPanel.add(exportButton);
        buttonPanel.setBorder(new EmptyBorder(1, 5, 1, 1));

        JPanel buttonWrapper = new JPanel(new BorderLayout());
        buttonWrapper.add(buttonPanel, BorderLayout.NORTH);
        panel.add(buttonWrapper, BorderLayout.EAST);

        return panel;
    }

    /** Selected rows as export items, in table order; the whole table when nothing is selected. */
    private List<CapturePattern> selectedPatternsOrAll() {
        int[] rows = patternTable == null ? new int[0] : patternTable.getSelectedRows();
        if (rows.length == 0) {
            return PatternIo.allPatterns(config);
        }
        List<CapturePattern> items = new ArrayList<>();
        for (int row : rows) {
            items.add(config.getPatterns().get(row));
        }
        return items;
    }

    private void addMenuItem(JPopupMenu popup, String label, ActionListener action) {
        JMenuItem item = new JMenuItem(label);
        item.addActionListener(action);
        popup.add(item);
    }

    /** Move the single selected pattern up/down within its own (request/response) list. */
    /**
     * Move every selected pattern one row, each within its own list — a request pattern can never
     * cross into the response half of the table. An item already at the edge, or held up by another
     * selected item that is, stays where it is, so a selection is never reordered or compressed into
     * itself. The moved rows keep the selection, so the buttons can be clicked repeatedly.
     */
    private void moveSelected(JTable table, int delta) {
        int[] rows = table.getSelectedRows();
        if (rows.length == 0) {
            return;
        }
        List<Integer> movedRows = new ArrayList<>();
        for (int[] move : planMove(selectedIndexes(rows), delta, config.getPatterns().size())) {
            if (move[0] != move[1]) {
                config.movePattern(move[0], move[1]);
            }
            movedRows.add(move[1]);
        }
        reloadPatternTable();
        table.clearSelection();
        for (int row : movedRows) {
            table.addRowSelectionInterval(row, row);
        }
    }

    /**
     * Where each selected index lands when the block steps one row.
     *
     * @param indexes selected indexes within one list, in any order
     * @param delta   -1 to move up, +1 to move down
     * @param size    how many patterns that list holds
     * @return {from, to} pairs in the order they must be applied; an index that cannot move (it is at
     *         the edge, or blocked by another selected index that is) maps to itself
     */
    static List<int[]> planMove(List<Integer> indexes, int delta, int size) {
        // Walk from the edge the items are moving towards, so each one is placed before the next
        // needs to know where it landed.
        List<Integer> ordered = new ArrayList<>(indexes);
        ordered.sort(delta < 0 ? Comparator.naturalOrder() : Comparator.reverseOrder());

        List<int[]> moves = new ArrayList<>();
        int limit = delta < 0 ? 0 : size - 1;
        for (int index : ordered) {
            int target = delta < 0 ? Math.max(index + delta, limit) : Math.min(index + delta, limit);
            moves.add(new int[] { index, target });
            limit = target - delta;
        }
        return moves;
    }

    /** Selected rows that still exist in the pattern list. */
    private List<Integer> selectedIndexes(int[] rows) {
        List<Integer> indexes = new ArrayList<>();
        int size = config.getPatterns().size();
        for (int row : rows) {
            if (row >= 0 && row < size) {
                indexes.add(row);
            }
        }
        return indexes;
    }

    /** Whether Up/Down would reorder anything, i.e. the selection is not already against that edge. */
    private boolean canMoveSelection(JTable table, int delta) {
        for (int[] move : planMove(selectedIndexes(table.getSelectedRows()), delta,
                config.getPatterns().size())) {
            if (move[0] != move[1]) {
                return true;
            }
        }
        return false;
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
                "Automatically DECRYPT RESPONSES. It will only affect targets defined in the patterns' target scope.");
        decryptExplanation.setFont(decryptExplanation.getFont().deriveFont(11f));
        decryptExplanation.setForeground(Color.GRAY);
        decryptExplanation.setAlignmentX(Component.LEFT_ALIGNMENT);
        decryptExplanation.setBorder(new EmptyBorder(0, 24, 15, 0));
        panel.add(decryptExplanation);

        // Encrypt requests checkbox
        JCheckBox encryptRequestsCheckbox = new JCheckBox(
                "Auto-encrypt intruder requests (you have to send intruder payloads in PLAINTEXT)");
        encryptRequestsCheckbox.setSelected(config.isIntruderRequestEncryptEnabled());
        encryptRequestsCheckbox.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(encryptRequestsCheckbox);

        // Explanation for encrypt requests
        JLabel encryptExplanation = new JLabel(
                "Automatically ENCRYPT REQUESTS. It will only affect targets defined in the patterns' target scope.");
        encryptExplanation.setFont(encryptExplanation.getFont().deriveFont(11f));
        encryptExplanation.setForeground(Color.GRAY);
        encryptExplanation.setAlignmentX(Component.LEFT_ALIGNMENT);
        encryptExplanation.setBorder(new EmptyBorder(0, 24, 2, 0));
        panel.add(encryptExplanation);

        JLabel encryptExplanation2 = new JLabel(
                "If you need to see the ciphertext sent to the target, use Burp Suite Logger (CTRL+SHIFT+L)");
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

        // Explanation for payload processor
        JLabel payloadExplanation = new JLabel(
                "In Intruder, go to \"Payload processing\" > \"Add\" > \"Invoke Burp extension\" to make command below transform the payload");
        payloadExplanation.setFont(payloadExplanation.getFont().deriveFont(11f));
        payloadExplanation.setForeground(Color.GRAY);
        payloadExplanation.setAlignmentX(Component.LEFT_ALIGNMENT);
        payloadExplanation.setBorder(new EmptyBorder(0, 24, 0, 0));
        panel.add(payloadExplanation);

        // Encrypt command text field
        JPanel commandPanel = new JPanel(new BorderLayout(5, 0));
        commandPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        commandPanel.setBorder(new EmptyBorder(0, 24, 5, 5));
        commandPanel.setMaximumSize(new Dimension(800, 45));

        JLabel commandLabel = new JLabel("Encrypt Command:");
        Color enabledLabelColor = commandLabel.getForeground();
        boolean payloadProcessorEnabled = config.isIntruderPayloadProcessorEnabled();
        commandLabel.setForeground(payloadProcessorEnabled ? enabledLabelColor : Color.GRAY);

        JTextField commandField = new JTextField(config.getIntruderEncryptCommand());
        commandField.setEnabled(payloadProcessorEnabled);
        commandField.setToolTipText(
                "Command to use in Intruder Payload Processor. {DATA} will be replaced by the captured data, {FILE} will be replaced by the file path of an auto-created file containing the captured data.   # hello jodson");
        String commandFieldPlaceholder = "python /tmp/YOUR_SCRIPT.js {FILE} ";
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
        JLabel commandExplanation = new JLabel(
                "{DATA} will be replaced by the captured data, {FILE} will be replaced by the file path of an auto-created file containing the captured data");
        commandExplanation.setFont(commandExplanation.getFont().deriveFont(11f));
        commandExplanation.setForeground(Color.GRAY);
        commandExplanation.setAlignmentX(Component.LEFT_ALIGNMENT);
        commandExplanation.setBorder(new EmptyBorder(0, 24, 15, 0));
        panel.add(commandExplanation);

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


    private CapturePattern createOrEditPatternPopup(boolean isRequest) {
        return createOrEditPatternPopup(null, isRequest, null, null, null, null, null);
    }

    private CapturePattern createOrEditPatternPopup(CapturePattern existingPattern, boolean isRequest) {
        return createOrEditPatternPopup(existingPattern, isRequest, null, null, null, null, null);
    }

    /**
     * @param seedEngineId     when non-null (and existingPattern is null), pre-selects this
     *                         engine and seeds its params for a NEW pattern
     * @param seedEngineParams engine params to seed
     * @param seedCaptureRegex when non-null (new pattern), sets Custom Regex + this value
     * @param seedName         when non-null (new pattern), the default pattern name
     * @param seedTarget       when non-null (new pattern), pre-selects Custom Scope with this regex
     * @return the built pattern + chosen location, or null if cancelled
     */
    private CapturePattern createOrEditPatternPopup(CapturePattern existingPattern, boolean isRequest,
            String seedEngineId, HashMap<String, String> seedEngineParams, String seedCaptureRegex, String seedName,
            String seedTarget) {
        CapturePattern pattern = null;

        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));

        // === Tab Name ===
        JTextField nameField = new JTextField();
        nameField.setToolTipText("Enter a name for the pattern.");
        addLabelAndField(panel, "Give a name:", nameField);

        // === Capture Pattern Section (horizontal layout) ===
        JLabel patternLabel = new JLabel("What will be captured?");
        patternLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(patternLabel);

        // Location (Request / Response) — right under the question, before the type dropdown
        JPanel locationRow = new JPanel();
        locationRow.setLayout(new BoxLayout(locationRow, BoxLayout.X_AXIS));
        locationRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        JRadioButton requestRadio = new JRadioButton("Request", isRequest);
        JRadioButton responseRadio = new JRadioButton("Response", !isRequest);
        ButtonGroup locationGroup = new ButtonGroup();
        locationGroup.add(requestRadio);
        locationGroup.add(responseRadio);
        locationRow.add(requestRadio);
        locationRow.add(Box.createHorizontalStrut(18));
        locationRow.add(responseRadio);
        locationRow.add(Box.createHorizontalGlue());
        panel.add(locationRow);
        panel.add(Box.createVerticalStrut(5));

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

        // Hint about the capture field, on its own row directly under it: it describes that field, so
        // sitting in the scope header below made it read as a note about the scope.
        JLabel regexHintLabel = new JLabel();
        regexHintLabel.setFont(regexHintLabel.getFont().deriveFont(11f));
        regexHintLabel.setForeground(Color.GRAY);
        JPanel regexHintRow = new JPanel();
        regexHintRow.setLayout(new BoxLayout(regexHintRow, BoxLayout.X_AXIS));
        regexHintRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        regexHintRow.setBorder(new EmptyBorder(2, 0, 0, 0));
        // Capped, otherwise the row absorbs the dialog's spare height and the hint drifts away again.
        regexHintRow.setMaximumSize(new Dimension(Integer.MAX_VALUE, 18));
        regexHintRow.add(Box.createHorizontalGlue());
        regexHintRow.add(regexHintLabel);
        panel.add(regexHintRow);
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
                regexHintLabel.setText("Case sensitive. Use (.*?) to define which part should be captured");
                break;
            }
            panel.revalidate();
        });

        // === Target Scope Section (horizontal layout) ===
        JLabel scopeLabel = new JLabel("What is the target scope?");
        JPanel scopeHeaderPanel = new JPanel();
        scopeHeaderPanel.setLayout(new BoxLayout(scopeHeaderPanel, BoxLayout.X_AXIS));
        scopeHeaderPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        scopeHeaderPanel.add(scopeLabel);
        scopeHeaderPanel.add(Box.createHorizontalGlue());
        panel.add(scopeHeaderPanel);

        JPanel scopeRow = new JPanel();
        scopeRow.setLayout(new BoxLayout(scopeRow, BoxLayout.X_AXIS));
        scopeRow.setAlignmentX(Component.LEFT_ALIGNMENT);

        String[] scopeTypes = { "Everything", "Project In-Scope", "Custom Scope" };
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
        scopeInputPanel.setVisible(false); // Hidden by default ("Everything" selected)

        scopeRow.add(scopeInputPanel);
        panel.add(scopeRow);
        panel.add(Box.createVerticalStrut(5));

        scopeTypeCombo.addActionListener(e -> {
            String selected = (String) scopeTypeCombo.getSelectedItem();
            scopeInputPanel.setVisible("Custom Scope".equals(selected));
            panel.revalidate();
        });

        // === Encryption Mode Dropdown ===
        JLabel encModeLabel = new JLabel("Which encryption mode we will use?");
        encModeLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(encModeLabel);

        JComboBox<String> encModeCombo = new JComboBox<>(CryptoEngineRegistry.getDropdownNames());
        encModeCombo.setMaximumSize(new Dimension(Integer.MAX_VALUE, 30));
        encModeCombo.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(encModeCombo);
        panel.add(Box.createVerticalStrut(5));

        // Configure button: opens the commands dialog (Custom Command) or the engine
        // config dialog (AES/RSA), following the same flow for both. A warning label to its
        // right mirrors the table's Configuration column (e.g. "⚠ Encrypt command is empty.").
        JButton configureBtn = new JButton("⚙ Configure...");
        JLabel configWarningLabel = new JLabel(" ");
        configWarningLabel.setFont(configWarningLabel.getFont().deriveFont(11f));

        JPanel configRow = new JPanel();
        configRow.setLayout(new BoxLayout(configRow, BoxLayout.X_AXIS));
        configRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        configRow.setMaximumSize(new Dimension(Integer.MAX_VALUE, configureBtn.getPreferredSize().height));
        configRow.add(configureBtn);
        configRow.add(Box.createHorizontalStrut(8));
        configRow.add(configWarningLabel);
        configRow.add(Box.createHorizontalGlue());
        panel.add(configRow);
        panel.add(Box.createVerticalStrut(5));

        // Holder for engine params (set when config popup is confirmed)
        final HashMap<String, String>[] engineParamsHolder = new HashMap[] { null };

        // Custom command fields - edited via the "Configure Commands" dialog, kept here
        // as the backing state (not shown inline).
        JTextField decCommand = new JTextField();
        decCommand.setToolTipText(
                "Command to decrypt/decode. {DATA} will be replaced by the captured data, {FILE} will be replaced by the file path of an auto-created file containing the captured data.");
        JTextField encCommand = new JTextField();
        encCommand.setToolTipText(
                "Command to encrypt/encode. {DATA} will be replaced by the captured data, {FILE} will be replaced by the file path of an auto-created file containing the captured data.");

        // Refresh the warning beside the Configure button from the current mode + config state.
        Runnable refreshConfigWarning = () -> {
            String selected = (String) encModeCombo.getSelectedItem();
            boolean isCustom = CryptoEngineRegistry.CUSTOM_COMMAND.equals(selected);
            String warn = isCustom
                    ? warningFor(false, null, null, decCommand.getText(), encCommand.getText())
                    : warningFor(true, CryptoEngineRegistry.getByDisplayName(selected), engineParamsHolder[0], null,
                            null);
            if (warn != null) {
                configWarningLabel.setText("⚠ " + capitalize(warn));
                configWarningLabel.setForeground(ERROR_COLOR);
            } else {
                configWarningLabel.setText(" ");
            }
        };

        // Button label reflects the selected mode
        encModeCombo.addActionListener(e -> {
            String selected = (String) encModeCombo.getSelectedItem();
            boolean isCustom = CryptoEngineRegistry.CUSTOM_COMMAND.equals(selected);
            if (isCustom) {
                configureBtn.setText("⚙ Configure Commands...");
            } else {
                CryptoEngine engine = CryptoEngineRegistry.getByDisplayName(selected);
                if (engine != null) {
                    configureBtn.setText("⚙ Configure " + engine.getDisplayName() + "...");
                }
            }
            refreshConfigWarning.run();
            // Only the button label changes between modes, so relayout in place without
            // repacking the dialog (which would shrink it back to its preferred size).
            panel.revalidate();
            panel.repaint();
        });

        // Configure button: commands dialog for Custom Command, engine dialog otherwise
        configureBtn.addActionListener(e -> {
            String selected = (String) encModeCombo.getSelectedItem();
            if (CryptoEngineRegistry.CUSTOM_COMMAND.equals(selected)) {
                openCustomCommandDialog(decCommand, encCommand);
                refreshConfigWarning.run();
                return;
            }
            CryptoEngine engine = CryptoEngineRegistry.getByDisplayName(selected);
            if (engine == null) return;

            EngineConfigPanel configPanel = engine.createConfigPanel(engineParamsHolder[0]);

            // Wrap in a dialog
            JDialog configDialog = new JDialog((java.awt.Frame) null, engine.getDisplayName() + " Configuration", true);
            configDialog.setLayout(new BorderLayout());

            JScrollPane scrollPane = new JScrollPane(configPanel);
            scrollPane.setBorder(new EmptyBorder(10, 10, 5, 10));
            configDialog.add(scrollPane, BorderLayout.CENTER);

            // Validation label: red ⚠ for real problems, amber ⓘ for advisory notes
            JLabel validationLabel = new JLabel(" ");
            validationLabel.setBorder(new EmptyBorder(5, 10, 5, 10));

            // Live validation
            Runnable refreshValidation = () -> {
                HashMap<String, String> ps = configPanel.getParams();
                String error = engine.validate(ps);
                if (error != null) {
                    validationLabel.setText("⚠ " + error);
                    validationLabel.setForeground(ERROR_COLOR);
                } else {
                    String note = engine.info(ps);
                    if (note != null) {
                        validationLabel.setText("ⓘ " + note);
                        validationLabel.setForeground(INFO_COLOR);
                    } else {
                        validationLabel.setText(" ");
                    }
                }
            };
            configPanel.setOnChangeListener(refreshValidation);

            // OK / Cancel buttons
            JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
            JButton okBtn = new JButton("OK");
            JButton cancelBtn = new JButton("Cancel");
            okBtn.addActionListener(ok -> {
                engineParamsHolder[0] = configPanel.getParams();
                configDialog.dispose();
            });
            cancelBtn.addActionListener(cancel -> {
                configDialog.dispose();
            });
            bindEscape(configDialog, configDialog::dispose);
            btnPanel.add(okBtn);
            btnPanel.add(cancelBtn);

            JPanel bottomPanel = new JPanel(new BorderLayout());
            bottomPanel.add(validationLabel, BorderLayout.CENTER);
            bottomPanel.add(btnPanel, BorderLayout.EAST);
            configDialog.add(bottomPanel, BorderLayout.SOUTH);

            configDialog.setMinimumSize(new Dimension(550, 300));
            configDialog.pack();
            configDialog.setLocationRelativeTo(null);
            refreshValidation.run(); // initial state
            configDialog.setVisible(true);
            refreshConfigWarning.run(); // reflect the new config on the pattern dialog
        });

        // === Optional settings (collapsible) ===
        // "Optional settings" makes clear these can be skipped; collapsed by default to keep
        // the dialog simple, but always discoverable.
        panel.add(Box.createVerticalStrut(8));

        JPanel moreSettingsPanel = new JPanel();
        moreSettingsPanel.setLayout(new BoxLayout(moreSettingsPanel, BoxLayout.Y_AXIS));
        moreSettingsPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        moreSettingsPanel.setVisible(false);

        JCheckBox cacheCommandsCheckbox = new JCheckBox("Use cache system for decrypting", CapturePattern.DEFAULT_USE_CACHE_SYSTEM);
        addComponent(moreSettingsPanel, cacheCommandsCheckbox);
        addGrayLabel(moreSettingsPanel, "Save decrypted outputs, and load them when a decrypt command fails");

        JCheckBox dontCacheGarbageCheckbox = new JCheckBox("Do not cache garbage decryptions", CapturePattern.DEFAULT_DETECT_GARBAGE);
        dontCacheGarbageCheckbox.setBorder(new EmptyBorder(0, 20, 0, 0));
        addComponent(moreSettingsPanel, dontCacheGarbageCheckbox);
        addGrayLabel(moreSettingsPanel,
                "Skips caching output that looks like a wrong-key result. May rarely skip valid binary/non-text output.");
        // Only meaningful when caching is on
        dontCacheGarbageCheckbox.setEnabled(cacheCommandsCheckbox.isSelected());
        cacheCommandsCheckbox.addActionListener(
                e -> dontCacheGarbageCheckbox.setEnabled(cacheCommandsCheckbox.isSelected()));

        JCheckBox saveToLogCheckbox = new JCheckBox("Log data to the file defined in General Settings", CapturePattern.DEFAULT_SAVE_TO_LOG);
        addComponent(moreSettingsPanel, saveToLogCheckbox);
        addGrayLabel(moreSettingsPanel,
                "Allowing you to easily search in plaintext data. Proxy data will also be logged if the next option is enabled");

        JCheckBox patchProxyCheckbox = new JCheckBox("Patch proxy traffic", CapturePattern.DEFAULT_PATCH_PROXY);
        addComponent(moreSettingsPanel, patchProxyCheckbox);
        addGrayLabel(moreSettingsPanel, "Automatically re-encrypt proxy data");

        JButton moreSettingsBtn = new JButton("▸ Optional settings");
        moreSettingsBtn.setAlignmentX(Component.LEFT_ALIGNMENT);
        moreSettingsBtn.addActionListener(ev -> {
            boolean show = !moreSettingsPanel.isVisible();
            moreSettingsPanel.setVisible(show);
            moreSettingsBtn.setText(show ? "▾ Optional settings" : "▸ Optional settings");
            panel.revalidate();
            java.awt.Window parentWindow = javax.swing.SwingUtilities.getWindowAncestor(panel);
            if (parentWindow != null) {
                parentWindow.pack();
                if (parentWindow.getWidth() < 560) {
                    parentWindow.setSize(560, parentWindow.getHeight());
                }
            }
        });
        panel.add(moreSettingsBtn);
        panel.add(Box.createVerticalStrut(3));
        panel.add(moreSettingsPanel);

        // === Validation alert label ===
        JLabel alertLabel = new JLabel(" ");
        alertLabel.setForeground(new Color(200, 50, 50));
        alertLabel.setFont(alertLabel.getFont().deriveFont(12f));
        alertLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(Box.createVerticalStrut(5));
        panel.add(alertLabel);

        // === Populate fields for editing or set defaults for new ===
        if (existingPattern != null) {
            nameField.setText(existingPattern.getName());
            decCommand.setText(existingPattern.getDecCommand());
            encCommand.setText(existingPattern.getEncCommand());
            patchProxyCheckbox.setSelected(existingPattern.shouldPatchProxy());
            cacheCommandsCheckbox.setSelected(existingPattern.shouldUseCacheSystem());
            saveToLogCheckbox.setSelected(existingPattern.shouldSaveToLog());
            dontCacheGarbageCheckbox.setSelected(existingPattern.shouldDetectGarbage());
            dontCacheGarbageCheckbox.setEnabled(existingPattern.shouldUseCacheSystem());

            // Auto-expand the optional settings when any differ from defaults, so they're visible
            if (existingPattern.shouldPatchProxy() || !existingPattern.shouldUseCacheSystem()
                    || !existingPattern.shouldSaveToLog() || !existingPattern.shouldDetectGarbage()) {
                moreSettingsPanel.setVisible(true);
                moreSettingsBtn.setText("▾ Optional settings");
            }

            // Set pattern type and input from stored values
            patternTypeCombo.setSelectedItem(existingPattern.getPatternType().getDisplayName());
            patternInputField.setText(existingPattern.getPatternInput());
            String urlRegex = existingPattern.getURLTargetRegex();
            // Parse scope
            if (existingPattern.usesProjectScope()) {
                scopeTypeCombo.setSelectedItem("Project In-Scope");
            } else if (urlRegex == null || urlRegex.isEmpty()) {
                scopeTypeCombo.setSelectedItem("Everything");
            } else {
                scopeTypeCombo.setSelectedItem("Custom Scope");
                scopeInputField.setText(urlRegex);
                scopeInputPanel.setVisible(true);
            }

            // Set encryption mode if engine is used
            if (existingPattern.usesEngine()) {
                CryptoEngine engine = CryptoEngineRegistry.get(existingPattern.getEngineId());
                if (engine != null) {
                    encModeCombo.setSelectedItem(engine.getDisplayName());
                    engineParamsHolder[0] = existingPattern.getEngineParams() != null
                            ? new HashMap<>(existingPattern.getEngineParams())
                            : null;
                }
            }
        } else {
            // New pattern - auto-generate name (or use a seeded name, e.g. from Analyze)
            nameField.setText(seedName != null ? seedName : config.generateUniqueName());
            setPlaceholder(decCommand, "cat {FILE} ");
            setPlaceholder(encCommand, "cat {FILE} ");
            // Default to Parameter JSON for new patterns
            patternTypeCombo.setSelectedItem(PatternType.PARAMETER_JSON.getDisplayName());

            // Seed engine + params from an analysis suggestion (stays a NEW pattern)
            if (seedEngineId != null) {
                CryptoEngine seedEngine = CryptoEngineRegistry.get(seedEngineId);
                if (seedEngine != null) {
                    encModeCombo.setSelectedItem(seedEngine.getDisplayName());
                    engineParamsHolder[0] = seedEngineParams != null ? new HashMap<>(seedEngineParams) : null;
                }
            }
            // Seed the target scope from the host the analyzed message came from
            if (seedTarget != null && !seedTarget.isEmpty()) {
                scopeTypeCombo.setSelectedItem("Custom Scope");
                scopeInputField.setText(seedTarget);
                scopeInputPanel.setVisible(true);
            }
            // Seed the capture as a Custom Regex built from the analyzed selection
            if (seedCaptureRegex != null) {
                patternTypeCombo.setSelectedItem(PatternType.CUSTOM_REGEX.getDisplayName());
                patternInputField.setText(seedCaptureRegex);
            }
        }

        // Trigger initial visibility update
        patternTypeCombo.getActionListeners()[0]
                .actionPerformed(new ActionEvent(patternTypeCombo, ActionEvent.ACTION_PERFORMED, "init"));
        scopeTypeCombo.getActionListeners()[0]
                .actionPerformed(new ActionEvent(scopeTypeCombo, ActionEvent.ACTION_PERFORMED, "init"));
        encModeCombo.getActionListeners()[0]
                .actionPerformed(new ActionEvent(encModeCombo, ActionEvent.ACTION_PERFORMED, "init"));

        String[] options = { "OK", "Cancel" };

        JOptionPane optionPane = new JOptionPane(panel, JOptionPane.PLAIN_MESSAGE, JOptionPane.OK_CANCEL_OPTION, null,
                options, options[0]);

        JDialog dialog = optionPane.createDialog(existingPattern == null ? "Adding Pattern" : "Editing Pattern");

        // Enforce a sensible default width so the input fields aren't cramped
        int minWidth = 560;
        if (dialog.getWidth() < minWidth) {
            dialog.setSize(minWidth, dialog.getHeight());
            dialog.setLocationRelativeTo(null);
        }

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
                alertLabel.setText("⚠ Define what should be captured.");
                continue;
            }

            // Chosen location from the radio (may differ from the initial value on edit)
            boolean chosenIsRequest = requestRadio.isSelected();

            // Build scope from dropdown selection
            String scopeSelection = (String) scopeTypeCombo.getSelectedItem();
            boolean useProjectScope = "Project In-Scope".equals(scopeSelection);
            String scopeRegex = "Custom Scope".equals(scopeSelection) ? scopeInputField.getText() : "";

            String name = nameField.getText();
            if (name == null || name.isEmpty()) {
                name = config.generateUniqueName();
            }

            boolean duplicate = false;
            for (CapturePattern p : config.getPatterns()) {
                if (p.getName().equals(name)) {
                    // Keeping your own name is never a clash. Matching on the name rather than on
                    // object identity matters while auto-load is running: it replaces the pattern in
                    // the list with a fresh object, so the one this dialog opened is no longer in it.
                    if (existingPattern != null
                            && (p == existingPattern || name.equals(existingPattern.getName()))) {
                        continue;
                    }
                    duplicate = true;
                    break;
                }
            }

            if (duplicate) {
                alertLabel.setText("⚠ That name is already taken. Pick a different one.");
                continue;
            }

            // Clear any previous alert
            alertLabel.setText(" ");

            // Determine if using engine or custom command
            String selectedMode = (String) encModeCombo.getSelectedItem();
            CryptoEngine selectedEngine = CryptoEngineRegistry.getByDisplayName(selectedMode);

            // Enabled is toggled from the table; preserve it on edit, default to true for new
            boolean enabled = existingPattern != null ? existingPattern.isEnabled() : true;

            if (selectedEngine != null) {
                // Engine-based pattern
                pattern = new CapturePattern(name, regex, scopeRegex, enabled,
                        patchProxyCheckbox.isSelected(), cacheCommandsCheckbox.isSelected(),
                        saveToLogCheckbox.isSelected(), useProjectScope, selectedPatternType, patternInput,
                        selectedEngine.getId(), engineParamsHolder[0]);
            } else {
                // Custom command pattern
                pattern = new CapturePattern(name, regex, scopeRegex, decCommand.getText(), encCommand.getText(),
                        enabled, patchProxyCheckbox.isSelected(),
                        cacheCommandsCheckbox.isSelected(), saveToLogCheckbox.isSelected(), useProjectScope,
                        selectedPatternType, patternInput);
            }
            pattern.setDetectGarbage(dontCacheGarbageCheckbox.isSelected());
            pattern.setRequest(chosenIsRequest);
            return pattern;
        }
    }

    /**
     * Modal dialog to configure the Custom Command decrypt/encrypt commands, with room
     * to explain the {DATA} and {FILE} placeholders. Edits the given fields in place;
     * Cancel restores their previous contents.
     */
    private void openCustomCommandDialog(JTextField decCommand, JTextField encCommand) {
        JDialog dialog = new JDialog((java.awt.Frame) null, "Configure Commands", true);
        dialog.setLayout(new BorderLayout());

        JPanel content = new JPanel();
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));
        content.setBorder(new EmptyBorder(10, 10, 10, 10));

        // Plain-text wrapped area (Burp disables HTML rendering in Swing labels)
        javax.swing.JTextArea explain = new javax.swing.JTextArea(
                "Decrypt converts the captured data to plaintext. Encrypt converts it back.\n\n"
                        + "Use these placeholders in either command:\n"
                        + "  • {DATA} will be replaced by the captured data, inserted inline.\n"
                        + "  • {FILE} will be replaced by the path to an auto-created tmp file holding the data (best for binary or large data).\n\n"
                        + "The command's output is used as the result.");
        explain.setEditable(false);
        explain.setLineWrap(true);
        explain.setWrapStyleWord(true);
        explain.setOpaque(false);
        explain.setFocusable(false);
        explain.setBorder(null);
        explain.setFont(javax.swing.UIManager.getFont("Label.font"));
        explain.setAlignmentX(Component.LEFT_ALIGNMENT);
        // Fix the width first so the wrapped height is computed correctly, then pin the
        // size so BoxLayout lays it out stably (no fields hidden / no jumping on resize).
        int explainWidth = 460;
        explain.setSize(explainWidth, Short.MAX_VALUE);
        Dimension explainSize = new Dimension(explainWidth, explain.getPreferredSize().height);
        explain.setPreferredSize(explainSize);
        explain.setMaximumSize(explainSize);
        explain.setMinimumSize(explainSize);
        content.add(explain);
        content.add(Box.createVerticalStrut(12));

        // Snapshot for Cancel (text + foreground, to preserve placeholder styling)
        String decSnapshot = decCommand.getText();
        String encSnapshot = encCommand.getText();
        Color decFg = decCommand.getForeground();
        Color encFg = encCommand.getForeground();

        addLabelAndField(content, "Decrypt Command", decCommand);
        addLabelAndField(content, "Encrypt Command", encCommand);
        content.add(Box.createVerticalGlue()); // absorb extra space at the bottom

        dialog.add(content, BorderLayout.CENTER);

        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton okBtn = new JButton("OK");
        JButton cancelBtn = new JButton("Cancel");
        okBtn.addActionListener(a -> dialog.dispose());
        Runnable cancel = () -> {
            decCommand.setText(decSnapshot);
            decCommand.setForeground(decFg);
            encCommand.setText(encSnapshot);
            encCommand.setForeground(encFg);
            dialog.dispose();
        };
        cancelBtn.addActionListener(a -> cancel.run());
        bindEscape(dialog, cancel);
        // Enter confirms — only here for Custom Command (the engine dialogs have many fields)
        dialog.getRootPane().setDefaultButton(okBtn);
        btnPanel.add(okBtn);
        btnPanel.add(cancelBtn);
        dialog.add(btnPanel, BorderLayout.SOUTH);

        dialog.pack();
        // Don't allow shrinking below the packed size, which would hide the fields
        dialog.setMinimumSize(dialog.getSize());
        dialog.setLocationRelativeTo(null);
        dialog.setVisible(true);
    }

    /** Make Escape run the given action (used to cancel/close modal config dialogs). */
    private static void bindEscape(JDialog dialog, Runnable onEscape) {
        dialog.getRootPane().registerKeyboardAction(e -> onEscape.run(),
                KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), JComponent.WHEN_IN_FOCUSED_WINDOW);
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
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));

        createConfigTransferSettings(panel);
        createRepeaterSettings(panel);
        createLogFileSettings(panel);
        createPrintTabSettings(panel, true);
        createPrintTabSettings(panel, false);
        createCacheSettings(panel);

        // Wrap content so it stays top-aligned inside the scroll pane
        JPanel panelWrapper = new JPanel(new BorderLayout());
        panelWrapper.add(panel, BorderLayout.NORTH);

        JScrollPane scrollPane = new JScrollPane(panelWrapper);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        scrollPane.setBorder(null);
        // Default unit increment is 1px, which makes the wheel crawl over a long settings page.
        scrollPane.getVerticalScrollBar().setUnitIncrement(16);
        scrollPane.getVerticalScrollBar().setBlockIncrement(120);

        // Use BorderLayout so the scroll pane fills all available vertical space in the tab
        JLabel titleLabel = new JLabel("Optionally, adjust general settings");
        titleLabel.setFont(hackFont);
        titleLabel.setBorder(new EmptyBorder(10, 10, 10, 10));

        JPanel outer = new JPanel(new BorderLayout());
        outer.add(titleLabel, BorderLayout.NORTH);
        JPanel scrollWrapper = new JPanel(new BorderLayout());
        scrollWrapper.setBorder(new EmptyBorder(0, 10, 10, 10));
        scrollWrapper.add(scrollPane, BorderLayout.CENTER);
        outer.add(scrollWrapper, BorderLayout.CENTER);

        return outer;
    }

    private void createRepeaterSettings(JPanel panel) {
        JLabel jlabel = new JLabel();
        jlabel.setFont(hackFont);
        jlabel.setText("• Repeater");
        jlabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        jlabel.setBorder(new EmptyBorder(20, 0, 10, 0));
        panel.add(jlabel);

        JCheckBox encryptOnModificationCheckbox = new JCheckBox("Update ciphertext ONLY when a modification is detected in the Repeater plaintext tab");
        encryptOnModificationCheckbox.setSelected(config.isRepeaterEncryptOnlyOnModification());
        encryptOnModificationCheckbox.setAlignmentX(Component.LEFT_ALIGNMENT);
        encryptOnModificationCheckbox.addActionListener(e -> {
            config.setRepeaterEncryptOnlyOnModification(encryptOnModificationCheckbox.isSelected());
        });
        panel.add(encryptOnModificationCheckbox);

        JLabel explanation = new JLabel("When disabled, it will ALWAYS run encrypt commands, and update the ciphertext before sending Repeater requests");
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

        JLabel explanation = new JLabel("If you want to disable logging, keep the 'Log data' option unchecked in all patterns");
        explanation.setFont(explanation.getFont().deriveFont(11f));
        explanation.setForeground(Color.GRAY);
        explanation.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(explanation);
    }

    /** Whole-config export/import, plus auto-load from a file maintained outside Burp. */
    private void createConfigTransferSettings(JPanel panel) {
        JLabel jlabel = new JLabel();
        jlabel.setFont(hackFont);
        jlabel.setText("• Configuration Export / Import");
        jlabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        jlabel.setBorder(new EmptyBorder(0, 0, 10, 0));
        panel.add(jlabel);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        buttons.setAlignmentX(Component.LEFT_ALIGNMENT);
        JButton exportAll = new JButton("Export all");
        exportAll.addActionListener(
                e -> PatternIo.export(uiComponent(), PatternIo.allPatterns(config), config.exportSettings()));
        JButton importAll = new JButton("Import all");
        importAll.addActionListener(e -> applyImport(PatternIo.importFrom(uiComponent(), config, true)));
        buttons.add(exportAll);
        buttons.add(importAll);
        panel.add(buttons);

        JPanel autoLoad = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        autoLoad.setAlignmentX(Component.LEFT_ALIGNMENT);
        autoLoad.setBorder(new EmptyBorder(10, 0, 0, 0));

        JCheckBox enabled = new JCheckBox("Auto-load patterns from file", config.isAutoLoadEnabled());
        JTextField pathField = new JTextField(config.getAutoLoadPath(), 34);
        JButton browse = new JButton("Browse");
        JSpinner interval = new JSpinner(new SpinnerNumberModel(config.getAutoLoadIntervalSeconds(), 1, 3600, 1));

        browse.addActionListener(e -> {
            JFileChooser chooser = new JFileChooser();
            chooser.setDialogTitle("Auto-load file");
            if (chooser.showOpenDialog(uiComponent()) == JFileChooser.APPROVE_OPTION) {
                pathField.setText(chooser.getSelectedFile().getPath());
            }
        });

        Runnable apply = () -> {
            config.setAutoLoad(enabled.isSelected(), pathField.getText().trim(), (Integer) interval.getValue());
            syncAutoLoader();
        };
        enabled.addActionListener(e -> apply.run());
        interval.addChangeListener(e -> apply.run());
        pathField.addActionListener(e -> apply.run());
        pathField.addFocusListener(new java.awt.event.FocusAdapter() {
            @Override
            public void focusLost(java.awt.event.FocusEvent e) {
                apply.run();
            }
        });

        JLabel autoLoadStatus = new JLabel(" ");
        autoLoadStatus.setFont(autoLoadStatus.getFont().deriveFont(11f));
        autoLoadStatus.setForeground(Color.GRAY);
        Runnable refreshStatus = () -> autoLoadStatus
                .setText(autoLoader == null ? " " : autoLoader.statusLine());
        // The poll runs on its own thread; this is the only way to see that it is still alive.
        if (autoLoadStatusTimer != null) {
            autoLoadStatusTimer.stop(); // an earlier build of this panel left one running
        }
        autoLoadStatusTimer = new javax.swing.Timer(1000, e -> refreshStatus.run());
        autoLoadStatusTimer.start();
        refreshStatus.run();

        autoLoad.add(enabled);
        autoLoad.add(pathField);
        autoLoad.add(browse);
        autoLoad.add(new JLabel("every"));
        autoLoad.add(interval);
        autoLoad.add(new JLabel("s"));
        JButton reloadNow = new JButton("Reload now");
        reloadNow.setToolTipText("Read and apply the file immediately, without waiting for the next check");
        reloadNow.addActionListener(e -> {
            apply.run(); // pick up an edited path or interval first
            if (autoLoader != null) {
                autoLoader.reloadNow(pathField.getText().trim());
            }
            refreshStatus.run();
        });
        autoLoad.add(Box.createHorizontalStrut(8));
        autoLoad.add(reloadNow);
        autoLoad.add(Box.createHorizontalStrut(12));
        autoLoad.add(autoLoadStatus);
        panel.add(autoLoad);

        JLabel hint = new JLabel(
                "Patterns with same name will be replaced and enabled. Settings inside this JSON will be ignored.");
        hint.setAlignmentX(Component.LEFT_ALIGNMENT);
        hint.setBorder(new EmptyBorder(4, 0, 0, 0));
        panel.add(hint);
    }

    private void createCacheSettings(JPanel panel) {
        JLabel jlabel = new JLabel();
        jlabel.setFont(hackFont);
        jlabel.setText("• Decryption Cache System");
        jlabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        jlabel.setBorder(new EmptyBorder(20, 0, 10, 0));
        panel.add(jlabel);

        JPanel cachePanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        cachePanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        cachePanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        cachePanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        String cacheSizeTextPrefix = "Cached data size: ";
        JLabel sizeLabel = new JLabel(cacheSizeTextPrefix + getCacheSizeFormatted());
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
                sizeLabel.setText(cacheSizeTextPrefix + getCacheSizeFormatted());
                JOptionPane.showMessageDialog(null, "Cache cleared successfully.");
            }
        });

        refreshButton.addActionListener(e -> {
            sizeLabel.setText(cacheSizeTextPrefix + getCacheSizeFormatted());
        });

        cachePanel.add(sizeLabel);
        cachePanel.add(clearButton);
        // Add space between buttons
        cachePanel.add(Box.createHorizontalStrut(5));
        cachePanel.add(refreshButton);

        panel.add(cachePanel);

        JLabel descriptionLabel = new JLabel("Cached data is stored in the Burp project file.");
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

    private void setPlaceholder(JTextField textField, String placeholder) {
        textField.setDisabledTextColor(Color.GRAY);
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