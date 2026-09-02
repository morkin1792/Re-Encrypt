package reencrypt.ui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Rectangle;
import java.awt.Toolkit;
import java.awt.event.ActionEvent;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.awt.geom.Rectangle2D;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import javax.swing.AbstractAction;
import javax.swing.ActionMap;
import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.ButtonGroup;
import javax.swing.InputMap;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.JToggleButton;
import javax.swing.KeyStroke;
import javax.swing.SwingUtilities;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.AbstractDocument;
import javax.swing.text.AttributeSet;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultHighlighter;
import javax.swing.text.Document;
import javax.swing.text.DocumentFilter;
import javax.swing.text.Highlighter;
import javax.swing.undo.UndoManager;

import reencrypt.Config;
import reencrypt.analysis.CiphertextLocator;

/**
 * Intruder-style editor for picking the ciphertext to analyze. The content (a pasted
 * string, or a sent request/response) is shown in an editable monospaced area; the chosen
 * span is wrapped with {@code §…§} markers and highlighted. Three buttons drive it:
 * Add (wrap the current selection), Clear (remove markers), Auto (clear + auto-locate).
 * Deleting either marker removes both and clears the mark. Analysis fires on every button.
 */
public class MarkerEditor extends JPanel {

    private static final char MARK = '§'; // §
    private static final String MARK_S = String.valueOf(MARK);
    private static final Color HILITE = new Color(255, 213, 0, 110);
    // Minimum non-whitespace context around the marked region needed to suggest a regex
    private static final int MIN_ANCHOR_CONTEXT = 5;

    private final Config config;
    private Runnable onAnalyze;

    private final JTextArea textArea;
    private LineGutter gutter;
    private final Highlighter.HighlightPainter painter = new DefaultHighlighter.DefaultHighlightPainter(HILITE);
    private final UndoManager undo = new UndoManager();
    private boolean programmatic; // bypass marker protection during our own edits

    // Bottom search bar (find within the editor content)
    private JTextField searchField;
    private JCheckBox caseBox;
    private JCheckBox regexBox;
    private JLabel countLabel;
    private final List<int[]> matches = new ArrayList<>();
    private final List<Object> searchTags = new ArrayList<>();
    private int matchIndex = -1;
    private final Highlighter.HighlightPainter searchPainter =
            new DefaultHighlighter.DefaultHighlightPainter(new Color(255, 150, 0, 80));
    private final Highlighter.HighlightPainter currentMatchPainter =
            new DefaultHighlighter.DefaultHighlightPainter(new Color(255, 120, 0, 180));

    private final JPanel togglePanel;
    private final JToggleButton reqToggle;
    private final JToggleButton respToggle;

    private boolean pasted;
    private boolean showingResponse;
    private String requestDoc; // current text for the request view (incl. markers/edits)
    private String responseDoc; // current text for the response view, or null
    private boolean reqAutoRan;
    private boolean respAutoRan;

    public MarkerEditor(Config config) {
        super(new BorderLayout());
        this.config = config;

        // Top bar: Request/Response toggle + Add/Clear/Auto buttons
        JPanel topBar = new JPanel(new BorderLayout());

        togglePanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        reqToggle = new JToggleButton("Request", true);
        respToggle = new JToggleButton("Response");
        ButtonGroup group = new ButtonGroup();
        group.add(reqToggle);
        group.add(respToggle);
        reqToggle.addActionListener(e -> switchTo(false));
        respToggle.addActionListener(e -> switchTo(true));
        togglePanel.add(reqToggle);
        togglePanel.add(respToggle);
        togglePanel.setVisible(false);
        topBar.add(togglePanel, BorderLayout.WEST);

        JPanel markBtns = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
        JButton addBtn = new JButton("Add " + MARK);
        JButton clearBtn = new JButton("Clear " + MARK);
        JButton autoBtn = new JButton("Auto " + MARK);
        addBtn.setToolTipText("Wrap the current selection, or drop a marker at the cursor (two clicks)");
        clearBtn.setToolTipText("Remove the markers");
        autoBtn.setToolTipText("Auto-detect the likely ciphertext");
        addBtn.addActionListener(e -> { add(); fireAnalyze(); });
        clearBtn.addActionListener(e -> { clearMarkers(); fireAnalyze(); });
        autoBtn.addActionListener(e -> { auto(); fireAnalyze(); });
        markBtns.add(addBtn);
        markBtns.add(clearBtn);
        markBtns.add(autoBtn);
        topBar.add(markBtns, BorderLayout.EAST);

        // A thin divider between the buttons and the editor
        JPanel north = new JPanel();
        north.setLayout(new BoxLayout(north, BoxLayout.Y_AXIS));
        north.add(topBar);
        north.add(new JSeparator());
        add(north, BorderLayout.NORTH);

        textArea = new JTextArea();
        textArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        textArea.setLineWrap(true);
        textArea.setWrapStyleWord(false);
        AbstractDocument doc = (AbstractDocument) textArea.getDocument();
        doc.setDocumentFilter(new MarkerFilter());

        // Re-analyze live as the user edits inside a marked region; auto-mark a fresh paste
        doc.addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) {
                maybeAutoOnPaste(e);
                onUserEdit();
                refreshGutter();
            }

            public void removeUpdate(DocumentEvent e) {
                onUserEdit();
                refreshGutter();
            }

            public void changedUpdate(DocumentEvent e) { }
        });

        // Undo/redo, recording only user (non-programmatic) edits
        doc.addUndoableEditListener(e -> {
            if (!programmatic) {
                undo.addEdit(e.getEdit());
            }
        });
        installUndoKeys();

        JScrollPane scroll = new JScrollPane(textArea);
        scroll.setBorder(BorderFactory.createEmptyBorder());
        gutter = new LineGutter();
        scroll.setRowHeaderView(gutter);
        // Re-wrapping on resize shifts line positions → repaint the gutter to match
        textArea.addComponentListener(new ComponentAdapter() {
            @Override
            public void componentResized(ComponentEvent e) {
                refreshGutter();
            }
        });
        add(scroll, BorderLayout.CENTER);

        add(buildSearchBar(), BorderLayout.SOUTH);
    }

    /** Recompute the gutter width/height and repaint it (after layout settles). */
    private void refreshGutter() {
        if (gutter == null) {
            return;
        }
        SwingUtilities.invokeLater(() -> {
            gutter.revalidate();
            gutter.repaint();
        });
    }

    private void onUserEdit() {
        if (programmatic) {
            return;
        }
        // Only re-analyze live when a marked region exists (we analyze the marked text only)
        if (markerOffsets() != null) {
            fireAnalyze();
        }
        // Keep the search results in sync with edits
        if (searchField != null && !searchField.getText().isEmpty()) {
            recomputeSearch();
        }
    }

    // ===== bottom search bar =====

    private JPanel buildSearchBar() {
        JPanel bar = new JPanel(new BorderLayout(6, 0));
        bar.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 0, 0, new Color(0, 0, 0, 40)),
                BorderFactory.createEmptyBorder(3, 6, 3, 6)));

        JLabel find = new JLabel("Find:");
        find.setFont(find.getFont().deriveFont(11f));

        searchField = new JTextField();

        countLabel = new JLabel("");
        countLabel.setFont(countLabel.getFont().deriveFont(11f));
        countLabel.setForeground(new Color(120, 120, 120));

        caseBox = new JCheckBox("Aa");
        caseBox.setToolTipText("Case sensitive");
        regexBox = new JCheckBox(".*");
        regexBox.setToolTipText("Regular expression");

        JButton prev = new JButton("▲");
        JButton next = new JButton("▼");
        prev.setToolTipText("Previous match");
        next.setToolTipText("Next match (Enter)");

        JPanel right = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
        right.add(countLabel);
        right.add(caseBox);
        right.add(regexBox);
        right.add(prev);
        right.add(next);

        bar.add(find, BorderLayout.WEST);
        bar.add(searchField, BorderLayout.CENTER);
        bar.add(right, BorderLayout.EAST);

        searchField.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { recomputeSearch(); }

            public void removeUpdate(DocumentEvent e) { recomputeSearch(); }

            public void changedUpdate(DocumentEvent e) { }
        });
        caseBox.addActionListener(e -> recomputeSearch());
        regexBox.addActionListener(e -> recomputeSearch());
        next.addActionListener(e -> moveMatch(1));
        prev.addActionListener(e -> moveMatch(-1));
        searchField.addActionListener(e -> moveMatch(1)); // Enter → next
        searchField.getInputMap(JComponent.WHEN_FOCUSED).put(
                KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, InputEvent.SHIFT_DOWN_MASK), "reencrypt-find-prev");
        searchField.getActionMap().put("reencrypt-find-prev", new AbstractAction() {
            public void actionPerformed(ActionEvent e) { moveMatch(-1); }
        });
        return bar;
    }

    /** Recompute matches for the current query/options, highlight them all, and show the first. */
    private void recomputeSearch() {
        clearSearchHighlights();
        matches.clear();
        matchIndex = -1;
        String q = searchField == null ? "" : searchField.getText();
        if (q.isEmpty()) {
            countLabel.setText("");
            countLabel.setForeground(new Color(120, 120, 120));
            return;
        }
        Pattern pattern;
        try {
            int flags = caseBox.isSelected() ? 0 : Pattern.CASE_INSENSITIVE;
            pattern = regexBox.isSelected() ? Pattern.compile(q, flags) : Pattern.compile(Pattern.quote(q), flags);
        } catch (PatternSyntaxException ex) {
            countLabel.setText("bad regex");
            countLabel.setForeground(new Color(200, 50, 50));
            return;
        }
        countLabel.setForeground(new Color(120, 120, 120));
        Matcher m = pattern.matcher(textArea.getText());
        while (m.find()) {
            if (m.end() > m.start()) { // skip zero-width matches
                matches.add(new int[] { m.start(), m.end() });
            }
        }
        if (matches.isEmpty()) {
            countLabel.setText("0 matches");
            return;
        }
        matchIndex = 0;
        applySearchHighlights();
        showCurrent();
    }

    private void applySearchHighlights() {
        Highlighter h = textArea.getHighlighter();
        for (int i = 0; i < matches.size(); i++) {
            int[] mm = matches.get(i);
            try {
                searchTags.add(h.addHighlight(mm[0], mm[1], i == matchIndex ? currentMatchPainter : searchPainter));
            } catch (BadLocationException ex) {
                // stale offset — ignore
            }
        }
        countLabel.setText((matchIndex + 1) + " / " + matches.size());
    }

    private void clearSearchHighlights() {
        Highlighter h = textArea.getHighlighter();
        for (Object t : searchTags) {
            h.removeHighlight(t);
        }
        searchTags.clear();
    }

    private void moveMatch(int delta) {
        if (matches.isEmpty()) {
            recomputeSearch();
            return;
        }
        matchIndex = (matchIndex + delta + matches.size()) % matches.size();
        clearSearchHighlights();
        applySearchHighlights();
        showCurrent();
    }

    private void showCurrent() {
        if (matchIndex < 0 || matchIndex >= matches.size()) {
            return;
        }
        try {
            Rectangle2D r = textArea.modelToView2D(matches.get(matchIndex)[0]);
            if (r != null) {
                textArea.scrollRectToVisible(r.getBounds());
            }
        } catch (BadLocationException ex) {
            // ignore
        }
    }

    /** When text is pasted/added into an otherwise-empty editor, auto-mark it. */
    private void maybeAutoOnPaste(DocumentEvent e) {
        if (programmatic) {
            return;
        }
        String full = textArea.getText();
        int off = e.getOffset();
        int len = e.getLength();
        if (off + len > full.length()) {
            return;
        }
        String inserted = full.substring(off, off + len);
        String rest = full.substring(0, off) + full.substring(off + len);
        // The inserted chunk is the only real content (editor was empty/whitespace) → Auto
        if (rest.isBlank() && inserted.trim().length() >= 4) {
            SwingUtilities.invokeLater(() -> {
                auto();
                fireAnalyze();
            });
        }
    }

    private void installUndoKeys() {
        InputMap im = textArea.getInputMap(JComponent.WHEN_FOCUSED);
        ActionMap am = textArea.getActionMap();
        int mask = Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx();
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_Z, mask), "reencrypt-undo");
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_Y, mask), "reencrypt-redo");
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_Z, mask | InputEvent.SHIFT_DOWN_MASK), "reencrypt-redo");
        am.put("reencrypt-undo", new AbstractAction() {
            public void actionPerformed(ActionEvent e) { doUndoRedo(true); }
        });
        am.put("reencrypt-redo", new AbstractAction() {
            public void actionPerformed(ActionEvent e) { doUndoRedo(false); }
        });
    }

    private void doUndoRedo(boolean isUndo) {
        programmatic = true;
        try {
            if (isUndo && undo.canUndo()) {
                undo.undo();
            } else if (!isUndo && undo.canRedo()) {
                undo.redo();
            }
        } catch (RuntimeException ex) {
            // CannotUndo/RedoException — ignore
        } finally {
            programmatic = false;
        }
        reapplyHighlight();
        fireAnalyze();
    }

    public void setOnAnalyze(Runnable r) {
        this.onAnalyze = r;
    }

    /** Show a sent request (and response, when present); auto-marks the request. */
    public void setContent(String reqText, boolean hasResponse, String respText) {
        pasted = false;
        requestDoc = normalize(reqText);
        responseDoc = hasResponse ? normalize(respText) : null;
        reqAutoRan = false;
        respAutoRan = false;
        showingResponse = false;
        togglePanel.setVisible(hasResponse);
        reqToggle.setSelected(true);
        loadActive();
    }

    /** Show a pasted/selected ciphertext (no request context, no toggle). */
    public void setPastedContent(String text) {
        pasted = true;
        requestDoc = normalize(text);
        responseDoc = null;
        reqAutoRan = false;
        showingResponse = false;
        togglePanel.setVisible(false);
        reqToggle.setSelected(true);
        loadActive();
    }

    /** True when the Response view is active (false for Request or pasted content). */
    public boolean isShowingResponse() {
        return showingResponse;
    }

    /**
     * A capture regex (group 1) for the marked region, using short surrounding text as
     * literal anchors, e.g. {@code "data":"(.+?)"}. The capture is always a {@code (.+)}
     * group (never a giant literal); newlines in the anchors match either CRLF or LF, and a
     * body capture anchors on the blank line that ends the headers rather than on (changing)
     * header values. Returns {@code ""} when the marked region is essentially the whole
     * content (fewer than {@link #MIN_ANCHOR_CONTEXT} non-whitespace chars around it) — there
     * is nothing reliable to anchor on, so we let the user write the regex themselves.
     */
    public String getCaptureRegex() {
        String[] ap = anchorParts();
        if (ap == null) {
            return "";
        }
        String ct = getCurrentCiphertext();
        boolean multiline = ct != null && ct.indexOf('\n') >= 0;
        String group = ap[1].isEmpty() ? "(.+)" : "(.+?)";
        return (multiline ? "(?s)" : "") + escapeRegex(ap[0]) + group + escapeRegex(ap[1]);
    }

    /**
     * A capture regex that extracts only the {@code part}-th of {@code total} segments of the
     * marked region, where the segments are separated by {@code delimiter} (for a value that is
     * several concatenated ciphertexts). Each segment is matched as {@code [^<delim>]+}; the
     * chosen one becomes group 1. For an equal-size split ({@code delimiter == '\0'}) or a
     * single part, falls back to {@link #getCaptureRegex()}. Returns {@code ""} when there isn't
     * enough surrounding context.
     */
    public String getCaptureRegexForPart(int part, int total, char delimiter) {
        if (total <= 1 || delimiter == '\0') {
            return getCaptureRegex();
        }
        String[] ap = anchorParts();
        if (ap == null) {
            return "";
        }
        String d = escapeRegex(String.valueOf(delimiter));      // literal delimiter outside a class
        String seg = "[^" + classEscape(delimiter) + "]+";      // one segment (no delimiter inside)
        StringBuilder sb = new StringBuilder();
        sb.append(escapeRegex(ap[0]));
        for (int i = 0; i < part; i++) {
            sb.append(seg).append(d);
        }
        sb.append("(").append(seg).append(")");
        for (int i = part + 1; i < total; i++) {
            sb.append(d).append(seg);
        }
        sb.append(escapeRegex(ap[1]));
        return sb.toString();
    }

    /** Escape a delimiter for use inside a {@code [^...]} character class. */
    private static String classEscape(char c) {
        return (c == ']' || c == '\\' || c == '^' || c == '-') ? "\\" + c : String.valueOf(c);
    }

    /**
     * {leftAnchor, rightAnchor} (raw, unescaped) for the marked region, or null when nothing
     * is marked or the surrounding text is too short to anchor on reliably.
     */
    private String[] anchorParts() {
        String t = textArea.getText();
        int a = t.indexOf(MARK);
        int b = a < 0 ? -1 : t.indexOf(MARK, a + 1);
        if (a < 0 || b < 0) {
            return null;
        }
        String before = t.substring(0, a);
        String after = t.substring(b + 1);
        if (nonWhitespaceCount(before) + nonWhitespaceCount(after) < MIN_ANCHOR_CONTEXT) {
            return null; // basically just the ciphertext — nothing reliable to anchor on
        }
        return new String[] { tailAnchor(before), headAnchor(after) };
    }

    private static int nonWhitespaceCount(String s) {
        int n = 0;
        for (int i = 0; i < s.length(); i++) {
            if (!Character.isWhitespace(s.charAt(i))) {
                n++;
            }
        }
        return n;
    }

    /**
     * Up to ~30 chars of context before the selection. If the capture is in the body, anchor
     * on the blank line that ends the headers (plus any body text right before the capture) —
     * never on header values, which change between messages. Otherwise anchor on the current
     * line (from its start).
     */
    private static String tailAnchor(String before) {
        if (before.isEmpty()) {
            return "";
        }
        int sep = before.indexOf("\n\n");
        if (sep >= 0) {
            String anchor = "\n\n" + before.substring(sep + 2);
            return anchor.length() > 30 ? anchor.substring(anchor.length() - 30) : anchor;
        }
        int nl = before.lastIndexOf('\n');
        String anchor = nl >= 0 ? before.substring(nl) : before; // include the leading newline
        return anchor.length() > 24 ? anchor.substring(anchor.length() - 24) : anchor;
    }

    /** Up to ~12 chars of context after the selection; crosses line breaks if the same-line part is short. */
    private static String headAnchor(String after) {
        if (after.isEmpty()) {
            return "";
        }
        int nl = after.indexOf('\n');
        String sameLine = nl >= 0 ? after.substring(0, nl) : after;
        String anchor = sameLine.length() >= 2 ? sameLine : after;
        return anchor.length() > 12 ? anchor.substring(0, 12) : anchor;
    }

    private static String escapeRegex(String s) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
            case '\n': sb.append("\\r?\\n"); break; // the live message uses CRLF; match CRLF or LF
            case '\r': break; // normalized out of the editor text; ignore
            case '\t': sb.append("\\t"); break;
            default:
                if ("\\.[]{}()*+-?^$|".indexOf(c) >= 0) {
                    sb.append('\\');
                }
                sb.append(c);
            }
        }
        return sb.toString();
    }

    /** The text between the two markers, or null when nothing is marked. */
    public String getCurrentCiphertext() {
        String t = textArea.getText();
        int a = t.indexOf(MARK);
        int b = a < 0 ? -1 : t.indexOf(MARK, a + 1);
        if (a >= 0 && b >= 0) {
            return t.substring(a + 1, b);
        }
        return null;
    }

    // ===== view management =====

    private void switchTo(boolean response) {
        if (response == showingResponse) {
            return;
        }
        saveActiveDoc();
        showingResponse = response;
        loadActive();
        fireAnalyze();
    }

    private void saveActiveDoc() {
        String t = textArea.getText();
        if (showingResponse) {
            responseDoc = t;
        } else {
            requestDoc = t;
        }
    }

    private void loadActive() {
        String doc = showingResponse ? responseDoc : requestDoc;
        setTextProgrammatic(doc == null ? "" : doc);
        textArea.getHighlighter().removeAllHighlights();
        boolean autoRan = showingResponse ? respAutoRan : reqAutoRan;
        if (!autoRan && doc != null && !doc.isEmpty()) {
            auto();
            if (showingResponse) {
                respAutoRan = true;
            } else {
                reqAutoRan = true;
            }
        } else {
            reapplyHighlight();
        }
        fireAnalyze();
        // Re-apply any active search to the freshly loaded content; otherwise make sure the view
        // sits at the top (defends against a stray scroll offset from row-header relayout).
        if (searchField != null && !searchField.getText().isEmpty()) {
            recomputeSearch();
        } else {
            SwingUtilities.invokeLater(() -> {
                textArea.setCaretPosition(0);
                textArea.scrollRectToVisible(new Rectangle(0, 0, 1, 1));
                refreshGutter();
            });
        }
    }

    // ===== marker actions =====

    private void auto() {
        stripAllMarkers();
        String text = textArea.getText();
        if (text.isEmpty()) {
            return;
        }
        int[] span = CiphertextLocator.locate(text, config, !pasted);
        addMarkers(span[0], span[1]);
    }

    private void clearMarkers() {
        stripAllMarkers();
    }

    /**
     * Add markers. With a selection, wrap it (replacing any existing markers). With no
     * selection, drop a single marker at the caret; a second press completes the pair
     * (then the region is highlighted). Only the first pair of markers is ever considered.
     */
    private void add() {
        if (textArea.getSelectionStart() != textArea.getSelectionEnd()) {
            addFromSelection();
            return;
        }
        int caret = textArea.getCaretPosition();
        programmatic = true;
        try {
            textArea.getDocument().insertString(caret, MARK_S, null);
        } catch (BadLocationException ex) {
            // ignore
        } finally {
            programmatic = false;
        }
        int[] mk = markerOffsets();
        textArea.getHighlighter().removeAllHighlights();
        if (mk != null) {
            try {
                textArea.getHighlighter().addHighlight(mk[0], mk[1] + 1, painter);
            } catch (BadLocationException ex) {
                // ignore
            }
            textArea.setCaretPosition(mk[0] + 1);
            textArea.moveCaretPosition(mk[1]);
        }
    }

    private void addFromSelection() {
        String t = textArea.getText();
        int s = textArea.getSelectionStart();
        int e = textArea.getSelectionEnd();
        if (s == e) {
            return; // nothing selected
        }
        // Map the selection onto the marker-free text.
        int ns = s;
        int ne = e;
        for (int i = 0; i < t.length(); i++) {
            if (t.charAt(i) == MARK) {
                if (i < s) {
                    ns--;
                }
                if (i < e) {
                    ne--;
                }
            }
        }
        String stripped = t.replace(MARK_S, "");
        ns = Math.max(0, Math.min(ns, stripped.length()));
        ne = Math.max(0, Math.min(ne, stripped.length()));
        if (ns >= ne) {
            return;
        }
        setTextProgrammatic(stripped);
        addMarkers(ns, ne);
    }

    private void addMarkers(int start, int end) {
        programmatic = true;
        try {
            Document d = textArea.getDocument();
            d.insertString(start, MARK_S, null);
            d.insertString(end + 1, MARK_S, null);
        } catch (BadLocationException ex) {
            // out of range — give up silently
        } finally {
            programmatic = false;
        }
        int hiStart = start;
        int hiEnd = end + 2; // include both markers
        textArea.getHighlighter().removeAllHighlights();
        try {
            textArea.getHighlighter().addHighlight(hiStart, hiEnd, painter);
        } catch (BadLocationException ex) {
            // ignore
        }
        // Select the inner text so the user can edit it immediately.
        textArea.setCaretPosition(start + 1);
        textArea.moveCaretPosition(end + 1);
        textArea.requestFocusInWindow();
    }

    private void stripAllMarkers() {
        String t = textArea.getText();
        if (t.indexOf(MARK) < 0) {
            textArea.getHighlighter().removeAllHighlights();
            return;
        }
        setTextProgrammatic(t.replace(MARK_S, ""));
        textArea.getHighlighter().removeAllHighlights();
    }

    private void reapplyHighlight() {
        String t = textArea.getText();
        int a = t.indexOf(MARK);
        int b = a < 0 ? -1 : t.indexOf(MARK, a + 1);
        textArea.getHighlighter().removeAllHighlights();
        if (a >= 0 && b >= 0) {
            try {
                textArea.getHighlighter().addHighlight(a, b + 1, painter);
            } catch (BadLocationException ex) {
                // ignore
            }
        }
    }

    // ===== helpers =====

    private void setTextProgrammatic(String text) {
        programmatic = true;
        try {
            textArea.setText(text);
            textArea.setCaretPosition(0);
        } finally {
            programmatic = false;
        }
    }

    private void fireAnalyze() {
        if (onAnalyze != null) {
            onAnalyze.run();
        }
    }

    private static String normalize(String s) {
        return s == null ? "" : s.replace("\r\n", "\n");
    }

    /**
     * Keeps markers consistent: an edit that touches a marker is performed as the user
     * intended (delete the whole selected range, replace it, etc.), then any leftover
     * markers are stripped — so deleting one marker, or a selection that spans markers,
     * removes all markers (and the selected text) rather than just the marker characters.
     */
    private class MarkerFilter extends DocumentFilter {
        @Override
        public void remove(FilterBypass fb, int offset, int length) throws BadLocationException {
            int[] mk = markerOffsets();
            fb.remove(offset, length);
            if (!programmatic && mk != null && touches(offset, length, mk)) {
                stripMarkers(fb);
            }
        }

        @Override
        public void replace(FilterBypass fb, int offset, int length, String text, AttributeSet attrs)
                throws BadLocationException {
            int[] mk = markerOffsets();
            fb.replace(offset, length, text, attrs);
            if (!programmatic && length > 0 && mk != null && touches(offset, length, mk)) {
                stripMarkers(fb);
            }
        }

        @Override
        public void insertString(FilterBypass fb, int offset, String string, AttributeSet attr)
                throws BadLocationException {
            fb.insertString(offset, string, attr);
        }

        /** Remove every remaining marker, then clear the highlight and refresh analysis. */
        private void stripMarkers(FilterBypass fb) throws BadLocationException {
            Document d = fb.getDocument();
            String t = d.getText(0, d.getLength());
            for (int i = t.length() - 1; i >= 0; i--) {
                if (t.charAt(i) == MARK) {
                    fb.remove(i, 1);
                }
            }
            SwingUtilities.invokeLater(() -> {
                textArea.getHighlighter().removeAllHighlights();
                fireAnalyze();
            });
        }

        private boolean touches(int off, int len, int[] mk) {
            int end = off + len;
            return (mk[0] >= off && mk[0] < end) || (mk[1] >= off && mk[1] < end);
        }
    }

    private int[] markerOffsets() {
        String t = textArea.getText();
        int a = t.indexOf(MARK);
        if (a < 0) {
            return null;
        }
        int b = t.indexOf(MARK, a + 1);
        if (b < 0) {
            return null;
        }
        return new int[] { a, b };
    }

    @Override
    public Dimension getPreferredSize() {
        Dimension d = super.getPreferredSize();
        d.width = Math.max(d.width, 360);
        return d;
    }

    /**
     * Left gutter showing a line number for each non-empty logical line, aligned with the
     * text area's lines (which may wrap). Lives in the scroll pane's row header so it scrolls
     * in sync with the content.
     */
    private class LineGutter extends JComponent {
        private static final int PAD = 8;

        LineGutter() {
            setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        }

        @Override
        public Dimension getPreferredSize() {
            int lines = Math.max(1, textArea.getLineCount());
            FontMetrics fm = getFontMetrics(getFont());
            int digits = Math.max(2, Integer.toString(lines).length());
            int w = fm.charWidth('0') * digits + PAD + 4;
            // Use the text area's already-laid-out height (never getPreferredSize(), which would
            // re-wrap the text at the wrong width from inside the row-header layout and leave
            // phantom blank space above the content).
            int h = textArea.getHeight();
            return new Dimension(w, h > 0 ? h : 1);
        }

        @Override
        protected void paintComponent(Graphics g) {
            super.paintComponent(g);
            Rectangle clip = g.getClipBounds();
            g.setColor(textArea.getBackground());
            g.fillRect(clip.x, clip.y, clip.width, clip.height);
            g.setColor(new Color(0, 0, 0, 30));
            g.drawLine(getWidth() - 1, clip.y, getWidth() - 1, clip.y + clip.height);

            g.setFont(getFont());
            g.setColor(new Color(130, 130, 130));
            FontMetrics fm = g.getFontMetrics();
            Document d = textArea.getDocument();
            try {
                int lineCount = textArea.getLineCount();
                for (int i = 0; i < lineCount; i++) {
                    int start = textArea.getLineStartOffset(i);
                    int end = textArea.getLineEndOffset(i);
                    String line = d.getText(start, end - start);
                    if (line.replace("\n", "").trim().isEmpty()) {
                        continue; // no number for blank lines
                    }
                    Rectangle2D r = textArea.modelToView2D(start);
                    if (r == null) {
                        continue;
                    }
                    int y = (int) r.getY();
                    int h = (int) r.getHeight();
                    if (y + h < clip.y || y > clip.y + clip.height) {
                        continue; // outside the visible slice
                    }
                    String num = Integer.toString(i + 1);
                    int tx = getWidth() - fm.stringWidth(num) - PAD;
                    g.drawString(num, tx, y + fm.getAscent());
                }
            } catch (BadLocationException ex) {
                // ignore
            }
        }
    }
}
