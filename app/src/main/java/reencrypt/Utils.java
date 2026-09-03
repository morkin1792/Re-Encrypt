package reencrypt;

import java.awt.Color;
import java.awt.Component;
import java.awt.Container;
import java.io.IOException;
import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.text.DefaultHighlighter;
import javax.swing.text.Highlighter;
import javax.swing.text.JTextComponent;

import net.openhft.hashing.LongHashFunction;

public class Utils {

    public static long getHash(byte[] data) {
        // XXH3 - fast 64-bit non-cryptographic hash
        return LongHashFunction.xx3().hashBytes(data);
    }

    /**
     * Highlight exact character ranges in every text component under {@code component}. Ranges are
     * clamped to each component's length (so a short sibling like a search box is left untouched).
     * Used by the print editor to highlight precisely the decrypted regions.
     */
    public static void highlightRanges(Component component, java.util.List<int[]> ranges, Color color) {
        if (component instanceof JTextComponent textComponent) {
            try {
                Highlighter highlighter = textComponent.getHighlighter();
                highlighter.removeAllHighlights();
                int len = textComponent.getDocument().getLength();
                for (int[] r : ranges) {
                    int s = Math.max(0, Math.min(r[0], len));
                    int e = Math.max(s, Math.min(r[1], len));
                    if (e > s) {
                        highlighter.addHighlight(s, e, new DefaultHighlighter.DefaultHighlightPainter(color));
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        if (component instanceof Container container) {
            for (Component child : container.getComponents()) {
                highlightRanges(child, ranges, color);
            }
        }
    }

    public static void highlightTextComponents(Component component, Pattern pattern, Color color) {
        if (component instanceof JTextComponent textComponent) {
            try {
                Highlighter highlighter = textComponent.getHighlighter();
                highlighter.removeAllHighlights();

                String text = textComponent.getText();
                Matcher matcher = pattern.matcher(text);
                while (matcher.find()) {
                    highlighter.addHighlight(matcher.start(), matcher.end(),
                            new DefaultHighlighter.DefaultHighlightPainter(color));
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        if (component instanceof Container container) {
            for (Component child : container.getComponents()) {
                highlightTextComponents(child, pattern, color);
            }
        }
    }

    public static JTextComponent findMainTextComponent(Component component) {
        ArrayList<JTextComponent> candidates = new ArrayList<>();
        collectTextComponents(component, candidates);

        for (JTextComponent c : candidates) {
            if (!(c instanceof javax.swing.JTextField)) {
                return c;
            }
        }

        if (!candidates.isEmpty()) {
            return candidates.get(0);
        }
        return null;
    }

    private static void collectTextComponents(Component component, ArrayList<JTextComponent> list) {
        if (component instanceof JTextComponent text) {
            if (text.isFocusable() && text.isShowing()) {
                list.add(text);
            }
        }
        if (component instanceof Container container) {
            for (Component child : container.getComponents()) {
                collectTextComponents(child, list);
            }
        }
    }

    public static Color hexToColor(String hex) {
        if (hex.startsWith("#")) {
            hex = hex.substring(1);
        }

        if (hex.length() == 8) {
            // Note: If hex is RGBA (e.g. CSS style), might need to rotate the string.
            // This implementation assumes the standard Java ARGB format.
            long longValue = Long.parseLong(hex, 16);
            return new Color((int) longValue, true);
        }

        // Handle standard 6-digit hex
        return Color.decode("#" + hex);
    }
}
