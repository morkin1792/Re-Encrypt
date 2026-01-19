package reencrypt;

import java.awt.Color;
import java.awt.Component;
import java.awt.Container;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
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

    public static <T extends Serializable> String serialize(ArrayList<T> list) throws IOException {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
                ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(list);
            return Base64.getEncoder().encodeToString(baos.toByteArray());
        }
    }

    public static <K extends Serializable, V extends Serializable> String serializeMap(HashMap<K, V> map)
            throws IOException {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
                ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(map);
            return Base64.getEncoder().encodeToString(baos.toByteArray());
        }
    }

    @SuppressWarnings("unchecked")
    public static <T extends Serializable> ArrayList<T> deserialize(String s)
            throws IOException, ClassNotFoundException {
        byte[] data = Base64.getDecoder().decode(s);
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return (ArrayList<T>) ois.readObject();
        }
    }

    @SuppressWarnings("unchecked")
    public static <K extends Serializable, V extends Serializable> HashMap<K, V> deserializeMap(String s)
            throws IOException, ClassNotFoundException {
        byte[] data = Base64.getDecoder().decode(s);
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return (HashMap<K, V>) ois.readObject();
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
