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
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.text.DefaultHighlighter;
import javax.swing.text.Highlighter;
import javax.swing.text.JTextComponent;

public class Utils {
    public static String getHash(byte[] cipherText) {
        MessageDigest md5 = null;
        try {
            // TODO: consider replacing to github.com/OpenHFT/Zero-Allocation-Hashing
            md5 = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
        }
        md5.update(cipherText);
        return new BigInteger(1, md5.digest()).toString(16);
    }

    public static <T extends Serializable> String serialize(ArrayList<T> list) throws IOException {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
                ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(list);
            return Base64.getEncoder().encodeToString(baos.toByteArray());
        }
    }

    public static <T extends Serializable> ArrayList<T> deserialize(String s)
            throws IOException, ClassNotFoundException {
        byte[] data = Base64.getDecoder().decode(s);
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return (ArrayList<T>) ois.readObject();
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
                    highlighter.addHighlight(
                        matcher.start(),
                        matcher.end(),
                        new DefaultHighlighter.DefaultHighlightPainter(color)
                    );
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

    public static JTextComponent findFirstTextComponent(Component component) {
        if (component instanceof JTextComponent text) {
            return text;
        }
        if (component instanceof Container container) {
            for (Component child : container.getComponents()) {
                JTextComponent found = findFirstTextComponent(child);
                if (found != null) return found;
            }
        }
        return null;
    }

}
