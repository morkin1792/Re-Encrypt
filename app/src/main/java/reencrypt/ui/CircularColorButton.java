package reencrypt.ui;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.function.Function;

import javax.swing.JButton;
import javax.swing.JColorChooser;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.colorchooser.AbstractColorChooserPanel;

public class CircularColorButton extends JPanel {

    private CircleButton button;
    private JLabel label;

    /**
     * @param labelText    The text to display before the button
     * @param font         Font to use for the label
     * @param initialColor Initial color of the circular button
     * @param diameter     Diameter of the circular button
     */
    public CircularColorButton(String labelText, Font font, Color initialColor, int diameter) {
        setLayout(new FlowLayout(FlowLayout.LEFT, 5, 0)); // small gap between label and button

        label = new JLabel(labelText);
        if (font != null) {
            label.setFont(font);
        }
        add(label);

        button = new CircleButton(initialColor, diameter);
        add(button);
    }

    public Color getColor() {
        return button.getCurrentColor();
    }

    @Override
    public void setEnabled(boolean enabled) {
        button.setEnabled(enabled);
        label.setEnabled(enabled);
    }

    public void setColorAction(Function<Color, Void> action) {
        button.setColorAction(action);
    }

    /**
     * Inner circular button class
     */
    public static class CircleButton extends JButton {

        private Color currentColor;
        private Color disabledColor;
        private Function<Color, Void> newColorAction;

        public CircleButton(Color color, int diameter) {
            setColor(color);

            setOpaque(false);
            setContentAreaFilled(false);
            setFocusPainted(false);
            setBorderPainted(false);

            // Fix layout sizing
            setPreferredSize(new Dimension(diameter, diameter));
            setMinimumSize(new Dimension(diameter, diameter));
            setMaximumSize(new Dimension(diameter, diameter));
            JColorChooser chooser = new JColorChooser();

            addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {

                    chooser.setColor(currentColor);

                    // Get all default panels
                    AbstractColorChooserPanel[] panels = chooser.getChooserPanels();

                    // Remove the bad ones
                    for (AbstractColorChooserPanel panel : panels) {
                        if (!panel.getDisplayName().equals("Swatches") && !panel.getDisplayName().equals("RGB")) {
                            chooser.removeChooserPanel(panel);
                        }
                    }

                    // Show
                    JDialog dialog = JColorChooser.createDialog(
                            null, "Pick a color", true, chooser, ev -> {
                                Color chosenColor = chooser.getColor();
                                setColor(chosenColor);
                                newColorAction.apply(chosenColor);
                                repaint();
                            }, null);
                    dialog.setVisible(true);
                }
            });
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

            int size = Math.min(getWidth(), getHeight());
            int x = (getWidth() - size) / 2;
            int y = (getHeight() - size) / 2;

            if (isEnabled()) {
                g2.setColor(currentColor);
            } else {
                g2.setColor(disabledColor);
            }

            g2.fillOval(x, y, size, size);

            if (isEnabled()) {
                g2.setColor(Color.BLACK);
            } else {
                g2.setColor(Color.GRAY);
            }
            g2.drawOval(x, y, size - 1, size - 1);

            g2.dispose();
        }

        @Override
        public boolean contains(int x, int y) {
            int size = Math.min(getWidth(), getHeight());
            int centerX = getWidth() / 2;
            int centerY = getHeight() / 2;
            int dx = x - centerX;
            int dy = y - centerY;
            return dx * dx + dy * dy <= (size / 2) * (size / 2);
        }

        public void setColor(Color color) {
            this.currentColor = color;
            this.disabledColor = new Color(color.getRed(), color.getGreen(), color.getBlue(),
                    Math.max(color.getAlpha() - 200, 0));
        }

        public Color getCurrentColor() {
            return currentColor;
        }

        public void setColorAction(Function<Color, Void> action) {
            this.newColorAction = action;
        }
    }
}
