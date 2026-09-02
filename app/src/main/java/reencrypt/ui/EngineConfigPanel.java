package reencrypt.ui;

import java.util.HashMap;

import javax.swing.JPanel;

/**
 * Abstract base class for engine configuration panels.
 * Each engine (AES, RSA) extends this to provide its own config UI.
 * The panel is shown inside a modal config popup dialog.
 */
public abstract class EngineConfigPanel extends JPanel {

    /**
     * Extract the current parameters from the UI state.
     *
     * @return flat key-value map of engine parameters
     */
    public abstract HashMap<String, String> getParams();

    /**
     * Set a listener that is called on every UI change (for live validation).
     * The listener should call {@code validate()} and update the error label.
     *
     * @param listener callback to invoke on any change
     */
    public abstract void setOnChangeListener(Runnable listener);
}
