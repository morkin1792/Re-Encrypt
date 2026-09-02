package reencrypt;

import java.awt.Component;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import javax.swing.JMenuItem;

import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse.SelectionContext;
import reencrypt.ui.SettingsTab;

/**
 * Adds "Send to Re:Encrypt" context-menu items: a selection (sent as a ciphertext string)
 * or a whole request/response (the Analyze tab then auto-locates the ciphertext).
 */
public class AnalyzeContextMenuProvider implements ContextMenuItemsProvider {

    private final SettingsTab settingsTab;

    public AnalyzeContextMenuProvider(SettingsTab settingsTab) {
        this.settingsTab = settingsTab;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> items = new ArrayList<>();

        Optional<MessageEditorHttpRequestResponse> editorOpt = event.messageEditorRequestResponse();
        if (editorOpt.isPresent()) {
            MessageEditorHttpRequestResponse m = editorOpt.get();
            Optional<Range> sel = m.selectionOffsets();
            if (sel.isPresent()) {
                JMenuItem item = new JMenuItem("Send selection to Re:Encrypt");
                item.addActionListener(e -> {
                    String text = extractSelection(m, sel.get());
                    if (text != null && !text.isEmpty()) {
                        settingsTab.analyzePasted(text);
                    }
                });
                items.add(item);
                return items;
            }
            HttpRequestResponse rr = m.requestResponse();
            if (rr != null) {
                items.add(sendRequestItem(rr));
                return items;
            }
        }

        List<HttpRequestResponse> selected = event.selectedRequestResponses();
        if (selected != null && !selected.isEmpty()) {
            items.add(sendRequestItem(selected.get(0)));
        }
        return items;
    }

    private JMenuItem sendRequestItem(HttpRequestResponse rr) {
        JMenuItem item = new JMenuItem("Send request to Re:Encrypt");
        item.addActionListener(e -> {
            String req = rr.request() != null ? rr.request().toString() : "";
            boolean hasResp = rr.hasResponse();
            String resp = hasResp ? rr.response().toString() : null;
            settingsTab.analyzeRequestResponse(req, hasResp, resp);
        });
        return item;
    }

    private String extractSelection(MessageEditorHttpRequestResponse m, Range range) {
        try {
            boolean wantResponse = m.selectionContext() == SelectionContext.RESPONSE
                    && m.requestResponse().hasResponse();
            String full = wantResponse ? m.requestResponse().response().toString()
                    : m.requestResponse().request().toString();
            int a = Math.max(0, range.startIndexInclusive());
            int b = Math.min(full.length(), range.endIndexExclusive());
            return a < b ? full.substring(a, b) : null;
        } catch (Exception ex) {
            return null;
        }
    }
}
