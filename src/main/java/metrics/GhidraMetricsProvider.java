package metrics;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.framework.OSFileNotFoundException;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.util.Msg;
import gui.SimilarityResultTable;
import impl.Lcs;
import impl.Ncd;
import impl.OpcodeFrequency;
import resources.Icons;

import javax.swing.*;
import java.awt.*;

public class GhidraMetricsProvider extends ComponentProviderAdapter {

    private final GhidraMetricsPlugin plugin;
    private JPanel panel;
    private DockingAction action;

    public GhidraMetricsProvider(GhidraMetricsPlugin ghidraMetricsPlugin, String pluginName) {
        super(ghidraMetricsPlugin.getTool(), pluginName, pluginName);
        this.plugin = ghidraMetricsPlugin;
        buildPanel();
        createActions();
    }

    // Customize GUI
    private void buildPanel() {
        panel = new JPanel(new BorderLayout());
        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.addTab("Entropy", new JPanel());
        tabbedPane.addTab("Halstead", new JPanel());
        tabbedPane.addTab("McCabe", new JPanel());

        SimilarityResultTable lcsTable = new SimilarityResultTable(plugin, new Lcs());
        tabbedPane.addTab("LCS", lcsTable.getPanel());

        try {
            SimilarityResultTable ncdTable = new SimilarityResultTable(plugin, new Ncd());
            tabbedPane.addTab("NCD", ncdTable.getPanel());
        } catch (OSFileNotFoundException e) {
            throw new RuntimeException(e);
        }
        
        SimilarityResultTable opcodeFreqTable = new SimilarityResultTable(plugin, new OpcodeFrequency());
        tabbedPane.addTab("Opcode Freq", opcodeFreqTable.getPanel());

        panel.add(tabbedPane);
        setVisible(true);
    }

    // TODO: Customize actions
    private void createActions() {
        action = new DockingAction("My Action", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {

                Msg.showInfo(getClass(), panel, "Custom Action", "Hello!");
            }
        };
        action.setToolBarData(new ToolBarData(Icons.REFRESH_ICON, null));
        action.setEnabled(true);
        action.markHelpUnnecessary();
        dockingTool.addLocalAction(this, action);
    }

    @Override
    public JComponent getComponent() {
        return panel;
    }

}
