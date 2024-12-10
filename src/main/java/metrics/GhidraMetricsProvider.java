package metrics;

import docking.action.DockingAction;
import ghidra.framework.OSFileNotFoundException;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import gui.HalsteadGui;
import gui.SimilarityResultTable;
import impl.Lcs;
import impl.Ncd;
import impl.OpcodeFrequency;

import javax.swing.*;
import java.awt.*;

public class GhidraMetricsProvider extends ComponentProviderAdapter {

    private final GhidraMetricsPlugin plugin;
    private JPanel panel;
    private DockingAction action;

    private HalsteadGui halsteadGui;
    private SimilarityResultTable lcsTable;
    private SimilarityResultTable ncdTable;
    private SimilarityResultTable opcodeFreqTable;

    public GhidraMetricsProvider(GhidraMetricsPlugin ghidraMetricsPlugin, String pluginName) {
        super(ghidraMetricsPlugin.getTool(), pluginName, pluginName);
        this.plugin = ghidraMetricsPlugin;
        buildPanel();
    }

    // Customize GUI
    private void buildPanel() {
        panel = new JPanel(new BorderLayout());
        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.addTab("Entropy", new JPanel());

        halsteadGui = new HalsteadGui(plugin);
        tabbedPane.addTab("Halstead", halsteadGui.getPanel());

        tabbedPane.addTab("McCabe", new JPanel());

        lcsTable = new SimilarityResultTable(plugin, new Lcs());
        tabbedPane.addTab("LCS", lcsTable.getPanel());

        try {
            ncdTable = new SimilarityResultTable(plugin, new Ncd());
            tabbedPane.addTab("NCD", ncdTable.getPanel());
        } catch (OSFileNotFoundException e) {
            // TODO Handle more gracefully
            throw new RuntimeException(e);
        }

        opcodeFreqTable = new SimilarityResultTable(plugin, new OpcodeFrequency());
        tabbedPane.addTab("Opcode Freq", opcodeFreqTable.getPanel());

        panel.add(tabbedPane);
        setVisible(true);
    }

    public void handleProgramActivated() {
        halsteadGui.populateProgramTable();
        lcsTable.resetTable();
        ncdTable.resetTable();
        opcodeFreqTable.resetTable();
    }

    public void handleLocationChanged() {
        halsteadGui.populateFunctionTable();
    }

    @Override
    public JComponent getComponent() {
        return panel;
    }

}
