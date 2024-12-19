package metrics;

import ghidra.framework.OSFileNotFoundException;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import gui.*;
import impl.Lcs;
import impl.Ncd;
import impl.OpcodeFrequency;

import javax.swing.*;
import java.awt.*;

public class GhidraMetricsProvider extends ComponentProviderAdapter {

    private final GhidraMetricsPlugin plugin;
    private JPanel panel;

    private EntropyGui entropyGui;
    private HalsteadGui halsteadGui;
    private McCabeGui mcCabeGui;
    private SimilarityResultTable lcsTable;
    private SimilarityResultTable ncdTable;
    private SimilarityResultTable opcodeFreqTable;
    private RopSimilarityGui ropSimilarityGui;

    public GhidraMetricsProvider(GhidraMetricsPlugin ghidraMetricsPlugin, String pluginName) {
        super(ghidraMetricsPlugin.getTool(), pluginName, pluginName);
        this.plugin = ghidraMetricsPlugin;
        buildPanel();
    }

    // Customize GUI
    private void buildPanel() {
        panel = new JPanel(new BorderLayout());
        JTabbedPane tabbedPane = new JTabbedPane();

        entropyGui = new EntropyGui(plugin);
        tabbedPane.addTab("Entropy", entropyGui.getPanel());

        halsteadGui = new HalsteadGui(plugin);
        tabbedPane.addTab("Halstead", halsteadGui.getPanel());

        mcCabeGui = new McCabeGui(plugin);
        tabbedPane.addTab("McCabe", mcCabeGui.getPanel());

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

        ropSimilarityGui = new RopSimilarityGui(plugin);
        tabbedPane.addTab("ROP", ropSimilarityGui.getPanel());

        panel.add(tabbedPane);
        setVisible(true);
    }

    public void handleProgramActivated() {
        halsteadGui.populateProgramTable();
        lcsTable.resetTable();
        ncdTable.resetTable();
        opcodeFreqTable.resetTable();
        entropyGui.resetTable();
        mcCabeGui.resetTable();
        ropSimilarityGui.resetGui();
    }

    public void handleLocationChanged() {
        halsteadGui.populateFunctionTable();
    }

    @Override
    public JComponent getComponent() {
        return panel;
    }

}
