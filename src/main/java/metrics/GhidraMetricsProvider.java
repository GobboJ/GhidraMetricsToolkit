package metrics;

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
    private SimilarityResultTable<Lcs> lcsTable;
    private SimilarityResultTable ncdTable;
    private SimilarityResultTable opcodeFreqTable;
    private RopSurvivalGui ropSimilarityGui;

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

        lcsTable = new SimilarityResultTable<>(plugin, Lcs::new);
        tabbedPane.addTab("LCS", lcsTable.getPanel());

        ncdTable = new SimilarityResultTable<>(plugin, Ncd::new);
        tabbedPane.addTab("NCD", ncdTable.getPanel());

        opcodeFreqTable = new SimilarityResultTable<>(plugin, OpcodeFrequency::new);
        tabbedPane.addTab("Opcode Freq", opcodeFreqTable.getPanel());

        ropSimilarityGui = new RopSurvivalGui(plugin);
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
