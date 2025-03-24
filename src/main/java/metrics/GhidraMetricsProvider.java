package metrics;

import ghidra.framework.plugintool.ComponentProviderAdapter;
import gui.*;
import impl.metrics.*;

import javax.swing.*;
import java.awt.*;

public class GhidraMetricsProvider extends ComponentProviderAdapter {

    private final GhidraMetricsPlugin plugin;
    private JPanel panel;

    private EntropyGui entropyGui;
    private HalsteadGui halsteadGui;
    private McCabeGui mcCabeGui;
    private SimilarityGui<Lcs> lcsTable;
    private SimilarityGui<Ncd> ncdTable;
    private SimilarityGui<OpcodeFrequency> opcodeFreqTable;
    private SimilarityGui<Jaccard> jaccardTable;
    private SimilarityGui<JaroWinkler> jaroWinklerTable;
    private SimilarityGui<Levenshtein> levenshteinTable;
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

        lcsTable = new SimilarityGui<>(plugin, Lcs::new);
        tabbedPane.addTab("LCS", lcsTable.getPanel());

        ncdTable = new SimilarityGui<>(plugin, Ncd::new);
        tabbedPane.addTab("NCD", ncdTable.getPanel());

        opcodeFreqTable = new SimilarityGui<>(plugin, OpcodeFrequency::new);
        tabbedPane.addTab("Opcode Freq", opcodeFreqTable.getPanel());

        ropSimilarityGui = new RopSurvivalGui(plugin);
        tabbedPane.addTab("ROP", ropSimilarityGui.getPanel());

        jaccardTable = new SimilarityGui<>(plugin, Jaccard::new);
        tabbedPane.addTab("Jaccard", jaccardTable.getPanel());

        jaroWinklerTable = new SimilarityGui<>(plugin, JaroWinkler::new);
        tabbedPane.addTab("Jaro-Winkler", jaroWinklerTable.getPanel());

        levenshteinTable = new SimilarityGui<>(plugin, Levenshtein::new);
        tabbedPane.addTab("Levenshtein", levenshteinTable.getPanel());

        panel.add(tabbedPane);
        setVisible(true);
    }

    public void handleProgramActivated() {
        halsteadGui.populateProgramTable();
        lcsTable.resetPanel();
        ncdTable.resetPanel();
        opcodeFreqTable.resetPanel();
        entropyGui.resetTable();
        mcCabeGui.resetTable();
        ropSimilarityGui.resetGui();
        jaccardTable.resetPanel();
        jaroWinklerTable.resetPanel();
        levenshteinTable.resetPanel();
    }

    public void handleLocationChanged() {
        halsteadGui.populateFunctionTable();
    }

    @Override
    public JComponent getComponent() {
        return panel;
    }

}
