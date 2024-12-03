package gui;

import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import impl.common.SimilarityInterface;
import impl.common.SimilarityResult;
import metrics.GhidraMetricsPlugin;
import utils.ProjectUtils;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableCellRenderer;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public class SimilarityResultTable {

    private final JPanel panel;

    public SimilarityResultTable(GhidraMetricsPlugin plugin, SimilarityInterface metric) {

        panel = new JPanel(new BorderLayout());

        String[] columnNames = {"Simil.", "Current Program", "Compared Program"};
        DefaultTableModel tableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        JTable table = new JTable(tableModel) {
            @Override
            public Component prepareRenderer(TableCellRenderer renderer, int row, int column) {
                Component c = super.prepareRenderer(renderer, row, column);
                if (!isRowSelected(row))
                    c.setBackground(row % 2 == 0 ? getBackground() : Color.LIGHT_GRAY);
                return c;
            }
        };

        JScrollPane scrollPane = new JScrollPane(table);

        List<DomainFile> programFiles = new ArrayList<>();
        ProjectUtils.findProgramsRecursively(plugin.getTool().getProject().getProjectData().getRootFolder(), programFiles);


        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        JComboBox<DomainFile> jComboBox = new JComboBox<>();
        for (DomainFile f : programFiles) {
            jComboBox.addItem(f);
        }
        jComboBox.setSelectedIndex(-1);
        jComboBox.setVisible(true);
        jComboBox.addActionListener(e -> {
            try {
                DomainFile choice = (DomainFile) jComboBox.getSelectedItem();
                Program p = ProjectUtils.getProgramFromDomainFile(choice);
                SimilarityResult result = metric.computeSimilarity(plugin.getCurrentProgram(), p);
                result.sortBySimilarity();
                populateTable(result);
            } catch (Exception ex) {
                Msg.showError(getClass(), panel, "Metric computation failed!", ex.getMessage());
                jComboBox.setSelectedIndex(-1);
            }
        });

        topPanel.add(new JLabel("Compare to: "));
        topPanel.add(jComboBox);

        panel.add(topPanel, BorderLayout.NORTH);
        panel.add(scrollPane, BorderLayout.CENTER);

        panel.putClientProperty("tableModel", tableModel);
    }

    public void populateTable(SimilarityResult result) {
        DefaultTableModel tableModel = (DefaultTableModel) panel.getClientProperty("tableModel");
        if (tableModel != null) {
            tableModel.setRowCount(0);
            for (Object[] l : result.getMatches()) {
                tableModel.addRow(l);
            }
        }
    }

    public JPanel getPanel() {
        return panel;
    }
}
