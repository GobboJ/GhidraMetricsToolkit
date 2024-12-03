package gui;

import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import impl.common.SimilarityInterface;
import impl.common.SimilarityResult;
import metrics.GhidraMetricsPlugin;
import utils.ProjectUtils;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.text.DecimalFormat;
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

        JTable table = new JTable(tableModel);

        TableRowSorter<DefaultTableModel> sorter = new TableRowSorter<>(tableModel);
        table.setRowSorter(sorter);

        DefaultTableCellRenderer doubleRenderer = new DefaultTableCellRenderer() {
            private final DecimalFormat formatter = new DecimalFormat("0.00");

            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                if (value instanceof Double) {
                    double doubleValue = (Double) value;

                    int red = (int) ((1.0 - doubleValue) * 255);
                    int green = (int) (doubleValue * 255);
                    int blue = 100;
                    red = (red + 255) / 2;
                    green = (green + 255) / 2;

                    c.setBackground(new Color(red, green, blue));
                    c.setForeground(Color.BLACK);
                }
                setText(value instanceof Double ? formatter.format(value) : value.toString());
                return c;
            }
        };
        table.getColumnModel().getColumn(0).setCellRenderer(doubleRenderer);

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
