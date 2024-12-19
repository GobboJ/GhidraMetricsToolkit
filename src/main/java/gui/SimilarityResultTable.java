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

    private static final String[] columnNames = {"Simil.", "Current Program", "Compared Program"};

    private final JPanel panel;
    private final JComboBox<DomainFile> programChooser;

    public SimilarityResultTable(GhidraMetricsPlugin plugin, SimilarityInterface metric) {

        panel = new JPanel(new BorderLayout());

        DefaultTableModel tableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        JTable table = new JTable(tableModel);

        table.setRowSorter(new TableRowSorter<>(tableModel));

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
        ProjectUtils.getProgramList(plugin.getTool().getProject().getProjectData().getRootFolder(), programFiles);


        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));


        programChooser = new JComboBox<>();
        for (DomainFile program : programFiles) {
            programChooser.addItem(program);
        }
        programChooser.setSelectedIndex(-1);
        programChooser.setVisible(true);
        programChooser.addActionListener(e -> {
            try {
                DomainFile choice = (DomainFile) programChooser.getSelectedItem();
                if (choice != null) {
                    Program program = ProjectUtils.getProgramFromDomainFile(choice);
                    SimilarityResult result = metric.computeSimilarity(plugin.getCurrentProgram(), program);
                    result.sortBySimilarity();
                    populateTable(result);
                }
            } catch (Exception ex) {
                Msg.showError(getClass(), panel, "Metric computation failed!", ex.getMessage());
                programChooser.setSelectedIndex(-1);
            }
        });

        topPanel.add(new JLabel("Compare to: "));
        topPanel.add(programChooser);

        panel.add(topPanel, BorderLayout.NORTH);
        panel.add(scrollPane, BorderLayout.CENTER);

        panel.putClientProperty("tableModel", tableModel);
    }

    public void populateTable(SimilarityResult result) {
        DefaultTableModel tableModel = (DefaultTableModel) panel.getClientProperty("tableModel");
        if (tableModel != null) {
            tableModel.setRowCount(0);
            for (Object[] row : result.getMatches()) {
                tableModel.addRow(row);
            }
        }
    }

    public void resetTable() {
        DefaultTableModel tableModel = (DefaultTableModel) panel.getClientProperty("tableModel");
        if (tableModel != null) {
            tableModel.setRowCount(0);
            programChooser.setSelectedIndex(-1);
        }
    }

    public JPanel getPanel() {
        return panel;
    }
}
