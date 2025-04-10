package gui;

import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import impl.common.*;
import metrics.GhidraMetricsPlugin;
import impl.utils.ProjectUtils;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.ActionListener;
import java.text.DecimalFormat;
import java.util.Arrays;
import java.util.List;

public class SimilarityGui<T extends SimilarityInterface> {

    private static final String[] columnNames = {"Simil.", "Weight", "Current Program", "Compared Program"};

    private final JPanel panel;
    private final JComboBox<DomainFile> programChooser;
    private final JCheckBox exclusive;
    private final JCheckBox weighted;
    private final JCheckBox symmetric;
    private final JLabel overallSimilarity;

    private Similarity<T> similarity;

    public SimilarityGui(GhidraMetricsPlugin plugin, SimilarityMetricFactory<T> metricFactory) {

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
                if (value != null)
                    setText(value instanceof Double ? formatter.format(value) : value.toString());
                else {
                    c.setBackground(Color.WHITE);
                    setText("―");
                }

                return c;
            }
        };
        table.getColumnModel().getColumn(0).setCellRenderer(doubleRenderer);
        table.getColumnModel().getColumn(1).setCellRenderer(doubleRenderer);
        table.getColumnModel().getColumn(0).setPreferredWidth(50);
        table.getColumnModel().getColumn(0).setMinWidth(50);
        table.getColumnModel().getColumn(0).setMaxWidth(100);
        table.getColumnModel().getColumn(1).setPreferredWidth(50);
        table.getColumnModel().getColumn(1).setMinWidth(50);
        table.getColumnModel().getColumn(1).setMaxWidth(100);

        JScrollPane scrollPane = new JScrollPane(table);

        List<DomainFile> programFiles = ProjectUtils.getPrograms(plugin.getTool().getProject());


        JPanel topPanel = new JPanel(new BorderLayout());

        JPanel leftTopPanel = new JPanel(new BorderLayout());
        JPanel rightTopPanel = new JPanel(new FlowLayout());

        exclusive = new JCheckBox("Exclusive");
        weighted = new JCheckBox("Weighted");
        symmetric = new JCheckBox("Symmetric");

        rightTopPanel.add(exclusive);
        rightTopPanel.add(weighted);
        rightTopPanel.add(symmetric);

        JPanel inputPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JPanel outputPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        overallSimilarity = new JLabel("N/A");
        outputPanel.add(new JLabel("Overall Similarity: "));
        outputPanel.add(overallSimilarity);


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
                    similarity = new Similarity<>(plugin.getCurrentProgram(), program, metricFactory);
                    SimilarityResult result = similarity.getOverallSimilarity(exclusive.isSelected(), weighted.isSelected(), symmetric.isSelected());
                    result.sortBySimilarity();
                    overallSimilarity.setText(String.format("%.2f", result.overallSimilarity));
                    populateTable(result);
                }
            } catch (Exception ex) {
                Msg.showError(getClass(), panel, "Metric computation failed!", Arrays.toString(ex.getStackTrace()));
                similarity = null;
                overallSimilarity.setText("N/A");
                programChooser.setSelectedIndex(-1);
            }
        });

        ActionListener checkBoxHandler = e -> {
            if (programChooser.getSelectedIndex() >= 0 && similarity != null) {
                SimilarityResult result = similarity.getOverallSimilarity(exclusive.isSelected(), weighted.isSelected(), symmetric.isSelected());
                result.sortBySimilarity();
                overallSimilarity.setText(String.format("%.2f", result.overallSimilarity));
                populateTable(result);
            }
        };

        exclusive.addActionListener(checkBoxHandler);
        weighted.addActionListener(checkBoxHandler);
        symmetric.addActionListener(checkBoxHandler);

        inputPanel.add(new JLabel("Compare to: "));
        inputPanel.add(programChooser);

        leftTopPanel.add(inputPanel, BorderLayout.NORTH);
        leftTopPanel.add(outputPanel, BorderLayout.CENTER);

        topPanel.add(leftTopPanel, BorderLayout.WEST);
        topPanel.add(rightTopPanel, BorderLayout.EAST);

        panel.add(topPanel, BorderLayout.NORTH);
        panel.add(scrollPane, BorderLayout.CENTER);

        panel.putClientProperty("tableModel", tableModel);
    }

    public void populateTable(SimilarityResult result) {
        DefaultTableModel tableModel = (DefaultTableModel) panel.getClientProperty("tableModel");
        if (tableModel != null) {
            tableModel.setRowCount(0);
            for (Object[] row : result.getFunctionSimilarities()) {
                tableModel.addRow(row);
            }
        }
    }

    public void resetPanel() {
        DefaultTableModel tableModel = (DefaultTableModel) panel.getClientProperty("tableModel");
        if (tableModel != null) {
            tableModel.setRowCount(0);
            programChooser.setSelectedIndex(-1);
        }
        overallSimilarity.setText("N/A");
        exclusive.setSelected(false);
        weighted.setSelected(false);
        symmetric.setSelected(false);
    }

    public JPanel getPanel() {
        return panel;
    }
}
