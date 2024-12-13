package gui;

import generic.stl.Pair;
import ghidra.util.exception.CancelledException;
import impl.McCabe;
import metrics.GhidraMetricsPlugin;
import resources.Icons;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.util.ArrayList;

public class McCabeGui {

    private static final String[] columnNames = {"Function", "Complexity"};

    private final JPanel panel;
    private final GhidraMetricsPlugin plugin;

    private final JLabel complexityResult;

    public McCabeGui(GhidraMetricsPlugin plugin) {

        this.plugin = plugin;
        panel = new JPanel(new BorderLayout());

        JPanel topPanel = new JPanel(new BorderLayout());
        JPanel resultPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        resultPanel.add(new JLabel("Complexity: "));
        complexityResult = new JLabel("N/A");
        resultPanel.add(complexityResult);
        topPanel.add(resultPanel, BorderLayout.WEST);
        JButton button = new JButton(Icons.REFRESH_ICON);
        topPanel.add(button, BorderLayout.EAST);

        DefaultTableModel tableModelProgram = new DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        JTable table = new JTable(tableModelProgram);
        table.setRowSorter(new TableRowSorter<>(tableModelProgram));
        JScrollPane tableScrollPane = new JScrollPane(table);
        
        button.addActionListener(e -> {
            tableModelProgram.setRowCount(0);
            try {
                int complexity = McCabe.computeMcCabe(plugin.getCurrentProgram());
                complexityResult.setText(Integer.toString(complexity));

                ArrayList<Pair<String, Integer>> res = McCabe.computeFunctions(plugin.getCurrentProgram());
                for (var l : res) {
                    tableModelProgram.addRow(new Object[] {l.first, l.second});
                }
            } catch (CancelledException ex) {
                resetTable();
            }
        });
        panel.putClientProperty("tableModel", tableModelProgram);
        panel.add(topPanel, BorderLayout.NORTH);
        panel.add(tableScrollPane, BorderLayout.CENTER);
    }

    public void resetTable() {
        DefaultTableModel tableModel = (DefaultTableModel) panel.getClientProperty("tableModel");
        if (tableModel != null) {
            tableModel.setRowCount(0);
            complexityResult.setText("N/A");
        }
    }

    public JPanel getPanel() {
        return panel;
    }
}
