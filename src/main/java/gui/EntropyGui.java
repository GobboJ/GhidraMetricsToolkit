package gui;

import generic.stl.Pair;
import impl.Entropy;
import metrics.GhidraMetricsPlugin;
import resources.Icons;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.io.File;
import java.io.IOException;
import java.text.DecimalFormat;
import java.util.ArrayList;

public class EntropyGui {

    private static final String[] columnNames = {"Section", "Entropy"};

    private final JPanel panel;
    private final GhidraMetricsPlugin plugin;

    private final JLabel binaryResult;
    private final JTextField baseInput;

    public EntropyGui(GhidraMetricsPlugin plugin) {

        this.plugin = plugin;
        panel = new JPanel(new BorderLayout());

        JPanel topPanel = new JPanel(new BorderLayout());

        JPanel inputPanel;
        inputPanel = new JPanel(new BorderLayout());
        JPanel basePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        baseInput = new JTextField("2", 4);
        baseInput.setHorizontalAlignment(SwingConstants.RIGHT);
        basePanel.add(new JLabel("Base:"));
        basePanel.add(baseInput);

        JButton processButton = new JButton(Icons.REFRESH_ICON);

        inputPanel.add(basePanel, BorderLayout.WEST);
        inputPanel.add(processButton, BorderLayout.EAST);


        JPanel outputPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        binaryResult = new JLabel("N/A");
        outputPanel.add(new JLabel("Binary Entropy: "));
        outputPanel.add(binaryResult);

        topPanel.add(inputPanel, BorderLayout.NORTH);
        topPanel.add(outputPanel, BorderLayout.CENTER);

        DefaultTableModel tableModelProgram = new DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        JTable table = new JTable(tableModelProgram);
        table.setRowSorter(new TableRowSorter<>(tableModelProgram));
        DefaultTableCellRenderer doubleRenderer = new DefaultTableCellRenderer() {
            private final DecimalFormat formatter = new DecimalFormat("0.00");

            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                if (value instanceof Double) {
                    setText(formatter.format(value));
                    c.setBackground(Color.WHITE);
                }
                return c;
            }
        };
        table.getColumnModel().getColumn(1).setCellRenderer(doubleRenderer);
        JScrollPane tableScrollPane = new JScrollPane(table);

        panel.add(topPanel, BorderLayout.NORTH);
        panel.add(tableScrollPane, BorderLayout.CENTER);

        processButton.addActionListener(e -> {
            tableModelProgram.setRowCount(0);
            try {
                int baseValue = Integer.parseInt(baseInput.getText());

                double binaryEntropy = Entropy.binaryEntropy(new File(plugin.getCurrentProgram().getExecutablePath()), baseValue);
                // TODO Handle executable not found case
                ArrayList<Pair<String, Double>> res = Entropy.entropyBySection(plugin.getCurrentProgram(), baseValue);
                for (var l : res) {
                    tableModelProgram.addRow(new Object[]{l.first, l.second});
                }
                binaryResult.setText(String.format("%.2f", binaryEntropy));
            } catch (NumberFormatException ex) {
                binaryResult.setText("Invalid input");
                tableModelProgram.setRowCount(0);
            } catch (IOException ex) {
                binaryResult.setText("Binary not found");
                tableModelProgram.setRowCount(0);
            }
        });

        panel.putClientProperty("tableModel", tableModelProgram);
    }

    public void resetTable() {
        DefaultTableModel tableModel = (DefaultTableModel) panel.getClientProperty("tableModel");
        if (tableModel != null) {
            tableModel.setRowCount(0);
            binaryResult.setText("N/A");
            baseInput.setText("2");
        }
    }

    public JPanel getPanel() {
        return panel;
    }
}
