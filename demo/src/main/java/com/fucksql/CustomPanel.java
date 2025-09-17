package com.fucksql;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;

public class CustomPanel extends JPanel {
    private JTextArea paramWhitelistArea;
    private JTextArea urlWhitelistArea;
    private JCheckBox enableProjectFilterCheckBox;
    private JTextField packetDelayField;
    private JButton confirmButton;
    private JButton addPayloadButton;
    private JTable payloadTable;
    private DefaultTableModel tableModel;
    private List<String[]> payloadList;

    public CustomPanel() {
        setLayout(new BorderLayout(10, 10));
        setBorder(BorderFactory.createEmptyBorder(30, 10, 30, 10));

        // 初始化payload列表
        payloadList = new ArrayList<>();

        // 创建顶部面板（原有功能）
        JPanel topPanel = createTopPanel();
        add(topPanel, BorderLayout.NORTH);

        // 创建底部面板（自定义payload功能）
        JPanel bottomPanel = createBottomPanel();
        add(bottomPanel, BorderLayout.CENTER);

        // 确认按钮事件监听（原有功能）
        confirmButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // 原有功能不变
            }
        });

        // 添加payload按钮事件监听
        addPayloadButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                showAddPayloadDialog();
            }
        });
    }

    // 创建顶部面板（原有功能）
    private JPanel createTopPanel() {
        JPanel Panel1 = new JPanel();
        Panel1.setLayout(new GridLayout(1, 2, 10, 10));
        paramWhitelistArea = new JTextArea(5, 30);
        urlWhitelistArea = new JTextArea(5, 30);
        paramWhitelistArea.setLineWrap(true);
        urlWhitelistArea.setLineWrap(true);
        paramWhitelistArea.setBorder(BorderFactory.createLineBorder(Color.BLACK));
        urlWhitelistArea.setBorder(BorderFactory.createLineBorder(Color.BLACK));
        Panel1.add(new JLabel("参数白名单："), BorderLayout.NORTH);
        Panel1.add(paramWhitelistArea, BorderLayout.CENTER);
        Panel1.add(new JLabel("URL白名单："), BorderLayout.NORTH);
        Panel1.add(urlWhitelistArea, BorderLayout.CENTER);

        JPanel optionsPanel = new JPanel();
        optionsPanel.setLayout(new GridLayout(3, 1, 0, 0));
        packetDelayField = new JTextField(1);
        enableProjectFilterCheckBox = new JCheckBox();
        enableProjectFilterCheckBox.setSelected(true);
        packetDelayField.setPreferredSize(new Dimension(packetDelayField.getPreferredSize().width, 20));
        packetDelayField.setText("0");
        confirmButton = new JButton("确定");
        optionsPanel.add(new JLabel("发包延时："));
        optionsPanel.add(packetDelayField);
        optionsPanel.add(new JLabel("是否开启项目范围过滤："));
        optionsPanel.add(enableProjectFilterCheckBox);
        optionsPanel.add(confirmButton);

        JPanel fieldsPanel = new JPanel();
        fieldsPanel.setLayout(new GridLayout(1, 1, 5, 5));
        fieldsPanel.add(Panel1);
        fieldsPanel.add(optionsPanel);

        return fieldsPanel;
    }

    // 创建底部面板（自定义payload功能）
    private JPanel createBottomPanel() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(BorderFactory.createTitledBorder("自定义Payload"));

        // 创建表格模型
        String[] columnNames = {"Payload 1", "Payload 2"};
        tableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false; // 表格内容不可编辑
            }
        };

        // 创建表格
        payloadTable = new JTable(tableModel);
        JScrollPane scrollPane = new JScrollPane(payloadTable);
        panel.add(scrollPane, BorderLayout.CENTER);

        // 创建按钮面板
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        addPayloadButton = new JButton("添加");
        JButton editButton = new JButton("编辑");
        JButton deleteButton = new JButton("删除");
        
        buttonPanel.add(addPayloadButton);
        buttonPanel.add(editButton);
        buttonPanel.add(deleteButton);
        panel.add(buttonPanel, BorderLayout.SOUTH);

        // 添加编辑按钮事件监听
        editButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int selectedRow = payloadTable.getSelectedRow();
                if (selectedRow >= 0) {
                    showEditPayloadDialog(selectedRow);
                } else {
                    JOptionPane.showMessageDialog(CustomPanel.this, "请先选择要编辑的payload行", "提示", JOptionPane.WARNING_MESSAGE);
                }
            }
        });

        // 添加删除按钮事件监听
        deleteButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int selectedRow = payloadTable.getSelectedRow();
                if (selectedRow >= 0) {
                    deleteSelectedPayload(selectedRow);
                } else {
                    JOptionPane.showMessageDialog(CustomPanel.this, "请先选择要删除的payload行", "提示", JOptionPane.WARNING_MESSAGE);
                }
            }
        });

        return panel;
    }

    // 显示添加payload对话框
    private void showAddPayloadDialog() {
        JDialog dialog = new JDialog((Frame) null, "添加Payload", true);
        dialog.setLayout(new GridLayout(3, 2, 10, 10));
        dialog.setSize(400, 150);
        dialog.setLocationRelativeTo(this);

        JTextField payload1Field = new JTextField();
        JTextField payload2Field = new JTextField();

        dialog.add(new JLabel("Payload 1:"));
        dialog.add(payload1Field);
        dialog.add(new JLabel("Payload 2:"));
        dialog.add(payload2Field);

        JButton confirmButton = new JButton("确定");
        JButton cancelButton = new JButton("取消");

        confirmButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String payload1 = payload1Field.getText();
                String payload2 = payload2Field.getText();
                
                // 添加到列表和表格
                payloadList.add(new String[]{payload1, payload2});
                tableModel.addRow(new Object[]{payload1, payload2});
                
                // 显示成功提示
                JOptionPane.showMessageDialog(dialog, "Payload添加成功！", "成功", JOptionPane.INFORMATION_MESSAGE);
                
                dialog.dispose();
            }
        });

        cancelButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                dialog.dispose();
            }
        });

        dialog.add(confirmButton);
        dialog.add(cancelButton);

        dialog.setVisible(true);
    }

    // 显示编辑payload对话框
    private void showEditPayloadDialog(int rowIndex) {
        JDialog dialog = new JDialog((Frame) null, "编辑Payload", true);
        dialog.setLayout(new GridLayout(3, 2, 10, 10));
        dialog.setSize(400, 150);
        dialog.setLocationRelativeTo(this);

        // 获取选中行的数据
        String payload1 = (String) tableModel.getValueAt(rowIndex, 0);
        String payload2 = (String) tableModel.getValueAt(rowIndex, 1);

        JTextField payload1Field = new JTextField(payload1);
        JTextField payload2Field = new JTextField(payload2);

        dialog.add(new JLabel("Payload 1:"));
        dialog.add(payload1Field);
        dialog.add(new JLabel("Payload 2:"));
        dialog.add(payload2Field);

        JButton confirmButton = new JButton("确定");
        JButton cancelButton = new JButton("取消");

        confirmButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String newPayload1 = payload1Field.getText();
                String newPayload2 = payload2Field.getText();
                
                // 更新列表和表格
                payloadList.set(rowIndex, new String[]{newPayload1, newPayload2});
                tableModel.setValueAt(newPayload1, rowIndex, 0);
                tableModel.setValueAt(newPayload2, rowIndex, 1);
                
                // 显示成功提示
                JOptionPane.showMessageDialog(dialog, "Payload更新成功！", "成功", JOptionPane.INFORMATION_MESSAGE);
                
                dialog.dispose();
            }
        });

        cancelButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                dialog.dispose();
            }
        });

        dialog.add(confirmButton);
        dialog.add(cancelButton);

        dialog.setVisible(true);
    }

    // 删除选中的payload
    private void deleteSelectedPayload(int rowIndex) {
        // 显示确认对话框
        int option = JOptionPane.showConfirmDialog(
                this,
                "确定要删除选中的payload吗？",
                "确认删除",
                JOptionPane.YES_NO_OPTION
        );
        
        if (option == JOptionPane.YES_OPTION) {
            // 从列表和表格中删除
            payloadList.remove(rowIndex);
            tableModel.removeRow(rowIndex);
            
            // 显示成功提示
            JOptionPane.showMessageDialog(this, "Payload删除成功！", "成功", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    @Override
    public Dimension getPreferredSize() {
        return new Dimension(700, 600);
    }

    public JTextArea getParamWhitelistArea() {
        return paramWhitelistArea;
    }

    public JTextArea getUrlWhitelistArea() {
        return urlWhitelistArea;
    }

    public JCheckBox getEnableProjectFilterCheckBox() {
        return enableProjectFilterCheckBox;
    }

    public JTextField getPacketDelayField() {
        return packetDelayField;
    }

    public JButton getConfirmButton() {
        return confirmButton;
    }
    
    public List<String[]> getPayloadList() {
        return payloadList;
    }
}