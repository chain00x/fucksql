package com.fucksql;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;

public class CustomPanel extends JPanel {
    private JTextArea excludeParamsArea;
    private JTextArea scanHostsArea;
    private JCheckBox enableProjectFilterCheckBox;
    private JTextField packetDelayField;
    private JButton confirmButton;
    private JButton addPayloadButton;
    private JTable payloadTable;
    private DefaultTableModel tableModel;
    private List<String[]> payloadList;
    private JCheckBox enablePassiveScanCheckBox; // 被动扫描开关
    private JCheckBox enableHostFilterCheckBox; // 开启host列表过滤（默认关闭）
    private JCheckBox enableParamExclusionCheckBox; // 开启参数排除（默认开启）

    public CustomPanel() {
        setLayout(new BorderLayout(10, 10));
        setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));

        // 初始化payload列表
        payloadList = new ArrayList<>();
        // 设置默认payload值
        String[] defaultPayload = {"'", "''"};
        payloadList.add(defaultPayload);

        // 创建配置面板
        JPanel configPanel = createConfigPanel();
        add(configPanel, BorderLayout.NORTH);

        // 创建自定义payload面板
        JPanel payloadPanel = createPayloadPanel();
        add(payloadPanel, BorderLayout.CENTER);

        // 确认按钮事件监听
        confirmButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // 可以在这里添加确认操作的逻辑
                JOptionPane.showMessageDialog(CustomPanel.this, "配置已保存！", "成功", JOptionPane.INFORMATION_MESSAGE);
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

    // 创建配置面板
    private JPanel createConfigPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new GridLayout(2, 1, 20, 20));
        panel.setBorder(BorderFactory.createTitledBorder("扫描配置"));
        
        // 第一行：扫描host列表和排除参数列表
        JPanel listsPanel = new JPanel(new GridLayout(1, 2, 20, 20));
        
        // 扫描host列表
        JPanel scanHostsPanel = new JPanel(new BorderLayout(5, 5));
        scanHostsArea = new JTextArea(5, 25);
        scanHostsArea.setLineWrap(true);
        scanHostsArea.setBorder(BorderFactory.createLineBorder(Color.LIGHT_GRAY));
        scanHostsArea.setToolTipText("每行输入一个host，例如: example.com");
        JScrollPane scanHostsScroll = new JScrollPane(scanHostsArea);
        scanHostsPanel.add(new JLabel("扫描Host列表(每行输入一个)："), BorderLayout.NORTH);
        scanHostsPanel.add(scanHostsScroll, BorderLayout.CENTER);
        
        // 排除参数列表
        JPanel excludeParamsPanel = new JPanel(new BorderLayout(5, 5));
        excludeParamsArea = new JTextArea(5, 25);
        excludeParamsArea.setLineWrap(true);
        excludeParamsArea.setBorder(BorderFactory.createLineBorder(Color.LIGHT_GRAY));
        excludeParamsArea.setToolTipText("每行输入一个参数名，例如: id, username");
        JScrollPane excludeParamsScroll = new JScrollPane(excludeParamsArea);
        excludeParamsPanel.add(new JLabel("排除参数列表(每行输入一个)："), BorderLayout.NORTH);
        excludeParamsPanel.add(excludeParamsScroll, BorderLayout.CENTER);
        
        listsPanel.add(scanHostsPanel);
        listsPanel.add(excludeParamsPanel);
        
        // 第二行：选项配置
        JPanel optionsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 20, 10));
        
        JPanel packetDelayPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        packetDelayField = new JTextField(5);
        packetDelayField.setPreferredSize(new Dimension(60, 25));
        packetDelayField.setText("0");
        packetDelayPanel.add(new JLabel("发包延时(秒)："));
        packetDelayPanel.add(packetDelayField);
        
        JPanel projectFilterPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        enableProjectFilterCheckBox = new JCheckBox();
        enableProjectFilterCheckBox.setSelected(true);
        projectFilterPanel.add(new JLabel("开启项目范围过滤(主动扫描不受此限制)："));
        projectFilterPanel.add(enableProjectFilterCheckBox);
        
        JPanel passiveScanPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        enablePassiveScanCheckBox = new JCheckBox();
        enablePassiveScanCheckBox.setSelected(false); // 默认不开启被动扫描
        passiveScanPanel.add(new JLabel("开启被动扫描："));
        passiveScanPanel.add(enablePassiveScanCheckBox);
        
        JPanel hostFilterPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        enableHostFilterCheckBox = new JCheckBox();
        enableHostFilterCheckBox.setSelected(false); // 默认关闭
        hostFilterPanel.add(new JLabel("开启host列表过滤："));
        hostFilterPanel.add(enableHostFilterCheckBox);
        
        JPanel paramExclusionPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        enableParamExclusionCheckBox = new JCheckBox();
        enableParamExclusionCheckBox.setSelected(true); // 默认开启
        paramExclusionPanel.add(new JLabel("开启参数排除："));
        paramExclusionPanel.add(enableParamExclusionCheckBox);
        
        confirmButton = new JButton("保存配置");
        confirmButton.setPreferredSize(new Dimension(100, 30));
        
        optionsPanel.add(packetDelayPanel);
        optionsPanel.add(projectFilterPanel);
        optionsPanel.add(passiveScanPanel);
        optionsPanel.add(hostFilterPanel);
        optionsPanel.add(paramExclusionPanel);
        optionsPanel.add(Box.createHorizontalGlue());
        optionsPanel.add(confirmButton);
        
        panel.add(listsPanel);
        panel.add(optionsPanel);
        
        return panel;
    }

    // 创建自定义payload面板
    private JPanel createPayloadPanel() {
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
        
        // 如果有默认payload，添加到表格模型
        if (!payloadList.isEmpty()) {
            for (String[] payload : payloadList) {
                tableModel.addRow(new Object[]{payload[0], payload[1]});
            }
        }
        
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

    // 保留原有的getter方法以保持向后兼容，但内部使用新的组件
    public JTextArea getParamWhitelistArea() {
        return excludeParamsArea;
    }

    public JTextArea getUrlWhitelistArea() {
        return scanHostsArea;
    }
    
    // 新的getter方法
    public JTextArea getExcludeParamsArea() {
        return excludeParamsArea;
    }

    public JTextArea getScanHostsArea() {
        return scanHostsArea;
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
    
    // 获取文本内容的便捷方法
    public String getExcludeParamsText() {
        return excludeParamsArea != null ? excludeParamsArea.getText() : "";
    }
    
    public String getScanHostsText() {
        return scanHostsArea != null ? scanHostsArea.getText() : "";
    }
    
    public String getParamWhitelistText() {
        return getExcludeParamsText(); // 保持向后兼容
    }
    
    public String getUrlWhitelistText() {
        return getScanHostsText(); // 保持向后兼容
    }
    
    public int getPacketDelay() {
        try {
            return Integer.parseInt(packetDelayField != null ? packetDelayField.getText() : "0");
        } catch (NumberFormatException e) {
            return 0;
        }
    }
    
    public boolean isProjectFilterEnabled() {
        return enableProjectFilterCheckBox != null && enableProjectFilterCheckBox.isSelected();
    }
    
    public JCheckBox getEnablePassiveScanCheckBox() {
        return enablePassiveScanCheckBox;
    }
    
    public boolean isPassiveScanEnabled() {
        return enablePassiveScanCheckBox != null && enablePassiveScanCheckBox.isSelected();
    }
    
    public JCheckBox getEnableHostFilterCheckBox() {
        return enableHostFilterCheckBox;
    }
    
    public boolean isHostFilterEnabled() {
        return enableHostFilterCheckBox != null && enableHostFilterCheckBox.isSelected();
    }
    
    public JCheckBox getEnableParamExclusionCheckBox() {
        return enableParamExclusionCheckBox;
    }
    
    public boolean isParamExclusionEnabled() {
        return enableParamExclusionCheckBox != null && enableParamExclusionCheckBox.isSelected();
    }
}