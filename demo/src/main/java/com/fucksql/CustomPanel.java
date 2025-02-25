package com.fucksql;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class CustomPanel extends JPanel {
    private JTextArea paramWhitelistArea;
    private JTextArea urlWhitelistArea;
    private JCheckBox enableProjectFilterCheckBox;
    private JTextField packetDelayField;
    private JButton confirmButton;

    public CustomPanel() {
        setLayout(new BorderLayout(10, 10));
        setBorder(BorderFactory.createEmptyBorder(30, 10, 30, 10));

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

        add(fieldsPanel, BorderLayout.NORTH);

        confirmButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                
            }
        });
    }

    @Override
    public Dimension getPreferredSize() {
        return new Dimension(400, 400);
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
}