package com.fucksql;

import javax.swing.*;

public class Main {

    private static void createAndShowGUI() {
        JFrame frame = new JFrame("Custom Panel Demo");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        CustomPanel customPanel = new CustomPanel();
        frame.getContentPane().add(customPanel);

        frame.pack();
        frame.setVisible(true);
    }
}