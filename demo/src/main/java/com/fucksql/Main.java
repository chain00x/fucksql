package com.fucksql;

import javax.swing.*;

public class Main {
    public static void main(String[] args) {
        System.out.print("data%3D%7B%22a%22%3A%7B%22b%22%3A%7B%22c%22%3A%22d%22%2C%22e%22%3A%22f%2Caaaa%22%2C%22g%22%3A%5B%22h%22%5D%7D%7D%7D".replace("%3d","="));
    }

    private static void createAndShowGUI() {
        JFrame frame = new JFrame("Custom Panel Demo");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        CustomPanel customPanel = new CustomPanel();
        frame.getContentPane().add(customPanel);

        frame.pack();
        frame.setVisible(true);
    }
}