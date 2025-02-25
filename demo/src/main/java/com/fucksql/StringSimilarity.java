package com.fucksql;

public class StringSimilarity {
    public double lengthRatio(String s1, String s2) {
        int len1 = s1.length();
        int len2 = s2.length();
        int diff = Math.abs(len1 - len2);
        int maxLen = Math.max(len1, len2);
        return (double) diff / maxLen;
    }
}