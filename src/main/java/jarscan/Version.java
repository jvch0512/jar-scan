package jarscan;

import java.util.ArrayList;
import java.util.List;

/** Numeric version comparison. Qualifiers such as -beta9 or .Final are ignored after the numeric part. */
public final class Version implements Comparable<Version> {
    private final int[] parts;
    public final String text;

    private Version(String text, int[] parts) { this.text = text; this.parts = parts; }

    /** Returns null when the text does not start with a digit. */
    public static Version parse(String s) {
        if (s == null || s.isEmpty() || !Character.isDigit(s.charAt(0))) return null;
        List<Integer> nums = new ArrayList<>();
        int i = 0;
        while (i < s.length()) {
            int j = i;
            while (j < s.length() && Character.isDigit(s.charAt(j))) j++;
            if (j == i) break;
            if (j - i > 9) return null;
            nums.add(Integer.parseInt(s.substring(i, j)));
            if (j < s.length() && s.charAt(j) == '.') i = j + 1; else break;
        }
        int[] p = new int[nums.size()];
        for (int k = 0; k < p.length; k++) p[k] = nums.get(k);
        return new Version(s, p);
    }

    @Override public int compareTo(Version o) {
        int n = Math.max(parts.length, o.parts.length);
        for (int i = 0; i < n; i++) {
            int a = i < parts.length ? parts[i] : 0, b = i < o.parts.length ? o.parts[i] : 0;
            if (a != b) return Integer.compare(a, b);
        }
        return 0;
    }

    @Override public String toString() { return text; }
}
