package jarscan;

import java.nio.file.*;
import java.util.*;

public final class Main {
    static int usage() {
        System.err.println("usage: jar-scan PATH [--tsv] [--fail-on medium|high|critical]\nExit: 0 ok, 1 findings at or above --fail-on, 2 bad input.");
        return 2;
    }

    /** Returns the exit code. Output goes to the given streams so tests can capture it. */
    public static int run(String[] args, java.io.PrintStream out, java.io.PrintStream err) {
        String path = null, fail = null;
        boolean tsv = false;
        for (int i = 0; i < args.length; i++) {
            String a = args[i];
            if (a.equals("--tsv")) tsv = true;
            else if (a.equals("--fail-on")) {
                if (++i >= args.length || !(args[i].equals("medium") || args[i].equals("high") || args[i].equals("critical"))) return usage();
                fail = args[i];
            } else if (a.startsWith("-")) return usage();
            else if (path != null) return usage();
            else path = a;
        }
        if (path == null) return usage();
        Path root = Paths.get(path);
        if (!Files.exists(root)) { err.println("error: no such file or directory: " + path); return 2; }
        Scanner sc = new Scanner();
        try {
            Path base = Files.isDirectory(root) ? root : root.getParent();
            for (Path p : Scanner.find(root)) {
                String label = Files.isDirectory(root) ? root.relativize(p).toString().replace('\\', '/') : p.getFileName().toString();
                sc.scanFile(label, p);
            }
        } catch (java.io.IOException e) {
            err.println("error: " + e.getMessage());
            return 2;
        }
        List<Scanner.Finding> fs = sc.results();
        if (tsv) out.println("# " + sc.archives + " archives, " + fs.size() + " findings");
        else out.println(sc.archives + " archives, " + fs.size() + " findings");
        for (Scanner.Finding f : fs) {
            if (tsv) out.println(f.severity + "\t" + f.rule + "\t" + f.where + "\t" + f.message);
            else out.println(String.format("%-8s %s %s%n         %s", f.severity.toUpperCase(), f.rule, f.where, f.message));
        }
        int floor = fail == null ? -1 : Scanner.rank(fail);
        if (floor >= 0) for (Scanner.Finding f : fs) if (Scanner.rank(f.severity) <= floor) return 1;
        return 0;
    }

    public static void main(String[] args) {
        System.exit(run(args, System.out, System.err));
    }
}
