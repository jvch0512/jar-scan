package jarscan;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;
import java.util.stream.*;
import java.util.zip.*;

public final class Scanner {
    public static final class Finding {
        public final String severity, rule, where, message;
        Finding(String s, String r, String w, String m) { severity = s; rule = r; where = w; message = m; }
    }

    static final int MAX_DEPTH = 3, MAX_ENTRIES = 100_000;
    static final long MAX_NESTED_BYTES = 200L * 1024 * 1024, MAX_PROPS = 4096;
    static final Pattern JAR_NAME = Pattern.compile("^(.+?)-(\\d[^/]*)\\.jar$");
    static final String JNDI = "org/apache/logging/log4j/core/lookup/JndiLookup.class";

    private final List<Finding> findings = new ArrayList<>();
    private final Set<String> seen = new HashSet<>();
    private long nestedBytes;
    private int entries;
    public int archives;

    public static int rank(String sev) {
        switch (sev) { case "critical": return 0; case "high": return 1; case "medium": return 2; case "low": return 3; default: return 4; }
    }

    /** Scan one archive file. Errors are returned as info findings, never thrown. */
    public List<Finding> scanFile(String label, Path p) {
        archives++;
        Ctx ctx = new Ctx();
        try (InputStream in = new BufferedInputStream(Files.newInputStream(p))) {
            walk(label, in, 0, ctx);
        } catch (IOException | RuntimeException e) {
            findings.add(new Finding("info", "JAR000", label, "could not read archive: " + e.getClass().getSimpleName()));
        }
        finish(label, ctx);
        return findings;
    }

    public List<Finding> results() {
        List<Finding> out = new ArrayList<>(findings);
        out.sort(Comparator.comparingInt((Finding f) -> rank(f.severity)).thenComparing(f -> f.where).thenComparing(f -> f.rule));
        return out;
    }

    private static final class Ctx { boolean log4jCore, jndiClass; String jndiWhere; }

    private void walk(String where, InputStream raw, int depth, Ctx ctx) throws IOException {
        ZipInputStream zin = new ZipInputStream(raw, StandardCharsets.UTF_8);
        ZipEntry e;
        while ((e = zin.getNextEntry()) != null) {
            if (++entries > MAX_ENTRIES) throw new IOException("too many entries");
            String name = e.getName();
            if (e.isDirectory()) continue;
            String simple = name.substring(name.lastIndexOf('/') + 1);
            String at = where + "!/" + name;
            if (name.equals(JNDI)) { ctx.jndiClass = true; ctx.jndiWhere = where; }
            if (simple.endsWith(".jar")) {
                Matcher m = JAR_NAME.matcher(simple);
                if (m.matches()) report(at, m.group(1), m.group(2), "file name", ctx);
                if (depth < MAX_DEPTH) {
                    byte[] data = readLimited(zin, 64L * 1024 * 1024);
                    if (data != null && (nestedBytes += data.length) <= MAX_NESTED_BYTES) {
                        try { walk(at, new ByteArrayInputStream(data), depth + 1, ctx); } catch (IOException | RuntimeException ex) { /* nested file is not a readable archive */ }
                    }
                }
            } else if (name.startsWith("META-INF/maven/") && simple.equals("pom.properties")) {
                byte[] data = readLimited(zin, MAX_PROPS);
                if (data != null) {
                    Properties pr = new Properties();
                    pr.load(new StringReader(new String(data, StandardCharsets.UTF_8)));
                    String a = pr.getProperty("artifactId"), v = pr.getProperty("version");
                    if (a != null && v != null) report(at, a.trim(), v.trim(), "pom.properties", ctx);
                }
            }
        }
    }

    private static byte[] readLimited(InputStream in, long max) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        long total = 0;
        int n;
        while ((n = in.read(buf)) > 0) {
            total += n;
            if (total > max) return null;
            out.write(buf, 0, n);
        }
        return out.toByteArray();
    }

    private void report(String at, String artifact, String version, String via, Ctx ctx) {
        if (artifact.equals("log4j-core")) ctx.log4jCore = true;
        Version v = Version.parse(version);
        for (Rules.Rule r : Rules.match(artifact, v)) {
            String key = at + r.id;
            if (seen.add(key)) findings.add(new Finding(r.severity, r.id, at, artifact + " " + version + " (" + via + "): " + r.message));
        }
    }

    private void finish(String label, Ctx ctx) {
        if (ctx.jndiClass && !ctx.log4jCore) {
            findings.add(new Finding("high", "CVE-2021-44228", ctx.jndiWhere + "!/" + JNDI,
                "JndiLookup class present but no log4j-core version found: probably a shaded Log4j 2, verify it is 2.17.1 or later"));
        }
    }

    public static List<Path> find(Path root) throws IOException {
        if (!Files.isDirectory(root)) return List.of(root);
        try (Stream<Path> s = Files.walk(root)) {
            return s.filter(Files::isRegularFile).filter(p -> {
                String n = p.getFileName().toString().toLowerCase();
                return n.endsWith(".jar") || n.endsWith(".war") || n.endsWith(".ear");
            }).sorted().collect(Collectors.toList());
        }
    }
}
