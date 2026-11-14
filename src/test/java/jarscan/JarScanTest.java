package jarscan;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;

/** Dependency-free test runner: `java -cp out jarscan.JarScanTest` exits non-zero on failure. */
public final class JarScanTest {
    static int n, fail;
    static void check(String name, boolean ok) { n++; if (!ok) { fail++; System.out.println("FAIL: " + name); } }

    static byte[] zip(Object... pairs) throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        try (ZipOutputStream z = new ZipOutputStream(b)) {
            for (int i = 0; i < pairs.length; i += 2) {
                z.putNextEntry(new ZipEntry((String) pairs[i]));
                Object d = pairs[i + 1];
                z.write(d instanceof byte[] ? (byte[]) d : ((String) d).getBytes(StandardCharsets.UTF_8));
                z.closeEntry();
            }
        }
        return b.toByteArray();
    }

    static Path tmp;
    static List<Scanner.Finding> scan(byte[] data) throws IOException {
        Path p = Files.createTempFile(tmp, "t", ".jar");
        Files.write(p, data);
        Scanner s = new Scanner();
        s.scanFile("t.jar", p);
        return s.results();
    }
    static boolean has(List<Scanner.Finding> fs, String rule, String sev) {
        for (Scanner.Finding f : fs) if (f.rule.equals(rule) && f.severity.equals(sev)) return true;
        return false;
    }
    static boolean flagged(String jar) throws IOException { return !scan(zip(jar, "")).isEmpty(); }
    static int run(String[] args) {
        PrintStream o = new PrintStream(new ByteArrayOutputStream()), e = new PrintStream(new ByteArrayOutputStream());
        return Main.run(args, o, e);
    }

    public static void main(String[] a) throws Exception {
        tmp = Files.createTempDirectory("jarscan");

        // version parsing and ordering
        check("parse simple", Version.parse("2.14.1") != null);
        check("parse rejects text", Version.parse("abc") == null && Version.parse("") == null && Version.parse(null) == null);
        check("qualifier ignored", Version.parse("2.0-beta9").compareTo(Version.parse("2.0")) == 0);
        check("order patch", Version.parse("2.14.1").compareTo(Version.parse("2.15.0")) < 0);
        check("order numeric not lexical", Version.parse("2.9").compareTo(Version.parse("2.10")) < 0);
        check("trailing zeros equal", Version.parse("1.10").compareTo(Version.parse("1.10.0")) == 0);
        check("four parts", Version.parse("6.3.0.1").compareTo(Version.parse("6.3.0.2")) < 0);
        check("huge number rejected", Version.parse("99999999999.1") == null);

        // log4j-core ranges
        check("log4j 2.14.1 critical", has(scan(zip("lib/log4j-core-2.14.1.jar", "")), "CVE-2021-44228", "critical"));
        check("log4j 2.0-beta9 critical", has(scan(zip("lib/log4j-core-2.0-beta9.jar", "")), "CVE-2021-44228", "critical"));
        check("log4j 2.15.0 high", has(scan(zip("lib/log4j-core-2.15.0.jar", "")), "CVE-2021-45046", "high"));
        check("log4j 2.16.0 medium", has(scan(zip("lib/log4j-core-2.16.0.jar", "")), "CVE-2021-45105", "medium"));
        check("log4j 2.17.0 low", has(scan(zip("lib/log4j-core-2.17.0.jar", "")), "CVE-2021-44832", "low"));
        check("log4j 2.17.1 clean", !flagged("lib/log4j-core-2.17.1.jar"));
        check("log4j 2.20.0 clean", !flagged("lib/log4j-core-2.20.0.jar"));
        check("log4j-api never flagged", !flagged("lib/log4j-api-2.14.1.jar"));
        check("log4j 1.x flagged", has(scan(zip("lib/log4j-1.2.17.jar", "")), "CVE-2019-17571", "high"));

        // other boundaries
        check("commons-text 1.9 flagged", has(scan(zip("commons-text-1.9.jar", "")), "CVE-2022-42889", "critical"));
        check("commons-text 1.10.0 clean", !flagged("commons-text-1.10.0.jar"));
        check("commons-text 1.4 clean", !flagged("commons-text-1.4.jar"));
        check("spring-beans 5.3.17 flagged", has(scan(zip("spring-beans-5.3.17.jar", "")), "CVE-2022-22965", "high"));
        check("spring-beans 5.3.18 clean", !flagged("spring-beans-5.3.18.jar"));
        check("spring-beans 5.2.19 flagged", flagged("spring-beans-5.2.19.jar"));
        check("spring-beans 5.2.20 clean", !flagged("spring-beans-5.2.20.jar"));
        check("spring-beans 5.1.0 not in range", !flagged("spring-beans-5.1.0.jar"));
        check("struts 2.5.32 flagged", has(scan(zip("struts2-core-2.5.32.jar", "")), "CVE-2023-50164", "critical"));
        check("struts 2.5.33 clean", !flagged("struts2-core-2.5.33.jar"));
        check("struts 6.3.0.1 flagged", flagged("struts2-core-6.3.0.1.jar"));
        check("struts 6.3.0.2 clean", !flagged("struts2-core-6.3.0.2.jar"));
        check("snakeyaml 1.33 flagged", flagged("snakeyaml-1.33.jar"));
        check("snakeyaml 2.0 clean", !flagged("snakeyaml-2.0.jar"));
        check("commons-collections 3.2.1 flagged", flagged("commons-collections-3.2.1.jar"));
        check("commons-collections 3.2.2 clean", !flagged("commons-collections-3.2.2.jar"));
        check("commons-collections 4.0 flagged", flagged("commons-collections-4.0.jar"));
        check("commons-collections 4.4 clean", !flagged("commons-collections4-4.4.jar") );
        check("h2 2.0.202 flagged", has(scan(zip("h2-2.0.202.jar", "")), "CVE-2021-42392", "critical"));
        check("h2 2.2.220 clean", !flagged("h2-2.2.220.jar"));
        check("fastjson 1.2.80 flagged", flagged("fastjson-1.2.80.jar"));
        check("xstream 1.4.19 flagged", flagged("xstream-1.4.19.jar"));
        check("unrelated jar clean", !flagged("commons-lang3-3.12.0.jar"));
        check("artifact with digits in name", !flagged("commons-lang3-3.12.0.jar") && flagged("struts2-core-2.3.1.jar"));

        // pom.properties inside shaded jars
        check("shaded pom.properties", has(scan(zip("META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties", "groupId=g\nartifactId=log4j-core\nversion=2.14.0\n")), "CVE-2021-44228", "critical"));
        check("shaded pom.properties safe version", scan(zip("META-INF/maven/g/log4j-core/pom.properties", "artifactId=log4j-core\nversion=2.20.0\n")).isEmpty());
        check("pom.properties without version ignored", scan(zip("META-INF/maven/g/x/pom.properties", "artifactId=log4j-core\n")).isEmpty());

        // JndiLookup class
        String J = "org/apache/logging/log4j/core/lookup/JndiLookup.class";
        check("jndi class alone flagged", has(scan(zip(J, "")), "CVE-2021-44228", "high"));
        check("jndi class with safe jar not flagged twice", scan(zip(J, "", "log4j-core-2.20.0.jar", "")).isEmpty());
        check("jndi class with vulnerable jar", scan(zip(J, "", "log4j-core-2.14.1.jar", "")).size() == 1);

        // nested archives
        byte[] inner = zip("lib/log4j-core-2.14.1.jar", "");
        check("nested fat jar", has(scan(zip("BOOT-INF/lib/app-lib-1.0.jar", inner)), "CVE-2021-44228", "critical"));
        check("nested location in where", scan(zip("BOOT-INF/lib/app-lib-1.0.jar", inner)).get(0).where.equals("t.jar!/BOOT-INF/lib/app-lib-1.0.jar!/lib/log4j-core-2.14.1.jar"));
        byte[] deep = zip("lib/log4j-core-2.14.1.jar", "");
        for (int i = 0; i < 5; i++) deep = zip("x" + i + "-1.0.jar", deep);
        check("depth limit stops recursion", scan(deep).isEmpty());
        check("non-archive nested jar tolerated", scan(zip("junk-1.0.jar", "not a zip")).isEmpty());
        check("same jar in two places reported twice", scan(zip("a/log4j-core-2.14.1.jar", "", "b/log4j-core-2.14.1.jar", "")).size() == 2);

        // hostile and broken archives
        List<Scanner.Finding> bad = scan("this is not a zip".getBytes());
        check("garbage file gives no crash", bad.isEmpty() || bad.get(0).rule.equals("JAR000"));
        check("empty file", scan(new byte[0]).isEmpty() || scan(new byte[0]).get(0).rule.equals("JAR000"));
        check("truncated zip", scan(Arrays.copyOf(zip("log4j-core-2.14.1.jar", "x"), 20)).size() <= 1);

        // sorting
        List<Scanner.Finding> mix = scan(zip("lib/log4j-core-2.17.0.jar", "", "lib/snakeyaml-1.0.jar", "", "lib/commons-text-1.9.jar", ""));
        check("sorted by severity", mix.get(0).severity.equals("critical") && mix.get(mix.size() - 1).severity.equals("low"));

        // directory scan
        Path d = Files.createTempDirectory(tmp, "dir");
        Files.write(d.resolve("a.war"), zip("WEB-INF/lib/snakeyaml-1.0.jar", ""));
        Files.write(d.resolve("b.txt"), "x".getBytes());
        Files.createDirectories(d.resolve("sub"));
        Files.write(d.resolve("sub/c.jar"), zip("snakeyaml-1.0.jar", ""));
        check("find picks archives only", Scanner.find(d).size() == 2);

        // CLI
        check("cli ok", run(new String[]{d.toString()}) == 0);
        check("cli fail-on high", run(new String[]{d.toString(), "--fail-on", "high"}) == 1);
        check("cli fail-on critical clean", run(new String[]{d.toString(), "--fail-on", "critical"}) == 0);
        check("cli missing path", run(new String[]{"/no/such/path"}) == 2);
        check("cli no args", run(new String[]{}) == 2);
        check("cli bad flag", run(new String[]{d.toString(), "--bogus"}) == 2);
        check("cli bad fail-on", run(new String[]{d.toString(), "--fail-on", "nope"}) == 2);
        ByteArrayOutputStream cap = new ByteArrayOutputStream();
        Main.run(new String[]{d.toString(), "--tsv"}, new PrintStream(cap), System.err);
        check("cli tsv", cap.toString().startsWith("# 2 archives, 2 findings\nhigh\tCVE-2022-1471\t"));

        System.out.println(n + " checks, " + fail + " failed");
        System.exit(fail == 0 ? 0 : 1);
    }
}
