package jarscan;

import java.util.ArrayList;
import java.util.List;

/** Curated table of well-known vulnerable library ranges. */
public final class Rules {
    public static final class Rule {
        public final String artifact, id, severity, message;
        final Version from, to; // from inclusive (null = open), to exclusive
        Rule(String artifact, String from, String to, String severity, String id, String message) {
            this.artifact = artifact; this.from = from == null ? null : Version.parse(from); this.to = Version.parse(to);
            this.severity = severity; this.id = id; this.message = message;
        }
        boolean matches(String a, Version v) {
            if (!artifact.equals(a)) return false;
            if (from != null && v.compareTo(from) < 0) return false;
            return v.compareTo(to) < 0;
        }
    }

    public static final List<Rule> ALL = new ArrayList<>();
    static {
        add("log4j-core", null, "2.15.0", "critical", "CVE-2021-44228", "Log4Shell: remote code execution through JNDI lookups, upgrade to 2.17.1 or later");
        add("log4j-core", "2.15.0", "2.16.0", "high", "CVE-2021-45046", "incomplete Log4Shell fix, upgrade to 2.17.1 or later");
        add("log4j-core", "2.16.0", "2.17.0", "medium", "CVE-2021-45105", "denial of service through recursive lookups, upgrade to 2.17.1 or later");
        add("log4j-core", "2.17.0", "2.17.1", "low", "CVE-2021-44832", "remote code execution if an attacker controls the logging configuration, upgrade to 2.17.1 or later");
        add("log4j", "1.0", "2.0", "high", "CVE-2019-17571", "Log4j 1.x is end of life and has a deserialization flaw in SocketServer, migrate to Log4j 2.17.1 or later");
        add("commons-text", "1.5", "1.10.0", "critical", "CVE-2022-42889", "Text4Shell: code execution through string interpolation, upgrade to 1.10.0 or later");
        add("spring-beans", "5.2.0", "5.2.20", "high", "CVE-2022-22965", "Spring4Shell: remote code execution on JDK 9 or later when deployed as a WAR on Tomcat, upgrade to 5.2.20 or 5.3.18");
        add("spring-beans", "5.3.0", "5.3.18", "high", "CVE-2022-22965", "Spring4Shell: remote code execution on JDK 9 or later when deployed as a WAR on Tomcat, upgrade to 5.3.18 or later");
        add("struts2-core", null, "2.5.33", "critical", "CVE-2023-50164", "file upload path traversal leading to remote code execution, upgrade to 2.5.33 or 6.3.0.2");
        add("struts2-core", "6.0.0", "6.3.0.2", "critical", "CVE-2023-50164", "file upload path traversal leading to remote code execution, upgrade to 6.3.0.2 or later");
        add("snakeyaml", null, "2.0", "high", "CVE-2022-1471", "unsafe deserialization when loading untrusted YAML, upgrade to 2.0 or later");
        add("commons-collections", "3.0", "3.2.2", "high", "CVE-2015-7501", "deserialization gadget chains, upgrade to 3.2.2 or 4.1");
        add("commons-collections", "4.0", "4.1", "high", "CVE-2015-7501", "deserialization gadget chains, upgrade to 4.1 or later");
        add("h2", null, "2.0.206", "critical", "CVE-2021-42392", "remote code execution through JNDI in the H2 console and URLs, upgrade to 2.0.206 or later");
        add("fastjson", null, "1.2.83", "high", "CVE-2022-25845", "remote code execution through autoType, upgrade to 1.2.83 or later");
        add("xstream", null, "1.4.20", "high", "CVE-2022-41966", "denial of service through crafted XML, upgrade to 1.4.20 or later");
    }

    private static void add(String a, String from, String to, String sev, String id, String msg) {
        ALL.add(new Rule(a, from, to, sev, id, msg));
    }

    public static List<Rule> match(String artifact, Version v) {
        List<Rule> out = new ArrayList<>();
        if (v == null) return out;
        for (Rule r : ALL) if (r.matches(artifact, v)) out.add(r);
        return out;
    }
}
