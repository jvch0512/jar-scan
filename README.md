# jar-scan

jar-scan opens JAR, WAR and EAR files and looks for libraries with famous remote code execution and deserialization bugs: Log4Shell, Text4Shell, Spring4Shell, Struts, SnakeYAML, commons-collections gadgets and more. It reads library file names, the `pom.properties` files that Maven leaves inside shaded jars, and well-known class files, and it goes into nested jars (Spring Boot fat jars), so a library that was copied into another jar is still found.

**Live demo:** https://jvch0512.github.io/jar-scan/ (Synthetic archives that contain only entry names, no real library code.)

Java 17+, JDK only (no dependencies). The demo page is rendered from the tool's `--tsv` output by `scripts/site.py` (Python 3, only needed to regenerate the page).

## Use

```bash
make build
java -cp out jarscan.Main examples
java -cp out jarscan.Main app.war --tsv
java -cp out jarscan.Main /opt/apps --fail-on high      # exit 1 in CI
```

Pass a file or a directory (searched recursively for `.jar`, `.war`, `.ear`).

Rules are CVE identifiers. The built-in table covers:

| Library | Affected | Issue |
|---|---|---|
| log4j-core | below 2.15.0 (critical), 2.15.0, 2.16.0, 2.17.0 | CVE-2021-44228, CVE-2021-45046, CVE-2021-45105, CVE-2021-44832 |
| commons-text | 1.5 to 1.9 | CVE-2022-42889 (Text4Shell) |
| spring-beans / spring-core | 5.2.0 to 5.2.19, 5.3.0 to 5.3.17 | CVE-2022-22965 (Spring4Shell) |
| struts2-core | below 2.5.33, 6.0.0 to 6.3.0.1 | CVE-2023-50164 |
| snakeyaml | below 2.0 | CVE-2022-1471 |
| commons-collections | 3.0 to 3.2.1, 4.0 | CVE-2015-7501 (deserialization gadgets) |
| h2 | below 2.0.206 | CVE-2021-42392 |
| fastjson | below 1.2.83 | CVE-2022-25845 |
| xstream | below 1.4.20 | CVE-2022-41966 |
| log4j 1.x | any | end of life, CVE-2019-17571 |
| JndiLookup.class | present without a known version | possible shaded Log4j 2 |

See [examples](examples) and [docs/sample-output.txt](docs/sample-output.txt).

## Limits

- It is a small curated table, not a vulnerability database. Use it for fast triage and combine it with a full SCA tool (Dependency-Check, Grype, Trivy) for coverage.
- Version ranges are the ones in the public advisories. Back-ported fixes in vendor builds (for example Red Hat) can make a flagged version safe.
- Whether a flagged library is reachable depends on how the application uses it. A finding means "present and in a vulnerable range".
- Archives are read in memory with limits on depth (3), entries and nested size, to survive hostile files.

## Where it fits

Incident response and exposure checks on application servers: a quick answer to "do we ship anything with Log4Shell or Spring4Shell, and where exactly?" on hosts where installing a scanner is not possible.

## Tests

```bash
make test    # 65 checks
```

MIT.
