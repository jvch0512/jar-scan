#!/usr/bin/env python3
"""Builds the synthetic archives in examples/. Entries are names only (empty or tiny files). Deterministic."""
import io
import zipfile

def z(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as f:
        for name, data in entries:
            i = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            i.compress_type = zipfile.ZIP_DEFLATED
            f.writestr(i, data)
    return buf.getvalue()

def pom(group, artifact, version):
    return ("groupId=%s\nartifactId=%s\nversion=%s\n" % (group, artifact, version)).encode()

shop_inner = z([("org/apache/logging/log4j/core/lookup/JndiLookup.class", b""), ("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n")])
open("examples/shop.war", "wb").write(z([
    ("WEB-INF/web.xml", b"<web-app/>"),
    ("WEB-INF/lib/log4j-core-2.14.1.jar", shop_inner),
    ("WEB-INF/lib/log4j-api-2.14.1.jar", b""),
    ("WEB-INF/lib/commons-text-1.9.jar", b""),
    ("WEB-INF/lib/spring-beans-5.3.17.jar", b""),
    ("WEB-INF/lib/commons-lang3-3.12.0.jar", b""),
]))
open("examples/reports-fat.jar", "wb").write(z([
    ("BOOT-INF/classes/app/Main.class", b""),
    ("BOOT-INF/lib/snakeyaml-1.33.jar", b""),
    ("BOOT-INF/lib/jackson-core-2.15.2.jar", b""),
    ("BOOT-INF/lib/log4j-core-2.17.1.jar", b""),
]))
open("examples/tool-shaded.jar", "wb").write(z([
    ("app/Tool.class", b""),
    ("META-INF/maven/org.apache.struts/struts2-core/pom.properties", pom("org.apache.struts", "struts2-core", "2.5.30")),
    ("META-INF/maven/commons-collections/commons-collections/pom.properties", pom("commons-collections", "commons-collections", "3.2.1")),
    ("META-INF/maven/com.h2database/h2/pom.properties", pom("com.h2database", "h2", "2.2.220")),
]))
open("examples/legacy.jar", "wb").write(z([
    ("lib/log4j-1.2.17.jar", b""),
    ("org/apache/logging/log4j/core/lookup/JndiLookup.class", b""),
]))
