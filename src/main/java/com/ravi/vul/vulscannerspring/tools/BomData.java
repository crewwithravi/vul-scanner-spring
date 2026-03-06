package com.ravi.vul.vulscannerspring.tools;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Static Spring Boot BOM version → managed library version mappings.
 * Used by resolveBomParent() to determine the correct parent version to bump
 * instead of directly upgrading a BOM-managed dependency.
 *
 * Source: https://docs.spring.io/spring-boot/appendix/dependency-versions/
 */
public final class BomData {

    private BomData() {}

    /** Map: springBootVersion → (groupId:artifactId → version) */
    public static final Map<String, Map<String, String>> SPRING_BOOT_BOM;

    static {
        SPRING_BOOT_BOM = new LinkedHashMap<>();

        SPRING_BOOT_BOM.put("3.5.11", entries(
            "org.apache.tomcat.embed:tomcat-embed-core",        "10.1.42",
            "org.apache.tomcat.embed:tomcat-embed-el",          "10.1.42",
            "org.apache.tomcat.embed:tomcat-embed-websocket",   "10.1.42",
            "io.netty:netty-all",                               "4.1.121.Final",
            "com.fasterxml.jackson.core:jackson-databind",      "2.19.0",
            "org.apache.logging.log4j:log4j-core",              "2.24.3",
            "org.springframework:spring-core",                  "6.2.8",
            "org.springframework.security:spring-security-core","6.4.5",
            "ch.qos.logback:logback-classic",                   "1.5.18",
            "org.yaml:snakeyaml",                               "2.4"
        ));

        SPRING_BOOT_BOM.put("3.5.8", entries(
            "org.apache.tomcat.embed:tomcat-embed-core",        "10.1.39",
            "org.apache.tomcat.embed:tomcat-embed-el",          "10.1.39",
            "org.apache.tomcat.embed:tomcat-embed-websocket",   "10.1.39",
            "io.netty:netty-all",                               "4.1.118.Final",
            "com.fasterxml.jackson.core:jackson-databind",      "2.18.3",
            "org.apache.logging.log4j:log4j-core",              "2.24.3",
            "org.springframework:spring-core",                  "6.2.5"
        ));

        SPRING_BOOT_BOM.put("3.4.5", entries(
            "org.apache.tomcat.embed:tomcat-embed-core",        "10.1.35",
            "io.netty:netty-all",                               "4.1.115.Final",
            "com.fasterxml.jackson.core:jackson-databind",      "2.18.2",
            "org.apache.logging.log4j:log4j-core",              "2.24.2"
        ));

        SPRING_BOOT_BOM.put("3.3.10", entries(
            "org.apache.tomcat.embed:tomcat-embed-core",        "10.1.30",
            "io.netty:netty-all",                               "4.1.110.Final",
            "com.fasterxml.jackson.core:jackson-databind",      "2.17.2"
        ));

        SPRING_BOOT_BOM.put("3.2.12", entries(
            "org.apache.tomcat.embed:tomcat-embed-core",        "10.1.28",
            "io.netty:netty-all",                               "4.1.107.Final",
            "com.fasterxml.jackson.core:jackson-databind",      "2.16.2"
        ));

        SPRING_BOOT_BOM.put("2.7.18", entries(
            "org.apache.tomcat.embed:tomcat-embed-core",        "9.0.83",
            "io.netty:netty-all",                               "4.1.100.Final",
            "com.fasterxml.jackson.core:jackson-databind",      "2.14.3",
            "org.apache.logging.log4j:log4j-core",              "2.20.0"
        ));

        SPRING_BOOT_BOM.put("2.7.8", entries(
            "org.apache.tomcat.embed:tomcat-embed-core",        "9.0.70",
            "io.netty:netty-all",                               "4.1.85.Final",
            "com.fasterxml.jackson.core:jackson-databind",      "2.14.1"
        ));

        SPRING_BOOT_BOM.put("2.6.14", entries(
            "org.apache.tomcat.embed:tomcat-embed-core",        "9.0.65",
            "com.fasterxml.jackson.core:jackson-databind",      "2.13.5"
        ));
    }

    /** GitHub repo for Maven groupId — used by fetchChangelog. */
    public static final Map<String, String> MAVEN_TO_GITHUB = new HashMap<>();

    static {
        MAVEN_TO_GITHUB.put("org.apache.logging.log4j",     "apache/logging-log4j2");
        MAVEN_TO_GITHUB.put("org.springframework",          "spring-projects/spring-framework");
        MAVEN_TO_GITHUB.put("org.springframework.boot",     "spring-projects/spring-boot");
        MAVEN_TO_GITHUB.put("org.springframework.security", "spring-projects/spring-security");
        MAVEN_TO_GITHUB.put("com.fasterxml.jackson.core",   "FasterXML/jackson-core");
        MAVEN_TO_GITHUB.put("com.google.guava",             "google/guava");
        MAVEN_TO_GITHUB.put("com.google.code.gson",         "google/gson");
        MAVEN_TO_GITHUB.put("io.netty",                     "netty/netty");
        MAVEN_TO_GITHUB.put("org.yaml",                     "snakeyaml/snakeyaml");
        MAVEN_TO_GITHUB.put("org.apache.httpcomponents",    "apache/httpcomponents-client");
        MAVEN_TO_GITHUB.put("org.apache.tomcat.embed",      "apache/tomcat");
        MAVEN_TO_GITHUB.put("org.apache.tomcat",            "apache/tomcat");
        MAVEN_TO_GITHUB.put("ch.qos.logback",               "qos-ch/logback");
        MAVEN_TO_GITHUB.put("org.slf4j",                    "qos-ch/slf4j");
        MAVEN_TO_GITHUB.put("org.apache.struts",            "apache/struts");
        MAVEN_TO_GITHUB.put("commons-io",                   "apache/commons-io");
        MAVEN_TO_GITHUB.put("commons-lang",                 "apache/commons-lang");
    }

    /** Apache changelog URL templates (group → URL with {major} placeholder). */
    public static final Map<String, String> APACHE_CHANGELOG_URLS = Map.of(
        "org.apache.tomcat.embed", "https://tomcat.apache.org/tomcat-{major}-doc/changelog.html",
        "org.apache.tomcat",       "https://tomcat.apache.org/tomcat-{major}-doc/changelog.html",
        "org.apache.struts",       "https://struts.apache.org/announce.html"
    );

    /** NVD CPE mapping: Maven groupId → (vendor, product, keyword). */
    public static final Map<String, String[]> MAVEN_CPE_MAP = new HashMap<>();

    static {
        MAVEN_CPE_MAP.put("org.apache.tomcat.embed",   new String[]{"apache", "tomcat",   "Apache Tomcat"});
        MAVEN_CPE_MAP.put("org.apache.tomcat",         new String[]{"apache", "tomcat",   "Apache Tomcat"});
        MAVEN_CPE_MAP.put("org.apache.struts",         new String[]{"apache", "struts2",  "Apache Struts"});
        MAVEN_CPE_MAP.put("org.apache.logging.log4j",  new String[]{"apache", "log4j2",   "Apache Log4j"});
        MAVEN_CPE_MAP.put("org.apache.log4j",          new String[]{"apache", "log4j2",   "Apache Log4j"});
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    private static Map<String, String> entries(String... pairs) {
        Map<String, String> map = new LinkedHashMap<>();
        for (int i = 0; i + 1 < pairs.length; i += 2) {
            map.put(pairs[i], pairs[i + 1]);
        }
        return map;
    }

    /** Parse a version string into an int[] for comparison. */
    public static int[] parseVersion(String version) {
        if (version == null || version.isBlank()) return new int[0];
        String cleaned = version.replaceAll("[^0-9.\\-]", "");
        String[] parts = cleaned.split("[.\\-]");
        int[] result = new int[parts.length];
        for (int i = 0; i < parts.length; i++) {
            try { result[i] = Integer.parseInt(parts[i]); }
            catch (NumberFormatException e) { return java.util.Arrays.copyOf(result, i); }
        }
        return result;
    }

    /** Compare two version int arrays. Returns negative/0/positive like Comparator. */
    public static int compareVersions(int[] a, int[] b) {
        int len = Math.max(a.length, b.length);
        for (int i = 0; i < len; i++) {
            int av = i < a.length ? a[i] : 0;
            int bv = i < b.length ? b[i] : 0;
            if (av != bv) return Integer.compare(av, bv);
        }
        return 0;
    }
}
