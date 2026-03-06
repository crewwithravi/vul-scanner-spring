package com.ravi.vul.vulscannerspring.tools;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.regex.*;
import java.util.stream.*;

/**
 * VulnHawk Tools — Spring AI @Tool-annotated methods.
 *
 * Provides 8 tools for the 4-agent vulnerability scanning pipeline:
 *   1. detectBuildSystem     — detect Maven or Gradle
 *   2. extractDependencies   — run mvn/gradle and parse full transitive tree
 *   3. checkOsvVulnerabilities — query OSV batch API
 *   4. lookupLatestSafeVersion — query Maven Central for available versions
 *   5. resolveBomParent      — find the correct Spring Boot BOM version to bump
 *   6. searchCodeUsage       — grep Java/Kotlin source for a package pattern
 *   7. fetchChangelog         — fetch GitHub release notes or Apache HTML changelog
 *   8. readProjectDocs        — read README and other docs from the repo
 */
@Component
public class VulnHawkTools {

    private static final Logger log = LoggerFactory.getLogger(VulnHawkTools.class);

    private final ObjectMapper om = new ObjectMapper();
    private final RestClient http = RestClient.create();

    @Value("${vulnhawk.github.token:}")
    private String githubToken;

    // ── TOOL 1: Detect Build System ─────────────────────────────────────────

    @Tool(description =
        "Scans a repository path and detects whether the project uses Maven or Gradle. " +
        "Input: repoPath — the absolute path to the repository root directory. " +
        "Returns: 'maven', 'gradle', or 'unknown'.")
    public String detectBuildSystem(String repoPath) {
        repoPath = sanitizePath(repoPath);
        Path dir = Path.of(repoPath);
        if (!Files.isDirectory(dir)) return "ERROR: Directory not found: " + repoPath;

        for (String name : List.of("build.gradle", "build.gradle.kts", "settings.gradle",
                                   "settings.gradle.kts", "gradlew")) {
            if (Files.exists(dir.resolve(name))) return "gradle";
        }
        if (Files.exists(dir.resolve("pom.xml"))) return "maven";

        // Walk up to 2 levels deep
        try (var stream = Files.walk(dir, 2)) {
            return stream
                .filter(Files::isRegularFile)
                .map(p -> p.getFileName().toString())
                .filter(n -> n.equals("build.gradle") || n.equals("build.gradle.kts") || n.equals("pom.xml"))
                .map(n -> n.equals("pom.xml") ? "maven" : "gradle")
                .findFirst()
                .orElse("unknown");
        } catch (IOException e) {
            return "unknown";
        }
    }

    // ── TOOL 2: Extract Dependencies ────────────────────────────────────────

    @Tool(description =
        "Extracts ALL dependencies (including transitive) from a Maven or Gradle project. " +
        "Input: repoPath — absolute path to the repo; buildSystem — 'maven' or 'gradle'. " +
        "Returns a JSON array of dependencies with groupId, artifactId, version, scope, depth " +
        "(depth 0 = direct dependency, depth 1+ = transitive).")
    public String extractDependencies(String repoPath, String buildSystem) {
        repoPath = sanitizePath(repoPath);
        buildSystem = buildSystem == null ? "" : buildSystem.strip().toLowerCase();
        Path dir = Path.of(repoPath);
        if (!Files.isDirectory(dir)) return "ERROR: Directory not found: " + repoPath;
        return switch (buildSystem) {
            case "maven"  -> extractMaven(dir);
            case "gradle" -> extractGradle(dir);
            default       -> "ERROR: Unsupported build system: " + buildSystem;
        };
    }

    private String extractMaven(Path dir) {
        try {
            List<String> cmd = List.of("mvn", "dependency:tree",
                "-DoutputType=text", "-Dverbose=false", "--batch-mode", "-q");
            String output = runProcess(dir, cmd, 180);
            if (output != null && !output.isBlank()) {
                List<Map<String, Object>> parsed = parseMavenTree(output);
                if (!parsed.isEmpty()) return om.writeValueAsString(parsed);
            }
        } catch (Exception e) {
            log.debug("mvn dependency:tree failed: {}", e.getMessage());
        }
        // Fallback: parse pom.xml directly
        return parsePomXml(dir.resolve("pom.xml"));
    }

    private List<Map<String, Object>> parseMavenTree(String output) {
        List<Map<String, Object>> deps = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        // groupId:artifactId:packaging:version:scope
        Pattern coord = Pattern.compile(
            "\\s[+\\\\|`\\- ]*([^\\s:]+):([^\\s:]+):[^\\s:]+:([^\\s:]+):([^\\s:]+)");
        Pattern depthPat = Pattern.compile("(\\|   |    |\\|  |   )");

        for (String line : output.split("\n")) {
            if (!line.contains("[INFO]")) continue;
            String content = line.split("\\[INFO]", 2)[1];
            Matcher m = coord.matcher(content);
            if (!m.find()) continue;
            String groupId    = m.group(1).strip();
            String artifactId = m.group(2).strip();
            String version    = m.group(3).strip();
            String scope      = m.group(4).strip();
            if (groupId.isEmpty() || artifactId.isEmpty() || version.isEmpty()) continue;
            if (List.of("test", "provided", "system").contains(scope)) continue;
            String key = groupId + ":" + artifactId;
            if (!seen.add(key)) continue;
            int depth = depthPat.matcher(content.substring(0, m.start())).results().mapToInt(r -> 1).sum();
            Map<String, Object> dep = new LinkedHashMap<>();
            dep.put("group_id", groupId);
            dep.put("artifact_id", artifactId);
            dep.put("version", version);
            dep.put("scope", scope);
            dep.put("depth", depth);
            deps.add(dep);
        }
        return deps;
    }

    private String parsePomXml(Path pomPath) {
        if (!Files.exists(pomPath)) return "ERROR: pom.xml not found";
        try {
            String xml = Files.readString(pomPath);
            // Extract namespace
            String ns = "";
            Matcher nsMatcher = Pattern.compile("xmlns=\"([^\"]+)\"").matcher(xml);
            if (nsMatcher.find()) ns = nsMatcher.group(1);
            String nsPrefix = ns.isEmpty() ? "" : "{" + ns + "}";

            // Parse properties for ${...} resolution
            Map<String, String> props = new LinkedHashMap<>();
            Matcher propMatcher = Pattern.compile("<([^/][^>]*)>([^<]+)<").matcher(xml);
            // Simple property extraction (key=value in <properties>)
            Pattern propsSection = Pattern.compile("<properties[^>]*>(.*?)</properties>", Pattern.DOTALL);
            Matcher psm = propsSection.matcher(xml);
            if (psm.find()) {
                Matcher pm = Pattern.compile("<([^>/\\s]+)>([^<]+)<").matcher(psm.group(1));
                while (pm.find()) props.put(pm.group(1), pm.group(2).strip());
            }

            List<Map<String, Object>> deps = new ArrayList<>();
            Pattern depPat = Pattern.compile(
                "<dependency[^>]*>(.*?)</dependency>", Pattern.DOTALL);
            Matcher dm = depPat.matcher(xml);
            while (dm.find()) {
                String block = dm.group(1);
                String g = extractTag(block, "groupId");
                String a = extractTag(block, "artifactId");
                String v = extractTag(block, "version");
                String s = extractTag(block, "scope");
                if (g.isEmpty() || a.isEmpty()) continue;
                if (v.startsWith("${")) v = props.getOrDefault(v.substring(2, v.length() - 1), v);
                if (v.startsWith("${")) v = "UNKNOWN";
                if (s.isEmpty()) s = "compile";
                if (List.of("test", "provided", "system").contains(s)) continue;
                Map<String, Object> dep = new LinkedHashMap<>();
                dep.put("group_id", g);
                dep.put("artifact_id", a);
                dep.put("version", v);
                dep.put("scope", s);
                dep.put("depth", 0);
                deps.add(dep);
            }
            return deps.isEmpty() ? "ERROR: No dependencies found in pom.xml"
                                  : om.writeValueAsString(deps);
        } catch (Exception e) {
            return "ERROR: Failed to parse pom.xml: " + e.getMessage();
        }
    }

    private String extractGradle(Path dir) {
        // Try gradlew or system gradle
        String gradlew = Files.exists(dir.resolve("gradlew")) ? dir.resolve("gradlew").toString() : "gradle";
        if (!gradlew.equals("gradle")) {
            try { new File(gradlew).setExecutable(true); } catch (Exception ignored) {}
        }

        for (String config : List.of("runtimeClasspath", "compileClasspath")) {
            try {
                List<String> cmd = List.of(gradlew, "dependencies",
                    "--configuration", config, "--no-daemon");
                String output = runProcess(dir, cmd, 180);
                if (output != null && !output.isBlank()) {
                    List<Map<String, Object>> deps = parseGradleTree(output);
                    if (!deps.isEmpty()) return om.writeValueAsString(deps);
                }
            } catch (Exception e) {
                log.debug("Gradle {} failed: {}", config, e.getMessage());
            }
        }
        // Fallback: parse build.gradle manually
        return parseBuildGradle(dir);
    }

    private List<Map<String, Object>> parseGradleTree(String output) {
        List<Map<String, Object>> deps = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        Pattern p = Pattern.compile("[+\\\\|\\- ]+([^\\s:]+):([^\\s:]+):([^\\s:()+]+)");
        for (String line : output.split("\n")) {
            Matcher m = p.matcher(line);
            if (!m.find()) continue;
            String g = m.group(1), a = m.group(2), v = m.group(3);
            if (v.contains(" -> ")) v = v.substring(v.lastIndexOf(" -> ") + 4);
            v = v.replaceAll("[(*)]", "").strip();
            if (v.isEmpty()) continue;
            String key = g + ":" + a;
            if (!seen.add(key)) continue;
            int indent = line.length() - line.replaceAll("^[ |+\\\\`]+", "").length();
            int depth = Math.max(0, indent / 5);
            Map<String, Object> dep = new LinkedHashMap<>();
            dep.put("group_id", g);
            dep.put("artifact_id", a);
            dep.put("version", v);
            dep.put("scope", "runtime");
            dep.put("depth", depth);
            deps.add(dep);
        }
        return deps;
    }

    private String parseBuildGradle(Path dir) {
        for (String name : List.of("build.gradle", "build.gradle.kts")) {
            Path p = dir.resolve(name);
            if (!Files.exists(p)) continue;
            try {
                String content = Files.readString(p);
                List<Map<String, Object>> deps = new ArrayList<>();
                Set<String> seen = new LinkedHashSet<>();
                Pattern pat = Pattern.compile("'([A-Za-z0-9][\\w.\\-]*:[A-Za-z0-9][\\w.\\-]*:[A-Za-z0-9][\\w.\\-]*)'");
                Matcher m = pat.matcher(content);
                while (m.find()) {
                    String[] parts = m.group(1).split(":");
                    if (parts.length != 3) continue;
                    String key = parts[0] + ":" + parts[1];
                    if (!seen.add(key)) continue;
                    Map<String, Object> dep = new LinkedHashMap<>();
                    dep.put("group_id", parts[0]);
                    dep.put("artifact_id", parts[1]);
                    dep.put("version", parts[2]);
                    dep.put("scope", "compile");
                    dep.put("depth", 0);
                    deps.add(dep);
                }
                if (!deps.isEmpty()) return om.writeValueAsString(deps);
            } catch (Exception e) {
                log.debug("Failed to parse {}: {}", name, e.getMessage());
            }
        }
        return "ERROR: No dependencies found in build.gradle";
    }

    // ── TOOL 3: Check OSV Vulnerabilities ───────────────────────────────────

    @Tool(description =
        "Checks a list of Maven/Gradle dependencies against the OSV (Open Source Vulnerabilities) database. " +
        "Input: dependenciesJson — JSON array with group_id, artifact_id, version for each dependency. " +
        "Returns a JSON vulnerability report with total_dependencies_checked, vulnerable_count, safe_count, " +
        "and a list of vulnerabilities with CVE/GHSA IDs and severity details.")
    public String checkOsvVulnerabilities(String dependenciesJson) {
        try {
            List<Map<String, Object>> allDeps = om.readValue(dependenciesJson, List.class);
            List<Map<String, Object>> queries = new ArrayList<>();
            List<Map<String, Object>> depMap = new ArrayList<>();

            for (Object obj : allDeps) {
                Map<String, Object> dep = (Map<String, Object>) obj;
                String g = str(dep, "group_id"), a = str(dep, "artifact_id"), v = str(dep, "version");
                if (g.isEmpty() || a.isEmpty() || v.isEmpty() || "UNKNOWN".equals(v)) continue;
                queries.add(Map.of(
                    "package", Map.of("name", g + ":" + a, "ecosystem", "Maven"),
                    "version", v
                ));
                depMap.add(dep);
            }

            if (queries.isEmpty()) return "No valid dependencies to check.";

            List<Object> allResults = new ArrayList<>();
            for (int i = 0; i < queries.size(); i += 1000) {
                List<Map<String, Object>> batch = queries.subList(i, Math.min(i + 1000, queries.size()));
                String body = om.writeValueAsString(Map.of("queries", batch));
                String resp = http.post()
                    .uri("https://api.osv.dev/v1/querybatch")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(body)
                    .retrieve()
                    .body(String.class);
                Map<String, Object> respMap = om.readValue(resp, Map.class);
                allResults.addAll((List<?>) respMap.getOrDefault("results", List.of()));
            }

            Map<String, Object> report = new LinkedHashMap<>();
            report.put("total_dependencies_checked", depMap.size());
            int vulnCount = 0, safeCount = 0;
            List<Map<String, Object>> vulns = new ArrayList<>();

            for (int i = 0; i < allResults.size() && i < depMap.size(); i++) {
                Map<String, Object> dep = depMap.get(i);
                Map<String, Object> result = (Map<String, Object>) allResults.get(i);
                List<Object> vulnList = (List<Object>) result.getOrDefault("vulns", List.of());

                if (vulnList.isEmpty()) {
                    safeCount++;
                    continue;
                }
                vulnCount++;
                List<String> ids = vulnList.stream()
                    .map(v -> str((Map<?, ?>) v, "id")).collect(Collectors.toList());
                List<Map<String, Object>> details = ids.stream().limit(5)
                    .map(this::fetchVulnDetails)
                    .filter(Objects::nonNull)
                    .collect(Collectors.toList());

                String coord = str(dep, "group_id") + ":" + str(dep, "artifact_id") + ":" + str(dep, "version");
                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put("dependency", coord);
                entry.put("vulnerability_ids", ids);
                entry.put("details", details);
                vulns.add(entry);
            }

            report.put("vulnerable_count", vulnCount);
            report.put("safe_count", safeCount);
            report.put("vulnerabilities", vulns);
            return om.writeValueAsString(report);

        } catch (Exception e) {
            return "ERROR: " + e.getMessage();
        }
    }

    private Map<String, Object> fetchVulnDetails(String vulnId) {
        try {
            String resp = http.get()
                .uri("https://api.osv.dev/v1/vulns/" + vulnId)
                .retrieve()
                .body(String.class);
            Map<String, Object> data = om.readValue(resp, Map.class);
            List<String> fixed = new ArrayList<>();
            String severity = "UNKNOWN";
            String summary = str(data, "summary");
            for (Object aff : (List<?>) data.getOrDefault("affected", List.of())) {
                Map<String, Object> affMap = (Map<String, Object>) aff;
                for (Object rng : (List<?>) affMap.getOrDefault("ranges", List.of())) {
                    for (Object evt : (List<?>) ((Map<String, Object>) rng).getOrDefault("events", List.of())) {
                        Object fix = ((Map<?, ?>) evt).get("fixed");
                        if (fix != null) fixed.add(fix.toString());
                    }
                }
                Object dbSev = ((Map<?, ?>) affMap.getOrDefault("database_specific", Map.of())).get("severity");
                if (dbSev instanceof String s && List.of("LOW","MEDIUM","HIGH","CRITICAL").contains(s.toUpperCase()))
                    severity = s.toUpperCase();
            }
            if ("UNKNOWN".equals(severity)) {
                for (Object sevObj : (List<?>) data.getOrDefault("severity", List.of())) {
                    Map<String, Object> sev = (Map<String, Object>) sevObj;
                    if ("CVSS_V3".equals(sev.get("type"))) {
                        severity = cvssVectorToSeverity(str(sev, "score"));
                        break;
                    }
                }
            }
            Map<String, Object> det = new LinkedHashMap<>();
            det.put("id", vulnId);
            det.put("summary", summary.length() > 200 ? summary.substring(0, 200) : summary);
            det.put("severity", severity);
            det.put("fixed_versions", fixed);
            det.put("aliases", ((List<?>) data.getOrDefault("aliases", List.of())).stream().limit(5).collect(Collectors.toList()));
            det.put("references", ((List<?>) data.getOrDefault("references", List.of())).stream()
                .limit(3).map(r -> str((Map<?,?>) r, "url")).collect(Collectors.toList()));
            return det;
        } catch (Exception e) {
            return Map.of("id", vulnId, "summary", "Failed to fetch details", "severity", "UNKNOWN",
                "fixed_versions", List.of(), "aliases", List.of(), "references", List.of());
        }
    }

    // ── TOOL 4: Lookup Latest Safe Version ──────────────────────────────────

    @Tool(description =
        "Looks up available versions of a Maven artifact on Maven Central and identifies " +
        "which ones fix known vulnerabilities. " +
        "Input: groupId, artifactId, currentVersion, fixedVersions (comma-separated list of known fixed versions, may be empty). " +
        "Returns a JSON with recommended_upgrade and annotated list of available_versions.")
    public String lookupLatestSafeVersion(String groupId, String artifactId,
                                          String currentVersion, String fixedVersions) {
        if (groupId == null || groupId.isBlank() || artifactId == null || artifactId.isBlank())
            return "ERROR: groupId and artifactId are required.";
        try {
            String url = String.format(
                "https://search.maven.org/solrsearch/select?q=g:%s+AND+a:%s&rows=20&wt=json&core=gav",
                groupId.strip(), artifactId.strip());
            String resp = http.get().uri(url).retrieve().body(String.class);
            Map<String, Object> respMap = om.readValue(resp, Map.class);
            List<Map<String, Object>> docs = (List<Map<String, Object>>)
                ((Map<String, Object>) respMap.getOrDefault("response", Map.of())).getOrDefault("docs", List.of());

            Set<String> fixedSet = new HashSet<>();
            if (fixedVersions != null && !fixedVersions.isBlank())
                Arrays.stream(fixedVersions.split(",")).map(String::strip).filter(s -> !s.isEmpty())
                    .forEach(fixedSet::add);

            int[] currentParts = BomData.parseVersion(currentVersion == null ? "" : currentVersion.strip());
            List<Map<String, Object>> versions = new ArrayList<>();
            String recommended = null;

            for (Map<String, Object> doc : docs) {
                String ver = str(doc, "v");
                if (ver.isEmpty()) continue;
                int[] verParts = BomData.parseVersion(ver);
                boolean isUpgrade = BomData.compareVersions(verParts, currentParts) > 0;
                boolean isFix = fixedSet.contains(ver);
                boolean sameMajor = currentParts.length > 0 && verParts.length > 0 && verParts[0] == currentParts[0];
                String direction = ver.equals(currentVersion) ? "CURRENT" : (isUpgrade ? "UPGRADE" : "DOWNGRADE");

                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put("version", ver);
                entry.put("direction", direction);
                entry.put("fixes_vulnerability", isFix);
                entry.put("same_major_version", sameMajor);
                versions.add(entry);

                if (recommended == null && isUpgrade && isFix) recommended = ver;
            }
            if (recommended == null)
                recommended = versions.stream().filter(v -> "UPGRADE".equals(v.get("direction")))
                    .map(v -> str(v, "version")).findFirst().orElse(null);

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("artifact", groupId + ":" + artifactId);
            result.put("current_version", currentVersion);
            result.put("recommended_upgrade", recommended);
            result.put("available_versions", versions);
            if (!fixedSet.isEmpty()) result.put("known_fixed_versions", new ArrayList<>(fixedSet));
            return om.writeValueAsString(result);

        } catch (Exception e) {
            return "ERROR: Maven Central lookup failed: " + e.getMessage();
        }
    }

    // ── TOOL 5: BOM Parent Resolver ─────────────────────────────────────────

    @Tool(description =
        "Determines whether a vulnerable dependency is managed by the Spring Boot BOM " +
        "(e.g. Tomcat, Netty, Jackson, Log4j versions). " +
        "If yes, returns which Spring Boot parent version to upgrade to instead of bumping " +
        "the dependency directly. " +
        "Input: groupId, artifactId, safeVersion (minimum non-vulnerable version), " +
        "currentParentVersion (optional, current spring-boot version in use). " +
        "Returns JSON with fix_via_parent, bump_parent_to, and a human-readable recommendation.")
    public String resolveBomParent(String groupId, String artifactId,
                                   String safeVersion, String currentParentVersion) {
        if (groupId == null || groupId.isBlank() || artifactId == null || artifactId.isBlank()
                || safeVersion == null || safeVersion.isBlank())
            return "ERROR: groupId, artifactId, and safeVersion are required.";

        String depKey = groupId.strip() + ":" + artifactId.strip();
        int[] safeParts = BomData.parseVersion(safeVersion.strip());

        // Find all Spring Boot versions that ship a version >= safeVersion
        List<String[]> candidates = new ArrayList<>(); // [sbVersion, shippedDepVersion]
        for (Map.Entry<String, Map<String, String>> entry : BomData.SPRING_BOOT_BOM.entrySet()) {
            String shipped = entry.getValue().get(depKey);
            if (shipped == null) continue;
            if (BomData.compareVersions(BomData.parseVersion(shipped), safeParts) >= 0)
                candidates.add(new String[]{entry.getKey(), shipped});
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("dependency", depKey);
        result.put("safe_version_needed", safeVersion);
        result.put("current_parent_version", currentParentVersion == null ? "unknown" : currentParentVersion);

        if (candidates.isEmpty()) {
            result.put("fix_via_parent", false);
            result.put("recommendation",
                depKey + " is not tracked in the Spring Boot BOM for version " + safeVersion + "+. " +
                "Bump " + artifactId + " directly in your build file.");
            return toJson(result);
        }

        // Pick the smallest Spring Boot version that ships the fix
        candidates.sort(Comparator.comparingInt(c -> BomData.parseVersion(c[0]).length == 0 ? 0
            : BomData.parseVersion(c[0])[0] * 10000 +
              (BomData.parseVersion(c[0]).length > 1 ? BomData.parseVersion(c[0])[1] * 100 : 0) +
              (BomData.parseVersion(c[0]).length > 2 ? BomData.parseVersion(c[0])[2] : 0)));
        String[] best = candidates.get(0);
        String bestSbVer = best[0], shippedDepVer = best[1];

        String parentChange = (currentParentVersion != null && !currentParentVersion.isBlank())
            ? "spring-boot " + currentParentVersion + " → " + bestSbVer
            : "spring-boot → " + bestSbVer;

        String recommendation =
            "DO NOT bump " + artifactId + " directly — it is managed by the Spring Boot BOM.\n\n" +
            "FIX: Upgrade " + parentChange + "\n" +
            "     This automatically brings " + artifactId + " " + shippedDepVer +
            " (>= safe version " + safeVersion + ").\n\n" +
            "In pom.xml:     <spring-boot.version>" + bestSbVer + "</spring-boot.version>\n" +
            "In build.gradle: id 'org.springframework.boot' version '" + bestSbVer + "'";

        result.put("fix_via_parent", true);
        result.put("parent_artifact", "org.springframework.boot:spring-boot-starter-parent");
        result.put("bump_parent_to", bestSbVer);
        result.put("parent_ships_version", shippedDepVer);
        result.put("do_not_bump_directly", true);
        result.put("recommendation", recommendation);
        return toJson(result);
    }

    // ── TOOL 6: Search Code Usage ────────────────────────────────────────────

    @Tool(description =
        "Searches Java/Kotlin/Groovy source files in a repository for imports and usage " +
        "of a specific dependency package. " +
        "Input: repoPath — absolute path to the repo; packagePattern — e.g. 'org.apache.logging.log4j'. " +
        "Returns JSON with usage_found flag and list of matching files and lines.")
    public String searchCodeUsage(String repoPath, String packagePattern) {
        repoPath = sanitizePath(repoPath);
        if (packagePattern == null || packagePattern.isBlank())
            return "ERROR: packagePattern is required.";
        Path dir = Path.of(repoPath);
        if (!Files.isDirectory(dir)) return "ERROR: Directory not found: " + repoPath;

        Set<String> skipDirs = Set.of("build", "target", ".gradle", ".mvn", ".git", "node_modules");
        List<String> extensions = List.of(".java", ".kt", ".kts", ".groovy", ".scala");
        List<Map<String, Object>> matches = new ArrayList<>();

        try {
            Files.walk(dir)
                .filter(p -> {
                    for (Path part : p) {
                        if (skipDirs.contains(part.toString())) return false;
                    }
                    return Files.isRegularFile(p) &&
                           extensions.stream().anyMatch(ext -> p.toString().endsWith(ext));
                })
                .forEach(file -> {
                    if (matches.size() >= 50) return;
                    try {
                        List<String> lines = Files.readAllLines(file);
                        for (int i = 0; i < lines.size() && matches.size() < 50; i++) {
                            if (lines.get(i).contains(packagePattern)) {
                                String content = lines.get(i).strip();
                                Map<String, Object> m = new LinkedHashMap<>();
                                m.put("file", dir.relativize(file).toString());
                                m.put("line", i + 1);
                                m.put("content", content.length() > 200 ? content.substring(0, 200) : content);
                                matches.add(m);
                            }
                        }
                    } catch (IOException ignored) {}
                });
        } catch (IOException e) {
            return "ERROR: " + e.getMessage();
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("package", packagePattern);
        if (matches.isEmpty()) {
            result.put("usage_found", false);
            result.put("message", "No usage of '" + packagePattern + "' found in source files. " +
                "The dependency may only be used transitively.");
            result.put("matches", List.of());
        } else {
            result.put("usage_found", true);
            result.put("total_matches", matches.size());
            result.put("matches", matches);
        }
        return toJson(result);
    }

    // ── TOOL 7: Fetch Changelog ──────────────────────────────────────────────

    @Tool(description =
        "Fetches release notes and breaking changes for a dependency upgrade. " +
        "Input: groupId, artifactId, currentVersion, targetVersion. " +
        "Checks GitHub Releases API and Apache changelog pages. " +
        "Returns JSON with breaking_changes list, safe_to_upgrade flag, and confidence_score (0-100).")
    public String fetchChangelog(String groupId, String artifactId,
                                 String currentVersion, String targetVersion) {
        if (groupId == null || artifactId == null || currentVersion == null || targetVersion == null)
            return "ERROR: groupId, artifactId, currentVersion, targetVersion are all required.";

        String githubRepo = BomData.MAVEN_TO_GITHUB.getOrDefault(groupId.strip(), "");

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("artifact", groupId + ":" + artifactId);
        result.put("current_version", currentVersion);
        result.put("target_version", targetVersion);
        result.put("github_repo", githubRepo);
        result.put("release_notes", new ArrayList<>());
        result.put("breaking_changes", new ArrayList<>());
        result.put("safe_to_upgrade", true);
        result.put("confidence", "low");
        result.put("confidence_score", 30);

        List<Map<String, Object>> releaseNotes = (List<Map<String, Object>>) result.get("release_notes");
        List<String> breakingChanges = (List<String>) result.get("breaking_changes");

        // 1. Try GitHub releases
        if (!githubRepo.isEmpty()) {
            try {
                fetchGithubReleases(githubRepo, currentVersion, targetVersion, releaseNotes, breakingChanges);
            } catch (Exception ignored) {}
        }

        // 2. Apache HTML changelog fallback
        if (releaseNotes.isEmpty() && BomData.APACHE_CHANGELOG_URLS.containsKey(groupId)) {
            try {
                fetchApacheChangelog(groupId, currentVersion, targetVersion, releaseNotes, breakingChanges);
            } catch (Exception ignored) {}
        }

        // Set confidence based on findings
        if (!breakingChanges.isEmpty()) {
            result.put("safe_to_upgrade", false);
            result.put("confidence", "high");
            result.put("confidence_score", 85);
        } else if (!releaseNotes.isEmpty()) {
            result.put("confidence", "high");
            result.put("confidence_score", 95);
        }
        return toJson(result);
    }

    private void fetchGithubReleases(String repo, String current, String target,
                                     List<Map<String, Object>> notes, List<String> breaking) throws Exception {
        String url = "https://api.github.com/repos/" + repo + "/releases?per_page=50";
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Accept", "application/vnd.github.v3+json");
        if (githubToken != null && !githubToken.isBlank())
            headers.put("Authorization", "token " + githubToken);

        RestClient.RequestHeadersSpec<?> req = http.get().uri(url);
        for (Map.Entry<String, String> h : headers.entrySet())
            req = ((RestClient.RequestHeadersUriSpec<?>) req).header(h.getKey(), h.getValue());

        String resp = req.retrieve().body(String.class);
        List<Map<String, Object>> releases = om.readValue(resp, List.class);

        int[] currentParts = BomData.parseVersion(current);
        int[] targetParts = BomData.parseVersion(target);
        List<String> breakingKeywords = List.of("breaking", "removed", "incompatible", "no longer", "deprecated and removed");

        for (Map<String, Object> release : releases) {
            String tag = str(release, "tag_name").replaceAll("^v", "");
            int[] tagParts = BomData.parseVersion(tag);
            if (BomData.compareVersions(tagParts, currentParts) <= 0) continue;
            if (BomData.compareVersions(tagParts, targetParts) > 0) continue;

            String body = str(release, "body");
            if (body.isEmpty()) continue;

            Map<String, Object> note = new LinkedHashMap<>();
            note.put("version", tag);
            note.put("tag", str(release, "tag_name"));
            note.put("highlights", body.length() > 2000 ? body.substring(0, 2000) : body);
            notes.add(note);

            String lower = body.toLowerCase();
            for (String kw : breakingKeywords) {
                if (lower.contains(kw)) {
                    breaking.add("Breaking change keyword '" + kw + "' found in " + tag + " release notes.");
                    break;
                }
            }
        }
    }

    private void fetchApacheChangelog(String groupId, String current, String target,
                                      List<Map<String, Object>> notes, List<String> breaking) throws Exception {
        String urlTemplate = BomData.APACHE_CHANGELOG_URLS.get(groupId);
        if (urlTemplate == null) return;
        String major = target.contains(".") ? target.split("\\.")[0] : "10";
        String url = urlTemplate.replace("{major}", major);
        String html = http.get().uri(url).retrieve().body(String.class);
        if (html == null) return;
        String text = html.replaceAll("<[^>]+>", " ").replaceAll("\\s+", " ");

        int[] currentParts = BomData.parseVersion(current);
        int[] targetParts = BomData.parseVersion(target);
        List<String> relevant = new ArrayList<>();
        Matcher m = Pattern.compile("(\\d+\\.\\d+\\.\\d+(?:\\.\\d+)?)\\s+([\\w\\s,]+?\\d{4})").matcher(text);
        while (m.find()) {
            int[] vp = BomData.parseVersion(m.group(1));
            if (BomData.compareVersions(vp, currentParts) > 0 && BomData.compareVersions(vp, targetParts) <= 0) {
                int start = Math.max(0, m.start() - 100), end = Math.min(text.length(), m.end() + 500);
                relevant.add(text.substring(start, end).strip());
            }
        }
        if (!relevant.isEmpty()) {
            String combined = String.join("\n\n", relevant);
            Map<String, Object> note = new LinkedHashMap<>();
            note.put("version", current + " -> " + target);
            note.put("tag", "apache-changelog:" + major + ".x");
            note.put("highlights", combined.length() > 3000 ? combined.substring(0, 3000) : combined);
            notes.add(note);
            String lower = combined.toLowerCase();
            for (String kw : List.of("breaking", "removed", "incompatible", "no longer")) {
                if (lower.contains(kw)) {
                    breaking.add("Apache changelog mentions '" + kw + "' between " + current + " and " + target);
                    break;
                }
            }
        }
    }

    // ── TOOL 8: Read Project Docs ────────────────────────────────────────────

    @Tool(description =
        "Reads project documentation (README, CHANGELOG, CONTRIBUTING) from a repository " +
        "to find any information about dependency requirements or upgrade notes. " +
        "Input: repoPath — absolute path to the repository root. " +
        "Returns up to 4000 characters of found documentation.")
    public String readProjectDocs(String repoPath) {
        repoPath = sanitizePath(repoPath);
        Path dir = Path.of(repoPath);
        if (!Files.isDirectory(dir)) return "ERROR: Directory not found: " + repoPath;

        List<String> docFiles = List.of("README.md", "README.adoc", "README.txt", "README",
            "CHANGELOG.md", "CHANGELOG", "CONTRIBUTING.md");
        StringBuilder sb = new StringBuilder();
        for (String name : docFiles) {
            Path p = dir.resolve(name);
            if (!Files.exists(p)) continue;
            try {
                String content = Files.readString(p);
                sb.append("=== ").append(name).append(" ===\n");
                sb.append(content, 0, Math.min(2000, content.length()));
                sb.append("\n\n");
                if (sb.length() > 4000) break;
            } catch (IOException ignored) {}
        }
        return sb.isEmpty() ? "No documentation files found." : sb.toString();
    }

    // ── Public helpers used by ScanOrchestrationService ─────────────────────

    /** Run a tool directly (without AI) — for the deterministic pipeline. */
    public String detectBuildSystemDirect(Path dir) { return detectBuildSystem(dir.toString()); }

    public String extractDependenciesDirect(Path dir, String buildSystem) {
        return extractDependencies(dir.toString(), buildSystem);
    }

    public String checkOsvVulnerabilitiesDirect(String json) { return checkOsvVulnerabilities(json); }

    public String lookupLatestSafeVersionDirect(String g, String a, String cur, String fixed) {
        return lookupLatestSafeVersion(g, a, cur, fixed);
    }

    public String resolveBomParentDirect(String g, String a, String safe, String parent) {
        return resolveBomParent(g, a, safe, parent);
    }

    public String fetchChangelogDirect(String g, String a, String cur, String target) {
        return fetchChangelog(g, a, cur, target);
    }

    public String searchCodeUsageDirect(String repoPath, String pkg) {
        return searchCodeUsage(repoPath, pkg);
    }

    // ── Private utilities ────────────────────────────────────────────────────

    private String runProcess(Path dir, List<String> cmd, int timeoutSec) throws Exception {
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.directory(dir.toFile());
        pb.redirectErrorStream(true);
        Process p = pb.start();
        StringBuilder sb = new StringBuilder();
        try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
            String line;
            while ((line = r.readLine()) != null) sb.append(line).append("\n");
        }
        p.waitFor(timeoutSec, TimeUnit.SECONDS);
        return p.exitValue() == 0 ? sb.toString() : null;
    }

    private String extractTag(String xml, String tag) {
        Matcher m = Pattern.compile("<" + tag + "[^>]*>([^<]+)</" + tag + ">").matcher(xml);
        return m.find() ? m.group(1).strip() : "";
    }

    private static String sanitizePath(String path) {
        if (path == null) return "";
        return path.strip().replaceAll("['\"]", "");
    }

    private static String str(Map<?, ?> map, String key) {
        Object v = map.get(key);
        return v == null ? "" : v.toString();
    }

    private String toJson(Object obj) {
        try { return om.writeValueAsString(obj); }
        catch (Exception e) { return "{}"; }
    }

    private static String cvssVectorToSeverity(String vector) {
        if (vector == null || !vector.contains(":")) return "UNKNOWN";
        Map<String, String> parts = new HashMap<>();
        for (String seg : vector.split("/")) {
            String[] kv = seg.split(":");
            if (kv.length == 2) parts.put(kv[0], kv[1]);
        }
        Map<String, Integer> w = Map.of("H", 3, "L", 1, "N", 0);
        int impact = Stream.of("C","I","A").mapToInt(k -> w.getOrDefault(parts.getOrDefault(k,"N"),0)).sum();
        String av = parts.getOrDefault("AV","N"), pr = parts.getOrDefault("PR","N");
        if (impact >= 7 && "N".equals(av) && ("N".equals(pr)||"L".equals(pr))) return "CRITICAL";
        if (impact >= 5 && "N".equals(av)) return "HIGH";
        if (impact >= 3) return "MEDIUM";
        if (impact >= 1) return "LOW";
        return "UNKNOWN";
    }
}
