package com.ravi.vul.vulscannerspring.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ravi.vul.vulscannerspring.tools.BomData;
import com.ravi.vul.vulscannerspring.tools.VulnHawkTools;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.regex.*;
import java.util.stream.*;

/**
 * VulnHawk scan orchestration — 4-agent pipeline implemented with Spring AI.
 *
 * Pipeline:
 *   Agent 1 (Repo Scanner)       → detect build system + extract full dep tree
 *   Agent 2 (Vuln Analyst)       → check all deps against OSV database
 *   Agent 3 (Upgrade Strategist) → BOM check + safe version lookup + changelog
 *   Agent 4 (Report Generator)   → structured Markdown report
 *
 * Each agent is a ChatClient.prompt() call with a role-specific system prompt
 * and the relevant @Tool-annotated methods from VulnHawkTools.
 * If LLM tool-calling fails, a deterministic fallback report is generated directly.
 */
@Service
public class ScanOrchestrationService {

    private static final Logger log = LoggerFactory.getLogger(ScanOrchestrationService.class);

    private final ChatClient chatClient;
    private final VulnHawkTools tools;
    private final ObjectMapper om = new ObjectMapper();

    @Value("${vulnhawk.llm.vendor:ollama}")
    private String llmVendor;

    // ── System prompts (translated from Python agents.py) ───────────────────

    private static final String REPO_SCANNER_SYSTEM = """
        You are an expert in Java/JVM build systems with deep knowledge of Maven and Gradle.
        Your role is: Repository Build System Analyst.

        GOAL: Analyze a Java/Kotlin repository to detect its build system (Maven or Gradle) and
        extract the COMPLETE dependency tree — including ALL transitive dependencies, not just the
        ones declared directly in the build file.
        Each dependency must include: group_id, artifact_id, version, scope, and depth
        (0 = direct dependency, 1+ = transitive).

        INSTRUCTIONS:
        1. Call detectBuildSystem with the repo path to determine if it uses Maven or Gradle.
        2. Call extractDependencies with the repo path and detected build system.
        3. Return the JSON dependency list exactly as returned by the tool.

        You MUST call both tools. Return the raw JSON dependency array as your final response.
        If a tool returns an ERROR, include it in your response so downstream agents can handle it.
        """;

    private static final String VULN_ANALYST_SYSTEM = """
        You are a cybersecurity specialist focused on software supply chain security.
        Your role is: Vulnerability Security Analyst.

        GOAL: Check EVERY dependency against the OSV (Open Source Vulnerabilities) database.
        Most exploited vulnerabilities enter projects as TRANSITIVE dependencies — Log4Shell
        (Log4j) being the prime example.

        INSTRUCTIONS:
        1. Call checkOsvVulnerabilities with the full JSON dependency list provided.
        2. Return the complete OSV vulnerability report JSON as your response.

        You MUST call the checkOsvVulnerabilities tool. Return the raw JSON report.
        """;

    private static final String UPGRADE_STRATEGIST_SYSTEM = """
        You are a senior software engineer specializing in dependency management and security remediation.
        Your role is: Dependency Upgrade Strategist.

        GOAL: For each vulnerable dependency in the vulnerability report, determine the correct fix strategy.

        STEP 1 — BOM CHECK (ALWAYS do this first):
          Call resolveBomParent to check if the dep is managed by Spring Boot BOM.
          If yes, recommend bumping the PARENT (spring-boot version), NOT the dep directly.

        STEP 2 — VERSION LOOKUP:
          Call lookupLatestSafeVersion to find the minimum non-vulnerable version on Maven Central.

        STEP 3 — CHANGELOG REVIEW:
          Call fetchChangelog to get release notes between current and target version.

        STEP 4 — CODE IMPACT:
          Call searchCodeUsage to find how the dependency is used in source code.

        For each vulnerable dependency, produce a structured upgrade recommendation including:
        - fix_via_parent flag and which parent to bump (if BOM-managed)
        - target version
        - breaking changes found
        - confidence score
        - exact pom.xml / build.gradle change needed

        Return your analysis as structured text that can be used to generate the final report.
        """;

    private static final String REPORT_GENERATOR_SYSTEM = """
        You are a technical writer specializing in security vulnerability reports.
        Your role is: Security Report Generator.

        GOAL: Generate a comprehensive, actionable vulnerability report in clean Markdown.

        The report MUST contain these sections (use ## headings):
        ## 1. Executive Summary
        ## 2. Build System
        ## 3. Scan Statistics
          - Total Dependencies Checked: N
          - Vulnerable Count: N
          - Safe Count: N
        ## 4. Critical & High Vulnerabilities
          (table: Dependency | Vuln ID | Severity | Summary | Fix Version)
        ## 5. Medium & Low Vulnerabilities
          (table: Dependency | Vuln ID | Severity | Summary | Fix Version)
        ## 6. Upgrade Plan
          (table: Dependency | Upgrade | Reason | Fix Version)
        ## 7. Compatibility Analysis
          (table: Dependency | Upgrade | Breaking Changes | Project Affected | Safe to Upgrade)
        ## 8. Compatibility Warnings
        ## 9. Next Steps
        ## 10. All Dependencies
          (table: Dependency | Type | Scope | Status | Vulnerabilities)

        For BOM-managed dependencies (Tomcat, Jackson, Netty in Spring Boot projects):
        CLEARLY indicate that they must be upgraded via the parent BOM, not directly.

        Include the exact pom.xml or build.gradle line to change for each fix.
        Use YES/NO in the "Safe to Upgrade" column.

        At the very end include this line (with the actual list from the vulnerability data):
        Dependency Allowlist: ["group:artifact:version", ...]
        """;

    public ScanOrchestrationService(ChatClient chatClient, VulnHawkTools tools) {
        this.chatClient = chatClient;
        this.tools = tools;
    }

    // ── Public API ───────────────────────────────────────────────────────────

    /**
     * Run a full scan from a GitHub URL (clone + 4-agent pipeline).
     */
    public String scanFromUrl(String githubUrl) throws Exception {
        Path tmpDir = cloneRepo(githubUrl);
        try {
            return runPipeline(tmpDir.toString(), "url", githubUrl);
        } finally {
            deleteTempDir(tmpDir);
        }
    }

    /**
     * Run a scan from a raw dependency list (group:artifact:version per line).
     * Skips Agent 1 — dep extraction is done directly from the input.
     */
    public String scanFromDepList(String depInput) throws Exception {
        List<Map<String, Object>> deps = parseDepList(depInput);
        if (deps.isEmpty()) throw new IllegalArgumentException("No valid dependencies in input.");
        return runPipelineFromDeps(deps, null);
    }

    // ── Pipeline ─────────────────────────────────────────────────────────────

    private String runPipeline(String repoPath, String inputType, String source) throws Exception {
        log.info("Starting 4-agent scan pipeline for: {}", source);

        // ── Agent 1: Repo Scanner ──────────────────────────────────────────
        log.info("Agent 1: Repo Scanner");
        String depsJson;
        String buildSystem = "unknown";
        try {
            String agent1Result = chatClient.prompt()
                .system(REPO_SCANNER_SYSTEM)
                .user("Repository path: " + repoPath +
                      "\n\nScan this repository. Call detectBuildSystem then extractDependencies. " +
                      "Return the full JSON dependency array.")
                .tools(tools)
                .call()
                .content();
            depsJson = extractJson(agent1Result);
            // Also detect build system directly for the report
            buildSystem = tools.detectBuildSystemDirect(Path.of(repoPath));
        } catch (Exception e) {
            log.warn("Agent 1 (AI) failed, using direct tool calls: {}", e.getMessage());
            buildSystem = tools.detectBuildSystemDirect(Path.of(repoPath));
            depsJson = tools.extractDependenciesDirect(Path.of(repoPath), buildSystem);
        }

        return runPipelineFromDeps(parseJsonList(depsJson), repoPath);
    }

    private String runPipelineFromDeps(List<Map<String, Object>> deps, String repoPath) throws Exception {
        String depsJson = om.writeValueAsString(deps);

        // ── Agent 2: Vulnerability Analyst ────────────────────────────────
        log.info("Agent 2: Vulnerability Analyst — checking {} dependencies", deps.size());
        String vulnJson;
        try {
            String agent2Result = chatClient.prompt()
                .system(VULN_ANALYST_SYSTEM)
                .user("Check ALL of these dependencies against the OSV database:\n\n" + depsJson +
                      "\n\nCall checkOsvVulnerabilities with this JSON. Return the raw vulnerability report JSON.")
                .tools(tools)
                .call()
                .content();
            vulnJson = extractJson(agent2Result);
            // Validate it's a proper vuln report
            Map<String, Object> check = om.readValue(vulnJson, Map.class);
            if (!check.containsKey("vulnerabilities")) throw new RuntimeException("Invalid vuln report");
        } catch (Exception e) {
            log.warn("Agent 2 (AI) failed, using direct OSV check: {}", e.getMessage());
            vulnJson = tools.checkOsvVulnerabilitiesDirect(depsJson);
        }

        // ── Agent 3: Upgrade Strategist ────────────────────────────────────
        log.info("Agent 3: Upgrade Strategist");
        String upgradeAnalysis;
        try {
            String repoNote = repoPath != null
                ? "\nRepository path for code search: " + repoPath : "";
            String agent3Result = chatClient.prompt()
                .system(UPGRADE_STRATEGIST_SYSTEM)
                .user("Vulnerability Report:\n" + vulnJson + repoNote +
                      "\n\nFor each vulnerable dependency: call resolveBomParent, " +
                      "lookupLatestSafeVersion, fetchChangelog, and searchCodeUsage. " +
                      "Provide a structured upgrade recommendation.")
                .tools(tools)
                .call()
                .content();
            upgradeAnalysis = agent3Result;
        } catch (Exception e) {
            log.warn("Agent 3 (AI) failed, building deterministic upgrade analysis: {}", e.getMessage());
            upgradeAnalysis = buildDeterministicUpgradeAnalysis(vulnJson, repoPath);
        }

        // ── Agent 4: Report Generator ──────────────────────────────────────
        log.info("Agent 4: Report Generator");
        String report;
        try {
            String agent4Result = chatClient.prompt()
                .system(REPORT_GENERATOR_SYSTEM)
                .user("Full dependency list (JSON):\n" + depsJson +
                      "\n\nVulnerability Report (JSON):\n" + vulnJson +
                      "\n\nUpgrade Analysis:\n" + upgradeAnalysis +
                      "\n\nGenerate the complete vulnerability report in Markdown format.")
                .call()
                .content();
            report = cleanReport(agent4Result);
            // Validate report has required sections
            if (!report.contains("Vulnerable Count") || !report.contains("Dependency Allowlist")) {
                throw new RuntimeException("Report missing required sections");
            }
        } catch (Exception e) {
            log.warn("Agent 4 (AI) failed, using deterministic report: {}", e.getMessage());
            report = buildFallbackReport(depsJson, vulnJson, repoPath);
        }

        return report;
    }

    // ── Deterministic fallback (no LLM needed) ───────────────────────────────

    private String buildDeterministicUpgradeAnalysis(String vulnJson, String repoPath) {
        try {
            Map<String, Object> report = om.readValue(vulnJson, Map.class);
            List<Map<String, Object>> vulns = (List<Map<String, Object>>) report.getOrDefault("vulnerabilities", List.of());
            StringBuilder sb = new StringBuilder("## Upgrade Analysis\n\n");
            for (Map<String, Object> item : vulns) {
                String dep = str(item, "dependency");
                String[] parts = dep.split(":");
                if (parts.length < 3) continue;
                String g = parts[0], a = parts[1], v = parts[2];

                // BOM check
                String bomResult = tools.resolveBomParentDirect(g, a, "", "");
                sb.append("### ").append(dep).append("\n");
                sb.append(bomResult).append("\n");

                // Version lookup
                List<Object> details = (List<Object>) item.getOrDefault("details", List.of());
                List<String> fixed = details.stream()
                    .flatMap(d -> ((List<Object>) ((Map<String,Object>) d).getOrDefault("fixed_versions", List.of())).stream())
                    .map(Object::toString).collect(Collectors.toList());
                String fixedCsv = String.join(",", fixed);
                String versionResult = tools.lookupLatestSafeVersionDirect(g, a, v, fixedCsv);
                sb.append(versionResult).append("\n");

                // Changelog
                try {
                    Map<String, Object> vm = om.readValue(versionResult, Map.class);
                    String target = str(vm, "recommended_upgrade");
                    if (!target.isEmpty()) {
                        sb.append(tools.fetchChangelogDirect(g, a, v, target)).append("\n");
                    }
                } catch (Exception ignored) {}

                // Code usage
                if (repoPath != null) {
                    sb.append(tools.searchCodeUsageDirect(repoPath, g)).append("\n");
                }
                sb.append("\n");
            }
            return sb.toString();
        } catch (Exception e) {
            return "Upgrade analysis unavailable: " + e.getMessage();
        }
    }

    /**
     * Fully deterministic Markdown report — no LLM required.
     * Mirrors Python's _build_fallback_report().
     */
    public String buildFallbackReport(String depsJson, String vulnJson, String repoPath) {
        try {
            List<Map<String, Object>> allDeps = parseJsonList(depsJson);
            Map<String, Object> vulnReport = om.readValue(vulnJson, Map.class);
            List<Map<String, Object>> vulns = (List<Map<String, Object>>) vulnReport.getOrDefault("vulnerabilities", List.of());
            int totalChecked = intVal(vulnReport, "total_dependencies_checked");
            int vulnCount = intVal(vulnReport, "vulnerable_count");
            int safeCount = intVal(vulnReport, "safe_count");

            // Build vulnerability tables
            List<String> critHighRows = new ArrayList<>(), medLowRows = new ArrayList<>();
            List<String> upgradeRows = new ArrayList<>(), compatRows = new ArrayList<>();
            List<String> allowlist = new ArrayList<>();

            for (Map<String, Object> item : vulns) {
                String dep = str(item, "dependency");
                String[] parts = dep.split(":");
                if (parts.length < 3) continue;
                String g = parts[0], a = parts[1], v = parts[2];
                allowlist.add(dep);
                List<Map<String, Object>> details = (List<Map<String, Object>>) item.getOrDefault("details", List.of());
                Map<String, Map<String, Object>> detailMap = new LinkedHashMap<>();
                for (Map<String, Object> d : details) detailMap.put(str(d, "id"), d);

                for (Object vidObj : (List<?>) item.getOrDefault("vulnerability_ids", List.of())) {
                    String vid = vidObj.toString();
                    Map<String, Object> det = detailMap.getOrDefault(vid, Map.of());
                    String sev = str(det, "severity").isEmpty() ? "UNKNOWN" : str(det, "severity");
                    String summary = truncate(str(det, "summary"), 120);
                    String fixVer = minFix((List<String>) det.getOrDefault("fixed_versions", List.of()));
                    String row = "| " + dep + " | " + vid + " | " + sev + " | " + summary + " | " + fixVer + " |";
                    if ("CRITICAL".equals(sev) || "HIGH".equals(sev)) critHighRows.add(row);
                    else medLowRows.add(row);
                }

                // Upgrade + compat rows
                List<String> fixed = details.stream()
                    .flatMap(d -> ((List<Object>) d.getOrDefault("fixed_versions", List.of())).stream()
                        .map(Object::toString)).distinct().collect(Collectors.toList());
                String fixedCsv = String.join(",", fixed);
                String targetVer = v;
                try {
                    String lvResp = tools.lookupLatestSafeVersionDirect(g, a, v, fixedCsv);
                    Map<String, Object> lv = om.readValue(lvResp, Map.class);
                    if (lv.get("recommended_upgrade") != null) targetVer = str(lv, "recommended_upgrade");
                } catch (Exception ignored) {}

                // Check BOM
                String bomNote = "";
                boolean fixViaParent = false;
                try {
                    String bomResp = tools.resolveBomParentDirect(g, a, targetVer, "");
                    Map<String, Object> bom = om.readValue(bomResp, Map.class);
                    if (Boolean.TRUE.equals(bom.get("fix_via_parent"))) {
                        fixViaParent = true;
                        bomNote = " (BOM: bump spring-boot to " + str(bom, "bump_parent_to") + ")";
                    }
                } catch (Exception ignored) {}

                String upgrade = v + " -> " + targetVer;
                String reason = fixViaParent
                    ? "Managed by Spring Boot BOM" + bomNote
                    : "Latest safe release" + (fixed.contains(targetVer) ? " (known fixed version)" : "");
                upgradeRows.add("| " + dep + " | " + upgrade + " | " + reason + " | " + minFix(fixed) + " |");

                // Changelog / compat
                String breaking = "None noted";
                String safeToUpgrade = "YES";
                try {
                    String clResp = tools.fetchChangelogDirect(g, a, v, targetVer);
                    Map<String, Object> cl = om.readValue(clResp, Map.class);
                    List<String> bc = (List<String>) cl.getOrDefault("breaking_changes", List.of());
                    if (!bc.isEmpty()) { breaking = truncate(bc.get(0), 80); safeToUpgrade = "NO"; }
                } catch (Exception ignored) {}

                String affected = "UNKNOWN";
                if (repoPath != null) {
                    try {
                        String uResp = tools.searchCodeUsageDirect(repoPath, g);
                        Map<String, Object> u = om.readValue(uResp, Map.class);
                        affected = Boolean.TRUE.equals(u.get("usage_found")) ? "YES" : "NO";
                    } catch (Exception ignored) {}
                }
                compatRows.add("| " + dep + " | " + upgrade + " | " + breaking + " | " + affected + " | " + safeToUpgrade + " |");
            }

            // All dependencies overview
            List<String> depRows = new ArrayList<>();
            Map<String, List<String>> vulnDepMap = new LinkedHashMap<>();
            for (Map<String, Object> item : vulns) {
                String dep = str(item, "dependency");
                List<String> ids = ((List<Object>) item.getOrDefault("vulnerability_ids", List.of()))
                    .stream().map(Object::toString).collect(Collectors.toList());
                vulnDepMap.put(dep, ids);
            }
            for (Map<String, Object> dep : allDeps) {
                String g = str(dep, "group_id"), a = str(dep, "artifact_id"), v = str(dep, "version");
                String scope = str(dep, "scope");
                int depth = dep.get("depth") instanceof Number ? ((Number) dep.get("depth")).intValue() : 0;
                String coord = g + ":" + a + ":" + v;
                String kind = depth == 0 ? "Direct" : "Transitive (d" + depth + ")";
                List<String> ids = vulnDepMap.get(coord);
                String status = (ids != null && !ids.isEmpty()) ? "VULNERABLE" : "SAFE";
                String vulnStr = (ids != null && !ids.isEmpty()) ? String.join(", ", ids.subList(0, Math.min(2, ids.size()))) : "—";
                depRows.add("| " + coord + " | " + kind + " | " + scope + " | " + status + " | " + vulnStr + " |");
            }

            // Build the report
            StringBuilder sb = new StringBuilder();
            sb.append("# Security Vulnerability Report\n\n");
            sb.append("## 1. Executive Summary\n");
            sb.append("The security scan identified **").append(vulnCount).append("** vulnerabilities ");
            sb.append("across **").append(totalChecked).append("** dependencies.\n\n");
            sb.append("## 2. Build System\n");
            sb.append("Detected from project structure.\n\n");
            sb.append("## 3. Scan Statistics\n");
            sb.append("- Total Dependencies Checked: ").append(totalChecked).append("\n");
            sb.append("- Vulnerable Count: ").append(vulnCount).append("\n");
            sb.append("- Safe Count: ").append(safeCount).append("\n\n");
            sb.append("## 4. Critical & High Vulnerabilities\n");
            sb.append("| Dependency | Vuln ID | Severity | Summary | Fix Version |\n");
            sb.append("| --- | --- | --- | --- | --- |\n");
            critHighRows.forEach(r -> sb.append(r).append("\n"));
            sb.append("\n## 5. Medium & Low Vulnerabilities\n");
            sb.append("| Dependency | Vuln ID | Severity | Summary | Fix Version |\n");
            sb.append("| --- | --- | --- | --- | --- |\n");
            medLowRows.forEach(r -> sb.append(r).append("\n"));
            sb.append("\n## 6. Upgrade Plan\n");
            sb.append("| Dependency | Upgrade | Reason | Fix Version |\n");
            sb.append("| --- | --- | --- | --- |\n");
            upgradeRows.forEach(r -> sb.append(r).append("\n"));
            sb.append("\n## 7. Compatibility Analysis\n");
            sb.append("| Dependency | Upgrade | Breaking Changes | Project Affected | Safe to Upgrade |\n");
            sb.append("| --- | --- | --- | --- | --- |\n");
            compatRows.forEach(r -> sb.append(r).append("\n"));
            sb.append("\n## 8. Compatibility Warnings\n");
            sb.append(compatRows.isEmpty() ? "None." : "Review breaking changes before upgrading.");
            sb.append("\n\n## 9. Next Steps\n");
            sb.append("- Apply recommended upgrades and run the full test suite.\n");
            sb.append("- Review breaking changes and update configuration as needed.\n");
            if (!depRows.isEmpty()) {
                sb.append("\n## 10. All Dependencies\n");
                sb.append("| Dependency | Type | Scope | Status | Vulnerabilities |\n");
                sb.append("| --- | --- | --- | --- | --- |\n");
                depRows.forEach(r -> sb.append(r).append("\n"));
            }
            sb.append("\nDependency Allowlist: ").append(om.writeValueAsString(allowlist)).append("\n");
            return sb.toString();
        } catch (Exception e) {
            log.error("Fallback report generation failed", e);
            return "# Scan Error\n\nFailed to generate report: " + e.getMessage();
        }
    }

    // ── Utility ──────────────────────────────────────────────────────────────

    private Path cloneRepo(String githubUrl) throws Exception {
        if (!githubUrl.matches("https?://github\\.com/.*"))
            throw new IllegalArgumentException("Invalid GitHub URL: " + githubUrl);
        Path tmpDir = Files.createTempDirectory("vulnhawk_");
        ProcessBuilder pb = new ProcessBuilder("git", "clone", "--depth", "1", githubUrl, tmpDir.toString());
        pb.redirectErrorStream(true);
        Process p = pb.start();
        String output = new String(p.getInputStream().readAllBytes());
        boolean finished = p.waitFor(120, TimeUnit.SECONDS);
        if (!finished || p.exitValue() != 0) {
            deleteTempDir(tmpDir);
            throw new IOException("git clone failed: " + output);
        }
        return tmpDir;
    }

    private void deleteTempDir(Path dir) {
        try {
            Files.walk(dir).sorted(Comparator.reverseOrder()).forEach(p -> {
                try { Files.delete(p); } catch (IOException ignored) {}
            });
        } catch (IOException ignored) {}
    }

    private List<Map<String, Object>> parseDepList(String input) {
        List<Map<String, Object>> deps = new ArrayList<>();
        for (String line : input.lines().map(String::strip).toList()) {
            if (line.isEmpty() || line.startsWith("#")) continue;
            String[] parts = line.split(":");
            if (parts.length < 3) continue;
            Map<String, Object> dep = new LinkedHashMap<>();
            dep.put("group_id", parts[0].strip());
            dep.put("artifact_id", parts[1].strip());
            dep.put("version", parts[2].strip());
            dep.put("scope", "compile");
            dep.put("depth", 0);
            deps.add(dep);
        }
        return deps;
    }

    private List<Map<String, Object>> parseJsonList(String json) {
        if (json == null || json.isBlank()) return List.of();
        try {
            // Find the JSON array inside the string (agent may include prose)
            int start = json.indexOf('[');
            int end = json.lastIndexOf(']');
            if (start < 0 || end < start) return List.of();
            return om.readValue(json.substring(start, end + 1), List.class);
        } catch (Exception e) {
            return List.of();
        }
    }

    private String extractJson(String text) {
        if (text == null) return "[]";
        // Try JSON array first
        int start = text.indexOf('[');
        int end = text.lastIndexOf(']');
        if (start >= 0 && end > start) return text.substring(start, end + 1);
        // Try JSON object
        start = text.indexOf('{');
        end = text.lastIndexOf('}');
        if (start >= 0 && end > start) return text.substring(start, end + 1);
        return text;
    }

    private static String cleanReport(String text) {
        if (text == null) return "";
        // Strip <think>...</think> blocks (Gemini, DeepSeek)
        text = text.replaceAll("(?s)<think>.*?</think>", "");
        text = text.replaceAll("(?s)<think>.*$", "");
        text = text.strip();
        // Strip fenced markdown code block wrapper
        text = text.replaceAll("^```(?:markdown)?\\s*\n", "");
        text = text.replaceAll("\n```\\s*$", "");
        return text;
    }

    private static String truncate(String text, int limit) {
        if (text == null || text.length() <= limit) return text == null ? "" : text;
        int idx = text.lastIndexOf(". ", limit);
        if (idx > limit / 2) return text.substring(0, idx + 1);
        idx = text.lastIndexOf(" ", limit);
        return (idx > 0 ? text.substring(0, idx) : text.substring(0, limit)) + "…";
    }

    private static String minFix(List<String> versions) {
        if (versions == null || versions.isEmpty()) return "—";
        return versions.stream()
            .min(Comparator.comparingInt(v -> {
                int[] p = BomData.parseVersion(v);
                return p.length > 0 ? p[0] * 1000000 + (p.length > 1 ? p[1] * 1000 : 0) + (p.length > 2 ? p[2] : 0) : 0;
            }))
            .orElse("—");
    }

    private static String str(Map<?, ?> map, String key) {
        Object v = map.get(key); return v == null ? "" : v.toString();
    }

    private static int intVal(Map<?, ?> map, String key) {
        Object v = map.get(key); return v instanceof Number n ? n.intValue() : 0;
    }
}
