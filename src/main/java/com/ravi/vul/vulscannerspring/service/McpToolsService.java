package com.ravi.vul.vulscannerspring.service;

import com.ravi.vul.vulscannerspring.model.HistoryItem;
import com.ravi.vul.vulscannerspring.tools.VulnHawkTools;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.ai.tool.annotation.ToolParam;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * MCP tool definitions for VulnHawk.
 * Exposed via spring-ai-starter-mcp-server-webmvc at /mcp/sse.
 * Compatible with Claude Code, Cursor, Claude Desktop, VS Code.
 */
@Service
public class McpToolsService {

    private static final Logger log = LoggerFactory.getLogger(McpToolsService.class);

    private final ScanOrchestrationService orchestration;
    private final ScanHistoryService history;
    private final VulnHawkTools tools;

    public McpToolsService(@Lazy ScanOrchestrationService orchestration,
                           ScanHistoryService history,
                           VulnHawkTools tools) {
        this.orchestration = orchestration;
        this.history = history;
        this.tools = tools;
    }

    // ── Tool 1: Scan a GitHub repository ─────────────────────────────────────

    @Tool(description = """
            Scan a GitHub repository for vulnerable Java/Kotlin dependencies.
            Runs a full 4-agent AI pipeline: detects build system (Maven/Gradle),
            extracts all dependencies, checks OSV database for CVEs, finds safe
            upgrade versions, and generates a structured Markdown security report.
            Use this when the user wants to scan a GitHub project for security issues.
            Returns the full Markdown vulnerability report.
            """)
    public String scan_repository(
            @ToolParam(description = "GitHub repository URL, e.g. https://github.com/org/repo")
            String github_url) {
        log.info("[MCP] scan_repository: {}", github_url);
        try {
            String[] keyName = ScanHistoryService.scanKeyForUrl(github_url);
            String report = orchestration.scanFromUrl(github_url);
            history.save(keyName[0], keyName[1], "url", "", report);
            return report;
        } catch (Exception e) {
            log.error("[MCP] scan_repository failed", e);
            return "Scan failed: " + e.getMessage();
        }
    }

    // ── Tool 2: Scan a raw dependency list ───────────────────────────────────

    @Tool(description = """
            Scan a list of Maven/Gradle dependencies for known vulnerabilities.
            Each dependency must be on its own line in format: groupId:artifactId:version
            Example input:
              org.springframework:spring-core:5.3.0
              log4j:log4j:1.2.17
              com.fasterxml.jackson.core:jackson-databind:2.9.0
            Returns a full Markdown vulnerability report with CVE details and upgrade paths.
            """)
    public String scan_dependencies(
            @ToolParam(description = "Newline-separated list of group:artifact:version dependencies")
            String dependencies) {
        log.info("[MCP] scan_dependencies ({} chars)", dependencies.length());
        try {
            String[] keyName = ScanHistoryService.scanKeyForDeps(dependencies);
            String report = orchestration.scanFromDepList(dependencies);
            history.save(keyName[0], keyName[1], "dep-list", "", report);
            return report;
        } catch (Exception e) {
            log.error("[MCP] scan_dependencies failed", e);
            return "Scan failed: " + e.getMessage();
        }
    }

    // ── Tool 3: Get a past scan report by ID ─────────────────────────────────

    @Tool(description = """
            Retrieve a specific vulnerability scan report by its numeric ID.
            Use list_scan_history first to find available scan IDs.
            Returns the full Markdown report for that scan.
            """)
    public String get_vulnerability_report(
            @ToolParam(description = "Numeric scan ID (from list_scan_history)")
            long id) {
        log.info("[MCP] get_vulnerability_report: id={}", id);
        Optional<HistoryItem> item = history.findById(id);
        if (item.isEmpty()) return "No report found for id: " + id;
        return item.get().getReportMd();
    }

    // ── Tool 4: List past scans ───────────────────────────────────────────────

    @Tool(description = """
            List all past vulnerability scans stored in history.
            Returns a summary table with scan ID, project name, vulnerability count,
            total dependencies checked, and when the scan was performed.
            Use this to find scan IDs for get_vulnerability_report.
            """)
    public String list_scan_history() {
        log.info("[MCP] list_scan_history");
        List<HistoryItem> items = history.listAll();
        if (items.isEmpty()) return "No scans in history yet.";

        StringBuilder sb = new StringBuilder();
        sb.append("| ID | Project | Vulns | Total Deps | Scanned At |\n");
        sb.append("|----|---------|-------|------------|------------|\n");
        for (HistoryItem item : items) {
            sb.append(String.format("| %d | %s | %d | %d | %s |\n",
                    item.getId(),
                    item.getDisplayName(),
                    item.getVulnCount(),
                    item.getTotalDeps(),
                    item.getScannedAt()));
        }
        return sb.toString();
    }

    // ── Tool 5: Check a single dependency ────────────────────────────────────

    @Tool(description = """
            Quickly check a single Maven dependency against the OSV vulnerability database.
            Use this for a fast check on one specific dependency without running a full scan.
            Format: groupId:artifactId:version
            Example: org.apache.logging.log4j:log4j-core:2.14.1
            Returns vulnerability details including CVE IDs, severity, and fixed versions.
            """)
    public String check_single_dependency(
            @ToolParam(description = "Dependency in format groupId:artifactId:version")
            String dependency) {
        log.info("[MCP] check_single_dependency: {}", dependency);
        String[] parts = dependency.split(":");
        if (parts.length < 3) {
            return "Invalid format. Use groupId:artifactId:version — e.g. org.springframework:spring-core:5.3.0";
        }
        String json = String.format("[{\"group_id\":\"%s\",\"artifact_id\":\"%s\",\"version\":\"%s\"}]",
                parts[0].strip(), parts[1].strip(), parts[2].strip());
        return tools.checkOsvVulnerabilitiesDirect(json);
    }

    // ── Tool 6: Find safe upgrade version ────────────────────────────────────

    @Tool(description = """
            Find the latest safe (non-vulnerable) version for a Maven dependency.
            Searches Maven Central for the latest release and cross-references with
            OSV known-fixed versions to recommend a safe upgrade.
            Format: groupId:artifactId:version
            Example: com.fasterxml.jackson.core:jackson-databind:2.9.0
            Returns the recommended safe version to upgrade to.
            """)
    public String get_safe_upgrade(
            @ToolParam(description = "Dependency in format groupId:artifactId:version")
            String dependency,
            @ToolParam(description = "Comma-separated known fixed versions from CVE advisory (optional, use empty string if unknown)")
            String fixed_versions) {
        log.info("[MCP] get_safe_upgrade: {}", dependency);
        String[] parts = dependency.split(":");
        if (parts.length < 3) {
            return "Invalid format. Use groupId:artifactId:version — e.g. log4j:log4j:1.2.17";
        }
        return tools.lookupLatestSafeVersionDirect(
                parts[0].strip(), parts[1].strip(), parts[2].strip(),
                fixed_versions == null ? "" : fixed_versions);
    }
}
