package com.ravi.vul.vulscannerspring.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public class HistoryItem {

    private long id;

    @JsonProperty("scan_key")
    private String scanKey;

    @JsonProperty("display_name")
    private String displayName;

    @JsonProperty("input_type")
    private String inputType;

    @JsonProperty("build_system")
    private String buildSystem;

    @JsonProperty("total_deps")
    private int totalDeps;

    @JsonProperty("vuln_count")
    private int vulnCount;

    @JsonProperty("report_md")
    private String reportMd;

    @JsonProperty("scanned_at")
    private String scannedAt;

    public HistoryItem() {}

    public HistoryItem(long id, String scanKey, String displayName, String inputType,
                       String buildSystem, int totalDeps, int vulnCount,
                       String reportMd, String scannedAt) {
        this.id = id;
        this.scanKey = scanKey;
        this.displayName = displayName;
        this.inputType = inputType;
        this.buildSystem = buildSystem;
        this.totalDeps = totalDeps;
        this.vulnCount = vulnCount;
        this.reportMd = reportMd;
        this.scannedAt = scannedAt;
    }

    public long getId() { return id; }
    public String getScanKey() { return scanKey; }
    public String getDisplayName() { return displayName; }
    public String getInputType() { return inputType; }
    public String getBuildSystem() { return buildSystem; }
    public int getTotalDeps() { return totalDeps; }
    public int getVulnCount() { return vulnCount; }
    public String getReportMd() { return reportMd; }
    public String getScannedAt() { return scannedAt; }
}
