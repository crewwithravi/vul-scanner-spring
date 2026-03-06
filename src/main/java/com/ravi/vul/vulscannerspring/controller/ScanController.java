package com.ravi.vul.vulscannerspring.controller;

import com.ravi.vul.vulscannerspring.model.HistoryItem;
import com.ravi.vul.vulscannerspring.model.ScanRequest;
import com.ravi.vul.vulscannerspring.service.ScanHistoryService;
import com.ravi.vul.vulscannerspring.service.ScanOrchestrationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestClient;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * VulnHawk REST API — matches the contract expected by app.js.
 *
 * Endpoints:
 *   GET  /             → serves index.html (handled by Spring MVC static resources)
 *   GET  /health       → LLM + backend health status
 *   POST /scan         → run vulnerability scan
 *   GET  /history      → list past scans
 *   GET  /history/{id} → retrieve a specific scan
 *   DELETE /history/{id} → delete a scan
 */
@RestController
@CrossOrigin
public class ScanController {

    private static final Logger log = LoggerFactory.getLogger(ScanController.class);

    private final ScanOrchestrationService orchestration;
    private final ScanHistoryService history;
    private final RestClient http = RestClient.create();

    @Value("${vulnhawk.llm.vendor:ollama}")
    private String llmVendor;

    @Value("${spring.ai.ollama.base-url:http://localhost:11434}")
    private String ollamaBaseUrl;

    @Value("${spring.ai.ollama.chat.model:llama3.1}")
    private String ollamaModel;

    @Value("${spring.ai.openai.api-key:}")
    private String openAiKey;

    @Value("${spring.ai.anthropic.api-key:}")
    private String anthropicKey;

    @Value("${spring.ai.google.genai.api-key:}")
    private String googleKey;

    public ScanController(ScanOrchestrationService orchestration, ScanHistoryService history) {
        this.orchestration = orchestration;
        this.history = history;
    }

    // ── Health ───────────────────────────────────────────────────────────────

    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> health() {
        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("status", "ok");
        resp.put("llm_vendor", llmVendor);

        // Check Ollama reachability
        Map<String, Object> ollamaStatus = new LinkedHashMap<>();
        ollamaStatus.put("base_url", ollamaBaseUrl);
        ollamaStatus.put("model", ollamaModel);
        try {
            http.get().uri(ollamaBaseUrl + "/api/tags").retrieve().toBodilessEntity();
            ollamaStatus.put("reachable", true);
        } catch (Exception e) {
            ollamaStatus.put("reachable", false);
            ollamaStatus.put("error", e.getMessage());
        }
        resp.put("ollama", ollamaStatus);

        resp.put("openai",    Map.of("api_key_set", !openAiKey.isBlank()));
        resp.put("anthropic", Map.of("api_key_set", !anthropicKey.isBlank()));
        resp.put("google",    Map.of("api_key_set", !googleKey.isBlank()));

        return ResponseEntity.ok(resp);
    }

    // ── Scan ─────────────────────────────────────────────────────────────────

    @PostMapping("/scan")
    public ResponseEntity<?> scan(@RequestBody ScanRequest request) {
        if ((request.github_url() == null || request.github_url().isBlank())
                && (request.input() == null || request.input().isBlank())) {
            return ResponseEntity.badRequest().body(Map.of("detail", "Either github_url or input must be provided."));
        }

        try {
            String report;
            String scanKey, displayName, inputType, buildSystem = "";

            if (request.github_url() != null && !request.github_url().isBlank()) {
                String[] keyName = ScanHistoryService.scanKeyForUrl(request.github_url());
                scanKey = keyName[0]; displayName = keyName[1]; inputType = "url";
                log.info("Scan request: GitHub URL = {}", request.github_url());
                report = orchestration.scanFromUrl(request.github_url());
            } else {
                String[] keyName = ScanHistoryService.scanKeyForDeps(request.input());
                scanKey = keyName[0]; displayName = keyName[1]; inputType = "dep-list";
                log.info("Scan request: dep list ({} chars)", request.input().length());
                report = orchestration.scanFromDepList(request.input());
            }

            // Save to history
            history.save(scanKey, displayName, inputType, buildSystem, report);

            return ResponseEntity.ok(Map.of("result", report));

        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("detail", e.getMessage()));
        } catch (Exception e) {
            log.error("Scan failed", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("detail", "Scan failed: " + e.getMessage()));
        }
    }

    // ── History ───────────────────────────────────────────────────────────────

    @GetMapping("/history")
    public ResponseEntity<List<HistoryItem>> listHistory() {
        return ResponseEntity.ok(history.listAll());
    }

    @GetMapping("/history/{id}")
    public ResponseEntity<?> getHistory(@PathVariable long id) {
        Optional<HistoryItem> item = history.findById(id);
        if (item.isEmpty()) return ResponseEntity.notFound().build();
        // Frontend expects { report_md: "..." }
        return ResponseEntity.ok(Map.of("report_md", item.get().getReportMd()));
    }

    @DeleteMapping("/history/{id}")
    public ResponseEntity<Void> deleteHistory(@PathVariable long id) {
        return history.delete(id)
            ? ResponseEntity.noContent().build()
            : ResponseEntity.notFound().build();
    }

    // ── Static root ──────────────────────────────────────────────────────────

    /**
     * Serve index.html at "/" so the SPA loads when navigating to the root.
     */
    @GetMapping(value = "/", produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<byte[]> root() throws java.io.IOException {
        byte[] html = new ClassPathResource("static/index.html").getInputStream().readAllBytes();
        return ResponseEntity.ok().contentType(MediaType.TEXT_HTML).body(html);
    }
}
