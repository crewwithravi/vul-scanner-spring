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
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicLong;

@RestController
@CrossOrigin
public class ScanController {

    private static final Logger log = LoggerFactory.getLogger(ScanController.class);

    // ── In-progress scan job tracking ─────────────────────────────────────────
    private static class ScanJob {
        volatile String status = "running";
        volatile String result;
        volatile String error;
    }

    private final Map<Long, ScanJob> jobs = new ConcurrentHashMap<>();
    private final AtomicLong jobIdGen = new AtomicLong(1);
    private final ExecutorService scanExecutor = Executors.newFixedThreadPool(3);

    // ── Dependencies ──────────────────────────────────────────────────────────
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

    // ── Scan (async) ─────────────────────────────────────────────────────────

    @PostMapping("/scan")
    public ResponseEntity<?> scan(@RequestBody ScanRequest request) {
        if ((request.github_url() == null || request.github_url().isBlank())
                && (request.input() == null || request.input().isBlank())) {
            return ResponseEntity.badRequest().body(Map.of("detail", "Either github_url or input must be provided."));
        }

        final long jobId = jobIdGen.getAndIncrement();
        final ScanJob job = new ScanJob();
        jobs.put(jobId, job);

        final String githubUrl = request.github_url();
        final String depInput  = request.input();

        scanExecutor.submit(() -> {
            try {
                String report;
                String scanKey, displayName, inputType, buildSystem = "";

                if (githubUrl != null && !githubUrl.isBlank()) {
                    String[] kn = ScanHistoryService.scanKeyForUrl(githubUrl);
                    scanKey = kn[0]; displayName = kn[1]; inputType = "url";
                    log.info("Scan job #{}: GitHub URL = {}", jobId, githubUrl);
                    report = orchestration.scanFromUrl(githubUrl);
                } else {
                    String[] kn = ScanHistoryService.scanKeyForDeps(depInput);
                    scanKey = kn[0]; displayName = kn[1]; inputType = "dep-list";
                    log.info("Scan job #{}: dep list ({} chars)", jobId, depInput.length());
                    report = orchestration.scanFromDepList(depInput);
                }

                history.save(scanKey, displayName, inputType, buildSystem, report);
                job.result = report;
                job.status = "completed";
                log.info("Scan job #{} completed", jobId);

            } catch (Exception e) {
                log.error("Scan job #{} failed", jobId, e);
                job.error = e.getMessage();
                job.status = "failed";
            }
        });

        return ResponseEntity.accepted().body(Map.of("scan_id", jobId, "status", "running"));
    }

    // ── Scan status (polling) ─────────────────────────────────────────────────

    @GetMapping("/scan/{id}/status")
    public ResponseEntity<?> scanStatus(@PathVariable long id) {
        ScanJob job = jobs.get(id);
        if (job == null) return ResponseEntity.notFound().build();

        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("scan_id", id);
        resp.put("status", job.status);
        if ("completed".equals(job.status)) resp.put("result", job.result);
        if ("failed".equals(job.status))    resp.put("error",  job.error);
        return ResponseEntity.ok(resp);
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
        return ResponseEntity.ok(Map.of("report_md", item.get().getReportMd()));
    }

    @DeleteMapping("/history/{id}")
    public ResponseEntity<Void> deleteHistory(@PathVariable long id) {
        return history.delete(id)
            ? ResponseEntity.noContent().build()
            : ResponseEntity.notFound().build();
    }

    // ── Static root ──────────────────────────────────────────────────────────

    @GetMapping(value = "/", produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<byte[]> root() throws java.io.IOException {
        byte[] html = new ClassPathResource("static/index.html").getInputStream().readAllBytes();
        return ResponseEntity.ok().contentType(MediaType.TEXT_HTML).body(html);
    }
}
