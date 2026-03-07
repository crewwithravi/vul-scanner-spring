package com.ravi.vul.vulscannerspring.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ravi.vul.vulscannerspring.model.HistoryItem;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.*;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Scan history — persisted to a JSON file so history survives restarts.
 * Stores up to 50 most recent scans.
 */
@Service
public class ScanHistoryService {

    private static final Logger log = LoggerFactory.getLogger(ScanHistoryService.class);
    private static final int MAX_HISTORY = 50;
    private static final DateTimeFormatter ISO = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss")
            .withZone(ZoneOffset.UTC);

    @Value("${vulnhawk.history.file:./data/history.json}")
    private String historyFile;

    private final ObjectMapper om = new ObjectMapper();
    private final AtomicLong idGen = new AtomicLong(1);
    private final Map<Long, HistoryItem> store = new ConcurrentHashMap<>();
    // Ordered insertion tracking
    private final List<Long> insertOrder = Collections.synchronizedList(new ArrayList<>());

    @PostConstruct
    public void loadFromDisk() {
        Path path = Path.of(historyFile);
        if (!Files.exists(path)) return;
        try {
            List<HistoryItem> items = om.readValue(path.toFile(),
                    new TypeReference<List<HistoryItem>>() {});
            // Restore in insertion order (oldest first)
            items.stream()
                 .sorted(Comparator.comparingLong(HistoryItem::getId))
                 .forEach(item -> {
                     store.put(item.getId(), item);
                     insertOrder.add(item.getId());
                 });
            long maxId = items.stream().mapToLong(HistoryItem::getId).max().orElse(0L);
            idGen.set(maxId + 1);
            log.info("Loaded {} history entries from {}", items.size(), historyFile);
        } catch (IOException e) {
            log.warn("Could not load history from {}: {}", historyFile, e.getMessage());
        }
    }

    private synchronized void saveToDisk() {
        try {
            Path path = Path.of(historyFile);
            Files.createDirectories(path.getParent() != null ? path.getParent() : Path.of("."));
            List<HistoryItem> ordered = insertOrder.stream()
                    .map(store::get).filter(Objects::nonNull).collect(Collectors.toList());
            om.writerWithDefaultPrettyPrinter().writeValue(path.toFile(), ordered);
        } catch (IOException e) {
            log.warn("Could not persist history to {}: {}", historyFile, e.getMessage());
        }
    }

    public HistoryItem save(String scanKey, String displayName, String inputType,
                             String buildSystem, String reportMd) {
        long id = idGen.getAndIncrement();
        int totalDeps = extractInt(reportMd, "Total Dependencies Checked[:\\s]+(\\d+)");
        int vulnCount  = extractInt(reportMd, "Vulnerable Count[:\\s]+(\\d+)");
        String now = ISO.format(Instant.now());

        HistoryItem item = new HistoryItem(id, scanKey, displayName, inputType,
                buildSystem == null ? "" : buildSystem, totalDeps, vulnCount, reportMd, now);
        store.put(id, item);
        insertOrder.add(id);

        // Evict oldest if over limit
        while (insertOrder.size() > MAX_HISTORY) {
            Long oldest = insertOrder.remove(0);
            store.remove(oldest);
        }
        saveToDisk();
        return item;
    }

    public List<HistoryItem> listAll() {
        return insertOrder.stream()
                .map(store::get)
                .filter(Objects::nonNull)
                .sorted(Comparator.comparingLong(HistoryItem::getId).reversed())
                .collect(Collectors.toList());
    }

    public Optional<HistoryItem> findById(long id) {
        return Optional.ofNullable(store.get(id));
    }

    public boolean delete(long id) {
        if (!store.containsKey(id)) return false;
        store.remove(id);
        insertOrder.remove(id);
        saveToDisk();
        return true;
    }

    // ── Key helpers (match Python's _scan_key_for_url / _scan_key_for_deps) ──

    public static String[] scanKeyForUrl(String url) {
        String path = url.strip().replaceFirst("https?://github\\.com/", "").replaceAll("/$", "");
        path = path.replaceAll("\\.git$", "");
        String[] parts = path.split("/");
        String key  = parts.length >= 2 ? parts[0] + "/" + parts[1] : path;
        String name = parts.length >= 2 ? parts[1] : path;
        return new String[]{key, name};
    }

    public static String[] scanKeyForDeps(String depInput) {
        String[] lines = depInput.lines()
                .map(String::strip).filter(l -> !l.isEmpty() && !l.startsWith("#"))
                .sorted().toArray(String[]::new);
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(String.join("\n", lines).getBytes());
            StringBuilder hex = new StringBuilder();
            for (int i = 0; i < 6; i++) hex.append(String.format("%02x", digest[i]));
            String key  = "dep-list:" + hex;
            String name = "Dep list (" + lines.length + " deps)";
            return new String[]{key, name};
        } catch (Exception e) {
            return new String[]{"dep-list:unknown", "Dep list"};
        }
    }

    private int extractInt(String text, String regex) {
        if (text == null) return 0;
        Matcher m = Pattern.compile(regex, Pattern.CASE_INSENSITIVE).matcher(text);
        return m.find() ? Integer.parseInt(m.group(1)) : 0;
    }
}
