# VulnHawk — AI-Powered Java Vulnerability Scanner

> Enterprise-grade dependency vulnerability scanner built on Spring AI, supporting
> multi-vendor LLMs (Gemini, Claude, OpenAI, Ollama) with a 4-agent AI pipeline,
> REST API, web UI, and a full MCP integration roadmap.

---

## Table of Contents

- [What is Enterprise-Level Design](#what-is-enterprise-level-design)
- [Project Overview](#project-overview)
- [Current Architecture](#current-architecture)
- [Technology Stack](#technology-stack)
- [Quick Start](#quick-start)
- [LLM Vendor Configuration](#llm-vendor-configuration)
- [API Reference](#api-reference)
- [4-Agent AI Pipeline](#4-agent-ai-pipeline)
- [Enterprise Roadmap — MCP Integration](#enterprise-roadmap--mcp-integration)
- [Enterprise Architecture (Target)](#enterprise-architecture-target)
- [Security Considerations](#security-considerations)
- [Environment Variables](#environment-variables)

---

## What is Enterprise-Level Design

Enterprise-level design means building software that is **production-ready from day one**,
not just "it works on my machine." It covers seven pillars:

```
+-------------------+------------------------------------------------------+
| Pillar            | What it means for VulnHawk                          |
+-------------------+------------------------------------------------------+
| Scalability       | Handle 100s of concurrent scans, not just 1          |
| Observability     | Logs, metrics, traces — know what's happening        |
| Resilience        | LLM fails? Fallback pipeline kicks in automatically  |
| Security          | API keys in Vault, no secrets in code, rate limiting |
| Persistence       | PostgreSQL history, not in-memory (lost on restart)  |
| Integrations      | GitHub PRs, Jira tickets, Slack alerts — automated   |
| Developer UX      | Scan from Claude Code / Cursor — no browser needed   |
+-------------------+------------------------------------------------------+
```

**Current state:** VulnHawk delivers pillars 3 and 4 well (resilience via fallback
pipeline, multi-vendor LLM). The roadmap below delivers the remaining five.

---

## Project Overview

VulnHawk scans Java and Kotlin projects (Maven and Gradle) for vulnerable dependencies
by running a 4-agent AI pipeline. It checks against the OSV database, finds safe
upgrade versions from Maven Central, resolves Spring Boot BOM versions, and generates
a structured Markdown security report.

**Ported from:** Python (CrewAI + FastAPI) → Java (Spring AI + Spring Boot)

**Input:** GitHub repository URL or raw `group:artifact:version` dependency list

**Output:** Structured Markdown report with CVE details, severity, and upgrade paths

---

## Current Architecture

```
Browser / Claude Code / CI Pipeline
            |
            | HTTP REST
            v
+---------------------------+
|      ScanController       |
|  POST /scan               |
|  GET  /health             |
|  GET  /history            |
|  GET  /history/{id}       |
|  DELETE /history/{id}     |
|  GET  /                   |  <-- serves SPA (index.html)
+---------------------------+
            |
            v
+---------------------------+
| ScanOrchestrationService  |  4-agent pipeline
|                           |
|  Agent 1: Repo Scanner    | ---> git clone --depth 1 (GitHub)
|  Agent 2: Vuln Analyst    | ---> OSV API (batch CVE lookup)
|  Agent 3: Upgrade Strategist --> Maven Central (safe versions)
|  Agent 4: Report Generator|     BOM resolution (Spring Boot)
|                           |
|  [Deterministic Fallback] |  if LLM fails, tools run directly
+---------------------------+
            |
     +------+-------+
     |               |
     v               v
+----------+  +--------------------+
| VulnHawk |  | ScanHistoryService |
| Tools    |  | (in-memory, max 50)|
| (@Tool)  |  +--------------------+
+----------+
     |
     v
+--------------------+
|   LLM Backend      |
|                    |
|  google-genai  <-- default
|  anthropic         |
|  openai            |
|  ollama (local)    |
+--------------------+
```

### 8 Built-in Tools

| Tool                      | What it does                                      |
|---------------------------|---------------------------------------------------|
| `detectBuildSystem`       | Identifies Maven or Gradle from project files     |
| `extractDependencies`     | Parses pom.xml / build.gradle / dependency tree   |
| `checkOsvVulnerabilities` | Batch CVE lookup via OSV API                      |
| `lookupLatestSafeVersion` | Finds safe upgrade from Maven Central             |
| `resolveBomParent`        | Resolves Spring Boot BOM managed versions         |
| `searchCodeUsage`         | Checks if vulnerable API is actually called       |
| `fetchChangelog`          | Pulls changelog for the target upgrade version    |
| `readProjectDocs`         | Reads README, SECURITY.md for context             |

---

## Technology Stack

| Layer            | Technology                        | Version    |
|------------------|-----------------------------------|------------|
| Framework        | Spring Boot                       | 3.5.0      |
| AI Abstraction   | Spring AI                         | 1.1.2      |
| LLM (default)    | Google Gemini (google-genai)      | 2.0-flash  |
| LLM (alt)        | Anthropic Claude / OpenAI / Ollama| configurable|
| Build            | Gradle                            | 9.3.1      |
| Java             | Java 17                           | LTS        |
| HTTP Server      | Embedded Tomcat                   | 10.1.x     |
| History Storage  | In-memory (ConcurrentHashMap)     | — (Phase 2)|
| Frontend         | Vanilla JS + Tailwind CSS SPA     | —          |

---

## Quick Start

### Prerequisites

- Java 17+
- A Google AI Studio API key (free at https://aistudio.google.com/app/apikey)

### Run

```bash
git clone <repo>
cd vul-scanner-spring

export SPRING_AI_GOOGLE_GENAI_API_KEY=AIza...
./gradlew bootRun
```

Open http://localhost:8080

### Run with a different vendor

```bash
# Anthropic Claude
export LLM_VENDOR=anthropic
export SPRING_AI_ANTHROPIC_API_KEY=sk-ant-...
./gradlew bootRun

# OpenAI
export LLM_VENDOR=openai
export SPRING_AI_OPENAI_API_KEY=sk-...
./gradlew bootRun

# Ollama (local or remote GPU)
export LLM_VENDOR=ollama
export OLLAMA_BASE_URL=http://<host>:11434
./gradlew bootRun
```

### Run with remote Ollama (Linux GPU → MacBook)

On Linux machine:
```bash
OLLAMA_HOST=0.0.0.0 ollama serve
ollama pull qwen3-coder:14b
```

On Mac:
```bash
export LLM_VENDOR=ollama
export OLLAMA_BASE_URL=http://<linux-ip>:11434
./gradlew bootRun
```

### Build JAR

```bash
./gradlew build
java -jar build/libs/vul-scanner-spring-0.0.1-SNAPSHOT.jar
```

---

## LLM Vendor Configuration

Spring AI 1.1.x uses `spring.ai.model.chat` to activate exactly one vendor.
Setting `LLM_VENDOR` controls which auto-configuration fires at startup.

| LLM_VENDOR    | Required env var                    | Default model        |
|---------------|-------------------------------------|----------------------|
| `google-genai`| `SPRING_AI_GOOGLE_GENAI_API_KEY`    | gemini-2.0-flash     |
| `anthropic`   | `SPRING_AI_ANTHROPIC_API_KEY`       | claude-sonnet-4-6    |
| `openai`      | `SPRING_AI_OPENAI_API_KEY`          | gpt-4o               |
| `ollama`      | `OLLAMA_BASE_URL` (optional)        | llama3.1             |

Override the model per vendor:
```bash
export GOOGLE_MODEL=gemini-1.5-pro
export ANTHROPIC_MODEL=claude-opus-4-6
export OPENAI_MODEL=gpt-4o-mini
export OLLAMA_MODEL=qwen3-coder:14b
```

---

## API Reference

### Health Check

```
GET /health
```

```json
{
  "status": "ok",
  "llm_vendor": "google-genai",
  "ollama":    { "base_url": "...", "model": "...", "reachable": false },
  "openai":    { "api_key_set": false },
  "anthropic": { "api_key_set": false },
  "google":    { "api_key_set": true }
}
```

### Run a Scan

```
POST /scan
Content-Type: application/json
```

**Option A — GitHub URL:**
```json
{ "github_url": "https://github.com/spring-projects/spring-petclinic" }
```

**Option B — Dependency list:**
```json
{
  "input": "org.springframework:spring-core:5.3.0\nlog4j:log4j:1.2.17"
}
```

**Response:**
```json
{ "result": "# VulnHawk Security Report\n## Summary\n..." }
```

### History

```
GET    /history          -- list all scans
GET    /history/{id}     -- get report by id  -> { "report_md": "..." }
DELETE /history/{id}     -- delete a scan
```

### Web UI

```
GET /   -- serves index.html (full SPA)
```

---

## 4-Agent AI Pipeline

```
INPUT: GitHub URL or dependency list
            |
            v
+---------------------------+
|  Agent 1: Repo Scanner    |
|                           |
|  Tools used:              |
|  - detectBuildSystem      |
|  - extractDependencies    |
|                           |
|  Output: full dep list    |
|  [group:artifact:version] |
+---------------------------+
            |
            v
+---------------------------+
|  Agent 2: Vuln Analyst    |
|                           |
|  Tools used:              |
|  - checkOsvVulnerabilities|
|                           |
|  Output: CVE findings     |
|  with severity + details  |
+---------------------------+
            |
            v
+---------------------------+
|  Agent 3: Strategist      |
|                           |
|  Tools used:              |
|  - resolveBomParent       |
|  - lookupLatestSafeVersion|
|  - fetchChangelog         |
|  - searchCodeUsage        |
|                           |
|  Output: upgrade paths    |
|  for each vulnerable dep  |
+---------------------------+
            |
            v
+---------------------------+
|  Agent 4: Report Generator|
|                           |
|  Output: structured       |
|  Markdown report          |
|                           |
|  Sections:                |
|  - Executive Summary      |
|  - Critical Findings      |
|  - Upgrade Plan           |
|  - Dependency Table       |
+---------------------------+
            |
            v
OUTPUT: Markdown report saved to history
```

**Resilience:** If any agent's LLM call fails, a deterministic fallback
runs the tools directly and builds the report programmatically — no data is lost.

---

## Enterprise Roadmap — MCP Integration

### What is MCP?

Model Context Protocol (by Anthropic) is a standard that lets AI tools (Claude Code,
Cursor, VS Code) call your application's functions directly. Think of it as a plugin
system for AI — any MCP-compatible client can discover and call VulnHawk's tools
without a browser.

```
Developer in Claude Code:
  > "Scan spring-petclinic for vulnerabilities"
  > "Is log4j 2.14.1 vulnerable?"
  > "What's the safe upgrade for spring-core 5.3.0?"

Claude Code calls VulnHawk MCP tools automatically.
No browser. No copy-paste. Integrated into the dev workflow.
```

### 5-Phase Enterprise Plan

```
+--------+-----------------------+------------------+-------------------+
| Phase  | Feature               | Effort           | Business Value    |
+--------+-----------------------+------------------+-------------------+
| 1      | MCP Server            | 2-3 days         | Dev tool access   |
|        | Expose scan tools     | ~100 lines code  | No browser needed |
+--------+-----------------------+------------------+-------------------+
| 2      | PostgreSQL Persistence| 3-4 days         | Compliance        |
|        | Replace in-memory     |                  | Unlimited history |
|        | history with JPA      |                  | Audit trail       |
+--------+-----------------------+------------------+-------------------+
| 3      | GitHub MCP Client     | 4-5 days         | Shift-left        |
|        | PR scanning           |                  | security          |
|        | Auto PR comments      |                  | Block bad merges  |
|        | CI/CD gate            |                  |                   |
+--------+-----------------------+------------------+-------------------+
| 4      | Jira + Slack MCP      | 2-3 days         | Zero-touch        |
|        | Auto-create tickets   |                  | SecOps workflow   |
|        | Real-time alerts      |                  |                   |
+--------+-----------------------+------------------+-------------------+
| 5      | Enterprise Dashboard  | 5-7 days         | CISO reporting    |
|        | Trend charts          |                  | Audit exports     |
|        | SLA tracking          |                  | Board-level view  |
+--------+-----------------------+------------------+-------------------+
```

### Phase 1 — MCP Server Implementation

Add to `build.gradle`:
```groovy
implementation 'org.springframework.ai:spring-ai-starter-mcp-server-webmvc'
```

Add to `application.properties`:
```properties
spring.ai.mcp.server.enabled=true
spring.ai.mcp.server.name=vulnhawk
spring.ai.mcp.server.version=1.0.0
spring.ai.mcp.server.description=VulnHawk Java Vulnerability Scanner
spring.ai.mcp.server.type=SYNC
```

New service `McpToolsService.java` exposes 6 tools:

| MCP Tool                  | Description                                  |
|---------------------------|----------------------------------------------|
| `scan_repository`         | Full scan of a GitHub repo URL               |
| `scan_dependencies`       | Scan a raw group:artifact:version list       |
| `get_vulnerability_report`| Retrieve a past report by ID                 |
| `list_scan_history`       | List all past scans                          |
| `check_single_dependency` | Quick OSV check for one dependency           |
| `get_safe_upgrade`        | Find safe upgrade version for one dependency |

Connect from Claude Code (`~/.claude/settings.json`):
```json
{
  "mcpServers": {
    "vulnhawk": {
      "url": "http://localhost:8080/mcp/sse"
    }
  }
}
```

### Phase 2 — Persistent Storage

Replace `ScanHistoryService` (in-memory, 50 max) with JPA + PostgreSQL:

```sql
CREATE TABLE scan_history (
    id           BIGSERIAL PRIMARY KEY,
    scan_key     VARCHAR(255),
    display_name VARCHAR(255),
    input_type   VARCHAR(50),
    build_system VARCHAR(50),
    total_deps   INTEGER,
    vuln_count   INTEGER,
    report_md    TEXT,
    scanned_at   TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE vulnerabilities (
    id           BIGSERIAL PRIMARY KEY,
    scan_id      BIGINT REFERENCES scan_history(id),
    cve_id       VARCHAR(50),
    package_name VARCHAR(255),
    severity     VARCHAR(20),
    fixed_version VARCHAR(100)
);
```

### Phase 3 — GitHub Integration Flow

```
Developer opens PR
    --> GitHub webhook fires
    --> VulnHawk receives push event
    --> Extract changed build files (pom.xml / build.gradle)
    --> Run scan on changed dependencies only
    --> Post results as PR comment
    --> Set PR check: PASS (no critical) or FAIL (critical found)
    --> Block merge if CRITICAL severity detected
```

### Phase 4 — Alert Workflow

```
Scan completes with CRITICAL finding
    --> Check: does Jira ticket exist for this CVE?
    --> No: create ticket
        Title:    [SECURITY] CVE-2021-44228 in log4j-core:2.14.1
        Priority: Critical
        Labels:   security, auto-detected
    --> Post Slack alert to #security channel
        "CRITICAL: log4j Log4Shell in spring-petclinic
         CVE-2021-44228 | Fix: upgrade to 2.17.1
         Jira: INFRA-4521 | Report: /history/142"
```

### Target Enterprise Architecture

```
+=====================================================================+
|                      DEVELOPER ECOSYSTEM                             |
|  Claude Code | Cursor | Claude Desktop | VS Code | CI/CD Pipeline   |
+=============================+=======================================+
                              | MCP Protocol
                              v
+=====================================================================+
|                   VULNHAWK MCP SERVER                                |
|  scan_repository | scan_dependencies | check_single_dependency       |
|  get_vulnerability_report | list_scan_history | get_safe_upgrade     |
+===========+==================+=====================================+
            |                  |
            v                  v
+------------------+  +------------------+
|  4-AGENT CORE    |  |  MCP CLIENTS     |
|                  |  |                  |
|  Agent 1-4       |  |  GitHub MCP      |
|  VulnHawkTools   |  |  Jira MCP        |
|  OSV API         |  |  Slack MCP       |
|  Maven Central   |  |                  |
|  Multi-LLM       |  +------------------+
+------------------+
            |
            v
+------------------+  +------------------+
|  POSTGRESQL      |  |  REDIS CACHE     |
|                  |  |                  |
|  scan_history    |  |  OSV responses   |
|  vulnerabilities |  |  Maven versions  |
|  audit_log       |  |  BOM data        |
+------------------+  +------------------+
```

---

## Security Considerations

| Concern              | Current State     | Enterprise Mitigation                  |
|----------------------|-------------------|----------------------------------------|
| API keys             | Environment vars  | HashiCorp Vault / AWS Secrets Manager  |
| Secrets in code      | None              | Pre-commit hooks block accidental leaks|
| MCP endpoint         | Open (Phase 1)    | API key auth + allowlist               |
| GitHub token scope   | Not yet used      | Read-only, minimal permissions         |
| LLM prompt injection | Basic only        | Sanitize repo content before agents    |
| Rate limiting        | None              | Bucket4j per-IP rate limiting          |
| Audit trail          | None              | PostgreSQL audit_log table (Phase 2)   |
| Scan result privacy  | In-memory         | Encrypt report_md at rest (Phase 2)    |

---

## Environment Variables

| Variable                          | Default           | Description                          |
|-----------------------------------|-------------------|--------------------------------------|
| `LLM_VENDOR`                      | `google-genai`    | Active LLM vendor                    |
| `SPRING_AI_GOOGLE_GENAI_API_KEY`  | —                 | Google Gemini API key (AI Studio)    |
| `SPRING_AI_ANTHROPIC_API_KEY`     | —                 | Anthropic Claude API key             |
| `SPRING_AI_OPENAI_API_KEY`        | —                 | OpenAI API key                       |
| `OLLAMA_BASE_URL`                 | localhost:11434   | Ollama server (local or remote GPU)  |
| `OLLAMA_MODEL`                    | `llama3.1`        | Ollama model name                    |
| `GOOGLE_MODEL`                    | `gemini-2.0-flash`| Override Gemini model                |
| `ANTHROPIC_MODEL`                 | `claude-sonnet-4-6`| Override Anthropic model            |
| `OPENAI_MODEL`                    | `gpt-4o`          | Override OpenAI model                |
| `GITHUB_TOKEN`                    | —                 | GitHub token (avoids rate limits)    |
