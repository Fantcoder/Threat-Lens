# ThreatLens Portfolio & Interview Deliverables

This document provides metric-backed resume bullet points, architectural talking points, and a 60-second elevator pitch designed for technical interviews targeting Python Backend, Platform, and Security Engineering roles.

All metrics below are derived directly from reproducible test and benchmark executions (`scripts/bench_batch.py`, `pytest --cov`, and Bandit SAST).

---

## 1. Metric-Backed Resume Bullet Points

### Option A: Backend & Distributed Systems Focus
> **ThreatLens | Personal Project** &mdash; *Async Python, FastAPI, SQLite, Docker*
> - Engineered an async Threat Intelligence Aggregator in **Python 3.11+** that concurrently queries multiple external APIs (VirusTotal, AlienVault OTX, AbuseIPDB) via HTTPX, normalizing heterogeneous responses into validated Pydantic models with **94.9% test coverage across 226 automated tests**.
> - Architected a multi-tier resilience engine featuring **token bucket rate limiters** for per-minute smoothing, **persistent SQLite daily quota trackers** with UTC midnight rollover, and **three-state circuit breakers** (`CLOSED`/`OPEN`/`HALF-OPEN`) with a strict single-probe recovery gate to prevent thundering herds on recovering upstreams.
> - Implemented an in-flight **request coalescing engine (Single-Flight pattern)** and SQLite WAL-mode cache with verdict-based TTL; benchmarked a 100-IoC batch (40% duplicates) with simulated 50ms latency, proving a **40.0% reduction in upstream HTTP calls** (180 calls vs. 300 uncoalesced) and reducing wall time from 5.66s (concurrency 1) to 2.95s (concurrency 20).
> - Built high-throughput CLI (Typer/Rich) and REST (FastAPI) services serving multi-format outputs (JSON, SIEM-ready CSV, Markdown, self-contained HTML dashboards) with pipeline exit codes (0 for clean, 2 for threats) for CI/CD security gating.

### Option B: Security & Resilience Focus
> **ThreatLens | Personal Project** &mdash; *FastAPI, Typer, Resilience, CI/CD*
> - Designed an explainable risk scoring engine with **dynamic weight renormalization** during partial provider failures, a **strong-signal floor** ($\ge 0.8 \times \text{max\_subscore}$) preventing dilution of high-severity alerts by unindexed feeds, and RFC 7807 problem detail error responses.
> - Enforced input hygiene and non-routable address rejection by engineering a custom IoC detector and refanger validating RFC 1918/3927/4291 boundaries, public suffix filtering via `tldextract`, and loopback/cloud-metadata blocking.
> - Built an automated `SecretRedactionFilter` scrubbing credentials from JSON logs and exception tracebacks, timing-safe API key authentication (`hmac.compare_digest`), bounded per-IP rate limiting, and a hardened multi-stage Docker container running as non-root (UID 10001).

---

## 2. 60-Second Interview Elevator Pitch

> *"In security operations, incident responders spend significant time manually cross-referencing suspicious IPs, domains, and file hashes across multiple threat intelligence feeds—each with different schemas, strict rate limits, and conflicting scores.*
>
> *To address this, I built **ThreatLens**, an open-source async threat intelligence aggregation microservice and CLI in Python 3.11 using FastAPI and Typer.*
>
> *When an IoC is submitted—even if defanged like `hxxps://bad[.]com`—ThreatLens validates indicator structure, rejects non-routable IP ranges for input hygiene, and fans out concurrent async requests across VirusTotal, AlienVault OTX, and AbuseIPDB.*
>
> *What makes the system resilient is its multi-tier defense: request coalescing eliminates cache stampedes, token buckets smooth requests to provider rate limits, persistent SQLite tables track daily quotas across restarts, and circuit breakers with single-probe half-open gates prevent flooding degraded upstreams. The scoring engine dynamically renormalizes provider weights and enforces a strong-signal floor so critical alerts aren't diluted.*
>
> *The project includes 226 tests with 94.9% test coverage, a reproducible batch benchmark script, and runs in a hardened non-root container."*

---

## 3. High-Value Interview Q&A Cheatsheet

### Q: Why did you choose SQLite over Redis for caching?
> **Answer:** *"For a standalone microservice and CLI tool, zero external infrastructure friction was a primary design goal. Requiring a Redis cluster adds operational overhead for local analysis. By using `aiosqlite` with Write-Ahead Logging (`PRAGMA journal_mode=WAL`) and a busy timeout (`PRAGMA busy_timeout=5000`), ThreatLens achieves sub-millisecond lookup latency and concurrent reads without blocking writes. Additionally, SQLite provides durable daily quota tracking across service restarts with zero operational dependencies."*

### Q: How does the system handle upstream provider outages or rate limits?
> **Answer:** *"Through four defense layers:
> 1. **Exponential Retries:** Using Tenacity, transient 5xx errors and 429 rate limits retry with exponential backoff and random jitter. When upstreams supply a `Retry-After` header, the system parses it and respects the requested wait.
> 2. **Circuit Breakers:** If 5 consecutive failures occur, the provider's circuit breaker trips to `OPEN`, fast-failing subsequent calls for 60 seconds without wasting network sockets.
> 3. **Single-Probe Half-Open Gate:** When the 60s cooldown expires, the breaker transitions to `HALF-OPEN` and permits exactly one probe request. Concurrent requests arriving during the probe are rejected immediately rather than flooding the recovering service.
> 4. **Dynamic Renormalization:** The scoring engine detects unavailable providers and renormalizes active provider weights to sum to 1.0, preserving score explainability. If all providers fail with errors, the API returns HTTP 502 Bad Gateway."*

### Q: How do you prevent cache stampedes under high concurrency?
> **Answer:** *"I implemented the single-flight request coalescing pattern using an internal `dict[str, asyncio.Future[AggregatedReport]]`. When multiple concurrent requests arrive for the same indicator (common during batch alert triage), only the first request dispatches upstream queries while creating a Future. All concurrent requests await that same Future. When the query completes, the result resolves across all waiting callers simultaneously, eliminating redundant network calls."*

### Q: How does the scoring engine prevent false-clean verdicts or dilution of critical threat signals?
> **Answer:** *"In naive weighted averaging, an indicator flagged as confirmed malware by VirusTotal (e.g. subscore 85) could be averaged down into 'low risk' if other feeds have not yet indexed the indicator and score 0.
> ThreatLens resolves this through two mechanisms:
> 1. **Strong-Signal Floor:** If any confident provider identifies strong malicious evidence ($S_i \ge 65$), the final risk score is bounded from below by $\lfloor 0.8 \times \max(S_i) \rfloor$, ensuring critical security alerts are never masked.
> 2. **Confidence Damping on Partial Failures:** If one provider fails and the remaining providers return clean results, confidence is penalized. If confidence falls below `min_confidence_for_clean` (0.60), the engine refuses to emit a `clean` verdict, falling back to `unknown` or preserving risk visibility, and avoids caching with long clean TTLs."*

### Q: How do you prevent credential leakage in logs and exception tracebacks?
> **Answer:** *"ThreatLens registers all configured API keys with a custom `SecretRedactionFilter` on startup. The logging formatter scrubs sensitive tokens from standard log messages, string representations, and formatted exception tracebacks (`formatException`), replacing them with `***REDACTED***`. Furthermore, REST API key verification uses constant-time `hmac.compare_digest` to prevent timing side-channel attacks."*

### Q: How did you test and benchmark without incurring API costs or network dependencies?
> **Answer:** *"The test suite comprises 226 automated unit and integration tests using `respx` mock routers and recorded JSON fixtures for successful responses, 404s, 429 rate limits, 5xx server errors, timeouts, and malformed payloads, guaranteeing zero live network calls during testing.
> For performance verification, `scripts/bench_batch.py` runs a 100-IoC batch against a mock transport with simulated 50ms latency across concurrency levels 1, 5, and 20, verifying that caching and coalescing save exactly 40.0% of upstream HTTP calls on a 40% duplicate dataset."*
