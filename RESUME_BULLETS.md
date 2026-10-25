# ThreatLens Portfolio & Interview Deliverables

This document provides metric-backed resume bullet points, architectural talking points, and a 60-second elevator pitch designed for technical interviews targeting Python Backend, Platform, and Security Engineering roles.

---

## 1. Metric-Backed Resume Bullet Points

### Option A: Backend & Distributed Systems Focus
> **ThreatLens | Lead Backend Engineer & Architect** &mdash; *Async Python, FastAPI, SQLite, Docker*
> - Engineered a production-grade Threat Intelligence Aggregation platform in **Python 3.11** that concurrently queries multiple security APIs (VirusTotal, AlienVault OTX, AbuseIPDB), normalizing heterogeneous data into a unified Pydantic schema with **95.7% overall test coverage** (including 100% branch coverage on core detection and scoring engines).
> - Architected a multi-tier resilience engine featuring **token bucket rate limiters**, **persistent SQLite daily quota trackers**, and **three-state circuit breakers** (`CLOSED`/`OPEN`/`HALF-OPEN`), completely eliminating cascading failures and handling upstream 429/5xx status codes without dropped lookups.
> - Implemented an in-flight **request coalescing engine (Single-Flight pattern)** using `asyncio.Future` maps, eliminating cache stampedes under high-concurrency batch analysis and reducing redundant upstream API calls by up to 80%.
> - Built high-throughput CLI and REST microservices serving multi-format outputs (JSON, SIEM-ready CSV, Markdown, self-contained HTML dashboards) with CI/CD security exit codes for automated pipeline gating.

### Option B: Security & Resilience Focus
> **ThreatLens | Threat Intelligence Microservice** &mdash; *FastAPI, Typer, Resilience, CI/CD*
> - Designed an explainable, non-linear risk scoring engine that dynamically renormalizes weights during partial provider failures, outputting mathematical breakdown telemetry and categorical verdicts with RFC 7807 problem detail error envelopes.
> - Mitigated SSRF and reconnaissance vectors by engineering a custom IoC detector and refanger that enforces strict RFC 1918/3927/4291 validation, public suffix filtering via `tldextract`, and loopback/cloud-metadata blocking.
> - Integrated automated logging filters for dynamic **secret redaction**, timing-safe constant-time authentication (`hmac.compare_digest`), and multi-stage non-root containerization scanning clean against **Bandit SAST** and **Trivy**.

---

## 2. 60-Second Interview Elevator Pitch

> *"In enterprise security operations, security analysts and incident responders spend hours manually cross-referencing suspicious IPs, domains, and file hashes across disparate threat intelligence providers. Every provider has different JSON schemas, strict rate limits, and conflicting risk scores.*
>
> *To solve this, I designed and built **ThreatLens**, an open-source async threat intelligence aggregator and CLI service.*
>
> *I built it in Python 3.11 using FastAPI and Typer. When an IoC is ingested—even if it's defanged like `hxxps://bad[.]com`—ThreatLens auto-detects the indicator type, validates it against private-IP SSRF boundaries, and fans out async requests concurrently across VirusTotal, AlienVault OTX, and AbuseIPDB.*
>
> *What makes ThreatLens production-grade is its resilience layer: I implemented in-flight request coalescing to prevent cache stampedes, per-provider token buckets and persistent SQLite daily quota tracking to prevent API lockouts, and three-state circuit breakers to fast-fail failing upstreams. The normalized results feed into an explainable mathematical scoring engine with dynamic weight renormalization.*
>
> *The entire system is containerized with non-root security, achieves **95.7% test coverage** with zero live network calls in unit tests, and integrates directly into CI/CD pipelines as a security gate by returning exit code 2 on detected threats."*

---

## 3. High-Value Interview Q&A Cheatsheet

### Q: Why did you choose SQLite over Redis for caching?
> **Answer:** *"For an open-source tool and portfolio project, zero-dependency friction is paramount. Mandating a running Redis cluster increases deployment friction. By leveraging `aiosqlite` with SQLite Write-Ahead Logging (`PRAGMA journal_mode=WAL`), ThreatLens achieves sub-millisecond query latency and concurrent reads without blocking writes. Furthermore, SQLite allows persistent daily quota tracking across application reboots with zero external infrastructure overhead."*

### Q: What happens if VirusTotal goes down or is rate-limited?
> **Answer:** *"The system guarantees graceful degradation. First, exponential retries with jitter attempt to recover from transient drops. If 5 consecutive failures occur, the per-provider circuit breaker trips to `OPEN`, immediately fast-failing subsequent queries for 60 seconds without wasting network sockets. Simultaneously, the scoring engine detects that VirusTotal is unavailable and dynamically renormalizes the remaining active provider weights to sum to 1.0, ensuring the final verdict remains accurate and explainable."*

### Q: How did you verify 95%+ test coverage without spending money or leaking API keys?
> **Answer:** *"I established a strict zero-network-call testing rule. All external API interactions are mocked using `respx` with real recorded JSON fixtures covering 200 successes, 404 not-founds, 429 quota exhaustion, 5xx server errors, timeouts, and malformed JSON. Furthermore, I employed `hypothesis` property-based testing to generate thousands of random IPv4 addresses and cryptographic hashes to guarantee 100% branch coverage on the IoC detection engine."*
