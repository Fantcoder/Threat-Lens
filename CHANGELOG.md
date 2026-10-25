# Changelog

All notable changes to the ThreatLens project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-10-25

### Added
- **Core Architecture & Scaffolding**:
  - Full modular package layout with Python 3.11+ strict typing (`mypy --strict`).
  - Cross-platform task orchestration mirroring `tasks.ps1` (PowerShell) and `Makefile` (Unix).
  - GitHub Actions CI matrix with automated linting, test coverage enforcement ($\ge 90\%$), SAST scanning (Bandit), and vulnerability audits (pip-audit).
- **IoC Detector & Refanging Engine**:
  - Auto-detection for IPv4, IPv6, Domains (FQDNs with PSL validation via `tldextract`), URLs, and cryptographic hashes (MD5, SHA1, SHA256).
  - Automatic refanging of security obfuscations: `hxxp://`, `hxxps://`, `[.]`, `(.)`, `[dot]`, and `[:]`.
  - Anti-SSRF validation rejecting RFC 1918, RFC 3927, RFC 4291, and cloud metadata addresses (`169.254.169.254`).
- **Concurrent Provider Adapters**:
  - VirusTotal v3 (IPv4, IPv6, Domain, URL via URL-safe unpadded base64, Hashes).
  - AlienVault OTX (IPv4, IPv6, Domain, URL, Hashes via OTX general indicator endpoints).
  - AbuseIPDB v2 (IPv4, IPv6 confidence checks).
  - Standardized normalization into Pydantic models with zero uncaught provider exceptions.
- **Resilience & Flow Control**:
  - In-memory TokenBucket rate limiter for per-minute provider smoothing.
  - Persistent SQLite DailyQuotaTracker with UTC midnight rollover.
  - Three-state CircuitBreaker (`CLOSED`, `OPEN`, `HALF_OPEN`) preventing cascading provider failures.
  - Exponential backoff with jitter and automated `Retry-After` header extraction via Tenacity.
- **Explainable Scoring Engine**:
  - Dynamic weight renormalization across available providers.
  - Non-linear scoring curves: VirusTotal sigmoid-like curve with malicious engine bonus, OTX logarithmic pulse curve with threat actor bonus, AbuseIPDB low-report damping.
  - Five verdict classifications: `clean`, `low_risk`, `suspicious`, `malicious`, `unknown`.
  - Machine-readable explainability breakdown with human audit rationale per provider.
- **High-Performance SQLite Cache**:
  - Variable TTL based on verdict classification (malicious = 2h, suspicious = 6h, clean = 24h).
  - In-flight request coalescing (single-flight pattern) eliminating concurrent cache stampedes.
  - Audit logging of historical queries.
- **FastAPI REST Service**:
  - Endpoints: `/health`, `/ready`, `/api/v1/lookup`, `/api/v1/lookup/batch`, `/api/v1/history`, `/api/v1/providers`.
  - RFC 7807 Problem Details compliant error responses.
  - Timing-safe authentication via `hmac.compare_digest`.
  - Automated `SecretRedactionFilter` scrubbing API tokens from structured JSON logs.
- **Typer CLI & Multi-Format Report Generator**:
  - Commands: `lookup`, `batch`, `providers`, `serve`.
  - Report formats: JSON, flattened CSV (SIEM-ready), GitHub-flavored Markdown, and self-contained dark-theme HTML dashboard.
  - Security gate exit codes (2 = threats detected, 0 = clean/low risk, 1 = error).
- **Containerization**:
  - Multi-stage Dockerfile with non-root user (`threatlens`, UID 10001) and healthcheck probe.
  - Production `docker-compose.yml` with persistent volume mapping.
