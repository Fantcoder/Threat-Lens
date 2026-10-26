# ThreatLens

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![CI](https://github.com/Fantcoder/Threat-Lens/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Fantcoder/Threat-Lens/actions/workflows/ci.yml)
[![Security Audit](https://github.com/Fantcoder/Threat-Lens/actions/workflows/security.yml/badge.svg?branch=main)](https://github.com/Fantcoder/Threat-Lens/actions/workflows/security.yml)
[![Code Style: Ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Type Checked: Mypy](https://img.shields.io/badge/type_checked-mypy_strict-blue.svg)](https://mypy-lang.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

> **Threat Intelligence Aggregator & CLI** &mdash; Concurrently query, normalize, and score Indicators of Compromise (IoCs) across multiple threat intelligence providers with explainable scoring, multi-tier resilience, and persistent local caching.

---

## Architecture Overview

ThreatLens unifies disparate threat intelligence sources into a single normalized schema, orchestrating async queries with built-in request coalescing, circuit breakers, and rate limiters.

```mermaid
graph TD
    subgraph Clients ["Delivery Interfaces"]
        CLI["Typer CLI<br/>(lookup / batch / providers / serve)"]
        API["FastAPI REST API<br/>(/api/v1/lookup, /batch, /history)"]
        Gate["CI/CD Security Gating<br/>(Exit Code 2 on Threats)"]
    end

    subgraph Core ["Core Engine & Resilience"]
        Det["IoC Detector & Refanger<br/>(RFC Non-Routable Rejection)"]
        Agg["Aggregator Orchestrator<br/>(Single-Flight Request Coalescing)"]
        Score["Explainable Scoring Engine<br/>(Dynamic Weight Renormalization)"]
        Res["Resilience Layer<br/>(TokenBucket, SQLite Daily Quotas, CircuitBreakers)"]
        Cache[("SQLite WAL Cache<br/>(TTL by Verdict)")]
    end

    subgraph Providers ["Intelligence Providers"]
        VT["VirusTotal v3 API"]
        OTX["AlienVault OTX API"]
        Abuse["AbuseIPDB v2 API"]
    end

    CLI --> Agg
    API --> Agg
    Gate --> CLI
    Agg --> Det
    Agg --> Cache
    Agg --> Res
    Res --> Providers
    Providers --> Score
    Score --> Agg
```

---

## Key Features

- **Multi-Type IoC Auto-Detection & Refanging**:
  - Automatically identifies IPv4, IPv6, Domains (FQDNs verified against Mozilla Public Suffix List via `tldextract`), URLs, and cryptographic hashes (MD5, SHA1, SHA256).
  - Automatically refangs defanged indicators commonly found in security tickets: `hxxp://`, `hxxps://`, `[.]`, `(.)`, `[dot]`, and `[:]`.
  - **RFC Non-Routable Address Rejection**: Strictly rejects loopback, RFC 1918 private subnets, link-local, and cloud metadata addresses (`169.254.169.254`) during indicator validation for input hygiene (note: input validation is not a complete SSRF defense against DNS rebinding, IPv6-mapped IPv4, or downstream redirects).
- **Concurrent Provider Fan-Out**:
  - Concurrently queries **VirusTotal v3**, **AlienVault OTX**, and **AbuseIPDB** using async HTTPX.
  - Normalizes heterogeneous responses into unified, validated Pydantic models with zero uncaught provider exceptions.
- **Explainable Scoring Engine**:
  - Transparent non-linear scoring curves (sigmoid VT curve with engine count bonus, logarithmic OTX pulse curve with threat actor bonus, AbuseIPDB confidence damping).
  - **Dynamic Weight Renormalization**: If a provider is skipped or circuit-broken, active provider weights are mathematically renormalized to sum to 1.0.
  - **Strong-Signal Floor**: Prevents confident malicious evidence from being diluted by neutral or partial feeds.
  - Outputs an audited, human-readable reason per provider alongside categorical verdicts: `clean`, `low_risk`, `suspicious`, `malicious`, `unknown`.
- **Multi-Tier Resilience & Flow Control**:
  - **Token Bucket Limiter**: Smooths requests to match upstream per-minute limits (RPM).
  - **Persistent Daily Quota Tracker**: Persists daily quota usage in SQLite across restarts with UTC midnight rollover.
  - **Three-State Circuit Breakers**: Prevents cascading failures to failing upstreams (`CLOSED` &rarr; `OPEN` &rarr; `HALF-OPEN`) with a strict single-probe gate.
  - **Exponential Backoff**: Resilient retry policy for 5xx and 429 status codes with jitter and automated `Retry-After` header parsing.
- **High-Performance Local Caching**:
  - Persistent SQLite cache in Write-Ahead Logging (WAL) mode with variable TTL based on verdict (malicious cached 6h, clean cached 24h).
  - **Request Coalescing (Single-Flight)**: Deduplicates simultaneous in-flight queries for identical indicators using `asyncio.Future` maps, eliminating cache stampedes.
- **Multi-Format Report Generator**:
  - Exports reports in **JSON**, **CSV** (flattened 17-column format ready for SIEM ingest), **Markdown**, and **self-contained HTML dashboards** (dark cybersecurity theme, KPI cards, sortable table via vanilla JS, and search filtering with zero CDN dependencies).
- **Security-First Architecture**:
  - Correlated request tracking (`X-Request-ID`).
  - Automated `SecretRedactionFilter` guarantees API keys never leak into JSON logs or exception tracebacks.
  - Timing-safe constant-time API key verification (`hmac.compare_digest`).
  - Multi-stage hardened Docker image running as non-root user `threatlens` (UID 10001).

---

## Quickstart

### 1. Installation

Requires Python 3.11+. The project is managed via [uv](https://docs.astral.sh/uv/) or pip.

**Windows (PowerShell):**
```powershell
# Clone the repository
git clone https://github.com/Fantcoder/Threat-Lens.git
cd Threat-Lens

# Install dependencies using the PowerShell task runner
.\tasks.ps1 install
```

**Linux / macOS:**
```bash
# Clone the repository
git clone https://github.com/Fantcoder/Threat-Lens.git
cd Threat-Lens

# Install dependencies using Makefile
make install
```

### 2. Configuration

Copy the example environment configuration:
```bash
cp .env.example .env
```

Edit `.env` with your provider API keys (ThreatLens runs cleanly even with no API keys configured; unconfigured providers will be marked as `skipped` and weights will automatically renormalize):
```env
THREATLENS_VIRUSTOTAL_API_KEY=your_vt_api_key_here
THREATLENS_OTX_API_KEY=your_otx_api_key_here
THREATLENS_ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
```

---

## CLI Usage

The CLI is powered by Typer and Rich.

### Single Indicator Lookup
```bash
threatlens lookup 8.8.8.8
```

Output:
```text
╭────────────────── ThreatLens Intelligence — 8.8.8.8 ──────────────────╮
│ Indicator      8.8.8.8                                                │
│ Type           ipv4                                                   │
│ Verdict        CLEAN                                                  │
│ Risk Score     0 / 100                                                │
│ Confidence     1.00                                                   │
│ Cached         No                                                     │
│ Succeeded      virustotal, otx, abuseipdb                             │
│ Failed         None                                                   │
╰───────────────────────────────────────────────────────────────────────╯
```

Flags:
- `--json` / `-j`: Output raw JSON report.
- `--refresh` / `-r`: Bypass local cache and force fresh upstream query.
- `--raw`: Include raw provider JSON payloads.

### Batch Analysis & Reporting
Analyze multiple indicators from a text file or pipeline:
```bash
# Analyze from file and export self-contained HTML dashboard
threatlens batch suspicious_iocs.txt --output report.html --format html --concurrency 5

# Analyze from stdin pipe and output CSV
cat urls.txt | threatlens batch - --format csv
```

### Provider Telemetry & Circuit Status
Inspect operational quotas and circuit breaker states:
```bash
threatlens providers
```

### Exit Codes for CI/CD Security Gating
ThreatLens is designed to act as an automated security gate in CI/CD pipelines:
- `0`: All analyzed indicators are `CLEAN` or `LOW_RISK`.
- `1`: Input error, invalid IoC, or missing file.
- `2`: One or more indicators are `MALICIOUS` or `SUSPICIOUS`.

```bash
# Example GitHub Actions or GitLab CI gate:
threatlens lookup $COMMIT_IP || exit $?
```

---

## REST API Reference

Start the API service via CLI or task runner:
```bash
threatlens serve --host 0.0.0.0 --port 8000
# Or: .\tasks.ps1 run
```

Interactive OpenAPI / Swagger documentation is available at:
`http://localhost:8000/docs`

### Endpoints Overview

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/health` | Liveness probe (HTTP 200 with service timestamp) |
| `GET` | `/ready` | Readiness probe (validates database and aggregator readiness) |
| `GET` | `/api/v1/lookup?ioc={ioc}` | Analyze single IoC (supports `refresh` and `include_raw`) |
| `POST` | `/api/v1/lookup/batch` | Bounded concurrent batch analysis (up to 100 IoCs) |
| `GET` | `/api/v1/history?limit={limit}` | Audit history of evaluated indicators in reverse chronological order |
| `GET` | `/api/v1/providers` | Inspect provider health, quotas used/remaining, and circuit states |

### Example cURL Request

```bash
curl -X GET "http://localhost:8000/api/v1/lookup?ioc=185.220.101.5" \
     -H "Accept: application/json"
```

Response:
```json
{
  "ioc": "185.220.101.5",
  "ioc_type": "ipv4",
  "normalized_value": "185.220.101.5",
  "verdict": "malicious",
  "risk_score": 68,
  "score_confidence": 1.0,
  "score_breakdown": [
    {
      "provider": "virustotal",
      "subscore": 33.2,
      "weight": 0.5,
      "contribution": 16.6,
      "reason": "3/74 engines flagged malicious, 1 suspicious (ratio 4.7%)"
    },
    {
      "provider": "otx",
      "subscore": 61.7,
      "weight": 0.25,
      "contribution": 15.4,
      "reason": "5 threat pulses (actors: APT28; malware: Sofacy)"
    },
    {
      "provider": "abuseipdb",
      "subscore": 85.0,
      "weight": 0.25,
      "contribution": 21.2,
      "reason": "85% confidence across 42 reports (strong-signal floor applied: 68)"
    }
  ],
  "providers": [
    {
      "provider": "virustotal",
      "status": "ok",
      "malicious_votes": 3,
      "suspicious_votes": 1,
      "total_engines": 74,
      "confidence": 1.0,
      "reputation": 15,
      "tags": [
        "dns",
        "google"
      ],
      "malware_families": [],
      "threat_actors": [],
      "pulse_count": null,
      "abuse_confidence": null,
      "total_reports": null,
      "geo": {
        "country": "US",
        "asn": 15169,
        "as_owner": "GOOGLE"
      },
      "first_seen": "2011-03-13T07:06:40Z",
      "last_seen": "2023-10-22T18:40:00Z",
      "references": [
        "https://www.virustotal.com/gui/ip-address/185.220.101.5"
      ],
      "latency_ms": 1,
      "error_message": null,
      "raw": null
    },
    {
      "provider": "otx",
      "status": "ok",
      "malicious_votes": null,
      "suspicious_votes": null,
      "total_engines": null,
      "confidence": null,
      "reputation": null,
      "tags": [
        "c2",
        "dns",
        "malware",
        "recon",
        "scanner"
      ],
      "malware_families": [
        "Sofacy"
      ],
      "threat_actors": [
        "APT28"
      ],
      "pulse_count": 5,
      "abuse_confidence": null,
      "total_reports": null,
      "geo": {
        "country": "United States",
        "asn": 15169,
        "as_owner": null
      },
      "first_seen": null,
      "last_seen": null,
      "references": [
        "https://otx.alienvault.com/indicator/ipv4/185.220.101.5"
      ],
      "latency_ms": 0,
      "error_message": null,
      "raw": null
    },
    {
      "provider": "abuseipdb",
      "status": "ok",
      "malicious_votes": null,
      "suspicious_votes": null,
      "total_engines": null,
      "confidence": null,
      "reputation": null,
      "tags": [
        "data center/web hosting/transit"
      ],
      "malware_families": [],
      "threat_actors": [],
      "pulse_count": null,
      "abuse_confidence": 85,
      "total_reports": 42,
      "geo": {
        "country": "RU",
        "asn": null,
        "as_owner": "BadHost Networks"
      },
      "first_seen": null,
      "last_seen": "2026-10-24T12:00:00Z",
      "references": [
        "https://www.abuseipdb.com/check/185.220.101.5"
      ],
      "latency_ms": 0,
      "error_message": null,
      "raw": null
    }
  ],
  "cached": false,
  "generated_at": "2026-10-26T10:01:46Z",
  "ttl_remaining": 21600
}
```

---

## Configuration Reference

All settings can be configured via environment variables or `.env` file:

| Environment Variable | Default | Description |
| :--- | :--- | :--- |
| `THREATLENS_CACHE_DIR` | `./data` | Directory storing SQLite cache and daily quota databases |
| `THREATLENS_API_KEY` | *None* | Optional service API key protecting REST endpoints via `X-API-Key` |
| `THREATLENS_CORS_ORIGINS` | `[]` | Allowed CORS origins as comma-separated string or JSON array (default: none) |
| `THREATLENS_LOG_LEVEL` | `INFO` | Application log level (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |
| `THREATLENS_HOST` | `0.0.0.0` | API server listen host |
| `THREATLENS_PORT` | `8000` | API server listen port |
| `THREATLENS_CLIENT_RATE_LIMIT`| `60` | In-memory token bucket rate limit per client IP (req/min) |
| `THREATLENS_VIRUSTOTAL_API_KEY` | *None* | VirusTotal v3 API key |
| `THREATLENS_VIRUSTOTAL_RPM` | `4` | VirusTotal requests per minute limit |
| `THREATLENS_VIRUSTOTAL_DAILY` | `500` | VirusTotal daily quota |
| `THREATLENS_VIRUSTOTAL_TIMEOUT` | `15.0` | VirusTotal HTTP request timeout (seconds) |
| `THREATLENS_OTX_API_KEY` | *None* | AlienVault OTX API key |
| `THREATLENS_OTX_RPM` | `10` | AlienVault OTX requests per minute limit |
| `THREATLENS_OTX_DAILY` | `1000` | AlienVault OTX daily quota |
| `THREATLENS_OTX_TIMEOUT` | `15.0` | AlienVault OTX HTTP request timeout (seconds) |
| `THREATLENS_ABUSEIPDB_API_KEY` | *None* | AbuseIPDB API key |
| `THREATLENS_ABUSEIPDB_RPM` | `10` | AbuseIPDB requests per minute limit |
| `THREATLENS_ABUSEIPDB_DAILY` | `1000` | AbuseIPDB daily quota |
| `THREATLENS_ABUSEIPDB_TIMEOUT` | `15.0` | AbuseIPDB HTTP request timeout (seconds) |
| `THREATLENS_MAX_RATE_LIMIT_WAIT` | `5.0` | Max wait time before token bucket yields `rate_limited` (seconds) |
| `THREATLENS_CIRCUIT_BREAKER_FAILURE_THRESHOLD` | `5` | Consecutive failures before circuit breaker trips `OPEN` |
| `THREATLENS_CIRCUIT_BREAKER_RECOVERY_TIMEOUT` | `60.0` | Cool-down time before transitioning to `HALF-OPEN` (seconds) |
| `THREATLENS_WEIGHT_VIRUSTOTAL` | `0.50` | Relative scoring weight for VirusTotal |
| `THREATLENS_WEIGHT_OTX` | `0.25` | Relative scoring weight for AlienVault OTX |
| `THREATLENS_WEIGHT_ABUSEIPDB` | `0.25` | Relative scoring weight for AbuseIPDB |
| `THREATLENS_STRONG_SIGNAL_FACTOR` | `0.8` | Floor factor preventing strong evidence dilution |
| `THREATLENS_MIN_CONFIDENCE_FOR_CLEAN` | `0.6` | Minimum confidence required to issue a clean/low-risk verdict |
| `THREATLENS_TTL_MALICIOUS` | `21600` | Cache TTL for malicious verdicts (6 hours, seconds) |
| `THREATLENS_TTL_SUSPICIOUS` | `21600` | Cache TTL for suspicious verdicts (6 hours, seconds) |
| `THREATLENS_TTL_CLEAN` | `86400` | Cache TTL for clean verdicts (24 hours, seconds) |
| `THREATLENS_TTL_LOW_RISK` | `86400` | Cache TTL for low-risk verdicts (24 hours, seconds) |
| `THREATLENS_TTL_UNKNOWN` | `900` | Cache TTL for unknown verdicts (15 minutes, seconds) |

---

## Docker Deployment

ThreatLens includes a production-grade multi-stage `Dockerfile` with non-root security.

```bash
# Build and run with Docker Compose
docker compose up -d

# Inspect service logs
docker compose logs -f

# Stop service
docker compose down
```

---

## Development & Testing

ThreatLens enforces strict quality gates:

```powershell
# Run full Pytest test suite (226+ tests)
.\tasks.ps1 test

# Enforce coverage threshold (>=90%)
.\tasks.ps1 test-cov

# Run Ruff linter and format validation
.\tasks.ps1 lint

# Run strict Mypy type-checking
.\tasks.ps1 type-check

# Run Bandit SAST security scans and pip-audit CVE checks
.\tasks.ps1 security
```

For complete architectural details, see [docs/architecture.md](file:///c:/Users/HP/Desktop/New%20folder%20%282%29/docs/architecture.md).  
For instructions on creating new provider adapters, see [docs/adding-a-provider.md](file:///c:/Users/HP/Desktop/New%20folder%20%282%29/docs/adding-a-provider.md).  
For the algorithmic risk calculation breakdown, see [docs/scoring.md](file:///c:/Users/HP/Desktop/New%20folder%20%282%29/docs/scoring.md).

---

## License

ThreatLens is licensed under the [MIT License](file:///c:/Users/HP/Desktop/New%20folder%20%282%29/LICENSE).
