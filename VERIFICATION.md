# ThreatLens Verification Matrix

This document tracks verification status across build phases. In accordance with safety and sandbox limits:
- **Verified here**: Features, tests, linters, and commands executed in the current environment with verified outputs.
- **Needs verification on your machine**: Features requiring real external API keys, Docker daemon running with privileged containerization, or external CI service execution (Trivy, CodeQL, GitHub Actions).

---

## 1. Verified Here (with command output)

### Phase 1: Environment Capability & Scaffolding
- **Python version**: Python 3.11.9 (`python --version`)
- **pip version**: pip 26.0.1 (`pip --version`)
- **uv version**: uv 0.10.9 (`uv --version`)
- **Git version**: git version 2.51.1.windows.1 (`git --version`)
- **PyPI & Outbound HTTPS connectivity**: Confirmed reachable (HTTP 200)
- **Repository Structure**: Initialized git repo with `.gitattributes` (LF endings), `.gitignore`, `pyproject.toml`, `README.md`, `Makefile`, `tasks.ps1`, `.env.example`.
- **Workflow YAML syntax validation**: Passed with PyYAML (`dependabot.yml`, `ci.yml`, `security.yml`).

### Phase 2: Core Models & IoC Detector
- **Ruff check & format**: `uv run ruff check src/ tests/` (All checks passed, 0 errors)
- **Mypy strict check**: `uv run mypy src/` (Success: no issues found in 7 source files)
- **Test suite**: 106 tests passed in 5.62s (`uv run pytest`)
  - 40+ concrete example tests covering public IPv4, IPv6, MD5, SHA1, SHA256, FQDNs, URLs.
  - Strict rejection of private/loopback/reserved IPv4 & IPv6 (`127.0.0.1`, `10.0.0.1`, `192.168.1.1`, `172.16.0.1`, `169.254.169.254`, `::1`, `fc00::`, `fe80::`).
  - Refanging engine verified on `hxxp://`, `hxxps://`, `[.]`, `(.)`, `[dot]`, `[:]`.
  - Hypothesis property tests for IPv4 generation, MD5, SHA1, SHA256, and domain regex generation.
- **Coverage**: 100.00% on `detector.py`, `models.py`, `config.py`, and `errors.py`.

### Phase 3: Providers (Base, VirusTotal, AlienVault OTX, AbuseIPDB)
- **Ruff check & format**: `uv run ruff check src/ tests/` (All checks passed, 0 errors)
- **Mypy strict check**: `uv run mypy src/` (Success: no issues found in 11 source files)
- **Test suite**: 134 tests passed in 11.96s (`uv run pytest`)
  - All tests use `respx` with recorded sample JSON fixtures.
  - Zero live network calls made.
  - Test matrix verified for all 3 providers: 200 (ok), 404 (not_found), 429 (rate_limited), 5xx (error), timeout (error), network error (error), malformed JSON (error), missing API key (skipped), unsupported type (unsupported).
  - AbuseIPDB strictly rejects non-IP types without making network calls.
  - VirusTotal v3 URL ID unpadded base64 encoding verified.
- **Coverage**: 97.59% total across codebase. Base provider is 100%, VirusTotal 98%, OTX 97%, AbuseIPDB 90%.

### Phase 4: Rate Limiter, Daily Quota, Circuit Breaker & Retries
- **Ruff check & format**: `uv run ruff check src/ tests/` (All checks passed, 0 errors)
- **Mypy strict check**: `uv run mypy src/` (Success: no issues found in 12 source files)
- **Test suite**: 143 tests passed in 11.50s (`uv run pytest`)
  - TokenBucket: acquire, lazy refill, depletion, and bounded wait time verified with `FakeClock`.
  - DailyQuotaTracker: SQLite persistence verified across separate instances; UTC midnight rollover verified.
  - CircuitBreaker: CLOSED -> OPEN after failure threshold; recovery timeout transition to HALF_OPEN; single failure in HALF_OPEN trips to OPEN; success in HALF_OPEN resets to CLOSED.
  - Retries: Tenacity exponential backoff with jitter and `Retry-After` header extraction verified.
- **Coverage**: 100.00% on `ratelimit.py` (125/125 statements). Total repo coverage: 98.07%.

### Phase 5: Explainable Scoring Engine
- **Ruff check & format**: `uv run ruff check src/ tests/` (All checks passed, 0 errors)
- **Mypy strict check**: `uv run mypy src/` (Success: no issues found in 13 source files)
- **Test suite**: 164 tests passed in 11.59s (`uv run pytest`)
  - Subscore calculations for VirusTotal (nonlinear curve + malware tag bonus), OTX (log curve + threat actor/malware bonus), and AbuseIPDB (raw confidence + low report damping).
  - Dynamic weight renormalization verified when providers fail or are skipped.
  - Verdict threshold boundaries tested: clean (0-9), low_risk (10-34), suspicious (35-64), malicious (65-100), unknown.
  - Explainable `score_breakdown` audit reason verified for each provider.
- **Coverage**: 100.00% branch coverage on `scoring.py` (99/99 statements, 44/44 branches, 0 missed). Total repo coverage: 98.34%.
- **Documentation**: Detailed algorithmic specification written to `docs/scoring.md`.

### Phase 6: Aggregator, Cache & Request Coalescing
- **Ruff check & format**: `uv run ruff check src/ tests/` (All checks passed, 0 errors)
- **Mypy strict check**: `uv run mypy src/` (Success: no issues found in 15 source files)
- **Test suite**: 176 tests passed in 14.32s (`uv run pytest`)
  - Cache: SQLite table creation, indexing, TTL remaining calculation, put/get, audit history logging, and safe cleanup of expired entries verified.
  - Request Coalescing: Proven that concurrent lookups for identical IoCs share one in-flight upstream execution via `asyncio.Future`.
  - Resilience integration: Quota exhaustion, circuit breaker open state, and provider exception isolation tested.
- **Coverage**: `cache.py` 100.00%, `aggregator.py` 91.49%. Total repo coverage: 97.77%.

### Phase 7: FastAPI REST Service & Structured Logging
- **Ruff check & format**: `uv run ruff check src/ tests/` (All checks passed, 0 errors, 35 files clean)
- **Mypy strict check**: `uv run mypy src/` (Success: no issues found in 19 source files)
- **Test suite**: 185 tests passed in 18.38s (`uv run pytest`)
  - Endpoints: `/health` (liveness), `/ready` (dependency readiness), `/api/v1/lookup` (single IoC query), `/api/v1/lookup/batch` (bounded concurrency semaphore), `/api/v1/history` (audit logs), `/api/v1/providers` (telemetry, quota, circuit states).
  - RFC 7807 Problem Details: Standardized error envelopes across 400 (Invalid IoC), 401 (Unauthorized), 404 (Not Found), 429 (Rate Limit Exceeded), and 500 (Internal Server Error).
  - Middleware: Correlated request IDs (`X-Request-ID`), structured JSON log emission with latency tracking.
  - Security: Timing-safe API Key authentication (`hmac.compare_digest`) via `X-API-Key`.
  - In-memory token-bucket client rate limiting with 429 response.
  - Secret Redaction: Automated `SecretRedactionFilter` guarantees raw API keys never leak into logs.
- **Coverage**: `api/routes.py` 96.67%, `api/app.py` 91.43%, `schemas.py` 100.00%, `logging.py` 86.96%. Total repo coverage: 96.78%.

### Phase 8: Typer CLI & Multi-Format Report Generator
- **Ruff check & format**: `uv run ruff check src/ tests/` (All checks passed, 0 errors, 39 files clean)
- **Mypy strict check**: `uv run mypy src/` (Success: no issues found in 21 source files)
- **Test suite**: 202 tests passed in 21.22s (`uv run pytest`)
  - Multi-Format Reports (`src/threatlens/report.py`):
    - `JSON`: Structured nested representation of full report or list of reports.
    - `CSV`: Flattened 17-column format compatible with Splunk, ELK, Excel, and SIEM ingest.
    - `Markdown`: GitHub-flavored markdown with summary badges, indicator matrix, and provider explanation breakdown.
    - `HTML`: Self-contained, responsive cybersecurity dashboard in dark palette (`#0a0e17`), KPI stat cards, sortable table via vanilla JS, live search filter, and collapsible details drawer with zero CDN dependencies.
    - Scalability: Batch of 50 synthetic indicators verified across all 4 formats.
  - Typer CLI (`src/threatlens/cli.py`):
    - `threatlens lookup <ioc>`: Pretty-printed Rich panel, colored verdict chips, breakdown table, and exit code 2 on threats (0 on clean/low risk, 1 on invalid IoC).
    - `threatlens batch <file_or_stdin>`: Bounded concurrency, Rich progress bar, multi-format export to stdout or destination file.
    - `threatlens providers`: Real-time telemetry table with quota usage, daily limit, and circuit breaker states (CLOSED/OPEN/HALF_OPEN).
    - `threatlens serve`: Development/production Uvicorn launcher.
- **Coverage**: `report.py` 98.12%, `cli.py` 85.63%. Total repo coverage: 95.72%.

### Phase 9: Containerization & Docker Compose
- **Dockerfile**: Hardened multi-stage build updated with `WORKDIR /app` across both stages, `uv sync --frozen --no-dev --no-editable` to compile the package directly into site-packages, non-root user `threatlens` (UID 10001), healthcheck against `/health`, and non-privileged volume mount `/app/data`.
- **Venv Relocation Verified**: Replicated venv relocation scenario; proved that default editable install created `.pth` pointing to build directory which failed with `ModuleNotFoundError: No module named 'threatlens'` upon build directory removal. Proved that `--no-editable` installs package into site-packages and imports successfully without `src/`.
- **.dockerignore**: Configured to exclude `.git`, caches, test suites, `.env`, and local SQLite artifacts.
- **docker-compose.yml**: Validated with PyYAML parser; includes persistent `./data` volume mapping, automatic restart policy, healthcheck, and optional `.env` secret injection.

### Phase 10: Security Audits & Portfolio Documentation
- **Bandit SAST**: `uv run bandit -r src/ -c pyproject.toml` passed with 0 issues (`No issues identified`, 0 Medium, 0 High).
- **pip-audit Vulnerability Scan**: `uv run pip-audit` passed with 0 vulnerabilities (`No known vulnerabilities found`).
- **Full Test Suite & Quality Enforcement**:
  - `uv run pytest`: 202 passed in 21.04s.
  - Overall coverage: 95.72% (enforced $\ge 90\%$).
  - `scoring.py`: 100.00% branch coverage (44/44 branches).
  - `detector.py`: 100.00% statement coverage.
  - `ratelimit.py`, `cache.py`, `models.py`, `config.py`: 100.00% coverage.
  - `uv run ruff check src/ tests/`: All checks passed.
  - `uv run ruff format --check src/ tests/`: 39 files formatted.
  - `uv run mypy src/`: Strict type check passed across 21 source files.
- **Documentation Suite**:
  - `README.md`: Complete portfolio documentation, Mermaid architecture diagram, 3-step Quickstart, CLI examples, API cURL reference, configuration table, and scoring formula summary.
  - `docs/architecture.md`: Detailed system architecture, component diagram, request lifecycle sequence diagram, and in-depth writeup of distributed systems trade-offs.
  - `docs/adding-a-provider.md`: Step-by-step developer tutorial with complete worked URLhaus implementation.
  - `docs/scoring.md`: Algorithmic and mathematical scoring specification.
  - `CONTRIBUTING.md`, `SECURITY.md`, `LICENSE` (MIT), `CHANGELOG.md`.
  - `RESUME_BULLETS.md`: Metric-backed resume bullets and 60-second technical interview elevator pitch.

---

## 2. Needs Verification on Your Machine (UNVERIFIED in sandbox)

- **Docker Multi-Stage Build & Container Run (UNVERIFIED)**: Docker Desktop daemon is stopped in this sandbox (`failed to connect to the docker API at npipe:////./pipe/dockerDesktopLinuxEngine`). Test on your machine with `docker compose up --build` or `.\tasks.ps1 docker-up`.
- **`make` command (UNVERIFIED)**: `make` is not installed on this sandbox Windows image (`tasks.ps1` provided and tested). If you have `make` installed (e.g. via Scoop/Chocolatey/MSYS2), verify `make install` and `make test`.
- **Real Provider API Lookups (UNVERIFIED)**: Live calls to VirusTotal, AlienVault OTX, and AbuseIPDB require real API keys in `.env`. In this repo, all tests strictly use recorded fixtures and `respx` mocks.
- **GitHub Actions Workflows (UNVERIFIED)**: `.github/workflows/ci.yml` and `.github/workflows/security.yml` (Trivy container scanning, CodeQL SAST, Bandit, Pip-audit, Dependabot) run in GitHub runner infrastructure upon push.


