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

---

## 2. Needs Verification on Your Machine (UNVERIFIED in sandbox)

- **`make` command**: `make` is not installed on this sandbox Windows image (`tasks.ps1` provided and tested). If you have `make` installed (e.g. via Scoop/Chocolatey/MSYS2), verify `make install` and `make test`.
- **Real Provider API Lookups**: Live calls to VirusTotal, AlienVault OTX, and AbuseIPDB require real API keys. In this repo, all tests strictly use recorded fixtures and `respx` mocks.
- **Docker Multi-Stage Build & Container Run**: Needs verification on your machine via `docker compose up --build`.
- **GitHub Actions Workflows**: `.github/workflows/ci.yml` and `.github/workflows/security.yml` (Trivy, CodeQL, Gitleaks, Dependabot) run in GitHub runner infrastructure.
