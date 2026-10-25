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

---

## 2. Needs Verification on Your Machine (UNVERIFIED in sandbox)

- **`make` command**: `make` is not installed on this sandbox Windows image (`tasks.ps1` provided and tested). If you have `make` installed (e.g. via Scoop/Chocolatey/MSYS2), verify `make install` and `make test`.
- **Real Provider API Lookups**: Live calls to VirusTotal, AlienVault OTX, and AbuseIPDB require real API keys. In this repo, all tests strictly use recorded fixtures and `respx` mocks.
- **Docker Multi-Stage Build & Container Run**: Needs verification on your machine via `docker compose up --build`.
- **GitHub Actions Workflows**: `.github/workflows/ci.yml` and `.github/workflows/security.yml` (Trivy, CodeQL, Gitleaks, Dependabot) run in GitHub runner infrastructure.
