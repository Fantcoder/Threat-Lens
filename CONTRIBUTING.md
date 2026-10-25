# Contributing to ThreatLens

Thank you for contributing to ThreatLens! We welcome contributions ranging from new threat intelligence providers to performance enhancements and bug fixes.

---

## 1. Development Prerequisites

- **Python**: 3.11 or higher
- **Package Manager**: [uv](https://docs.astral.sh/uv/) (recommended) or pip
- **Task Runner**: `tasks.ps1` (PowerShell on Windows) or `Makefile` (Linux / macOS)
- **Git**: Installed and configured (line endings forced to LF via `.gitattributes`)

---

## 2. Setting Up the Local Environment

### On Windows (PowerShell)
```powershell
# Clone the repository
git clone https://github.com/threatlens/threatlens.git
cd threatlens

# Install dependencies and pre-commit environment via uv
.\tasks.ps1 install

# Copy environment template
Copy-Item .env.example .env
```

### On Linux / macOS (Make)
```bash
# Clone the repository
git clone https://github.com/threatlens/threatlens.git
cd threatlens

# Install dependencies
make install

# Copy environment template
cp .env.example .env
```

---

## 3. Development Workflow & Commands

| Task | PowerShell Command | Unix / Make Command | Description |
| :--- | :--- | :--- | :--- |
| **Lint Check** | `.\tasks.ps1 lint` | `make lint` | Run Ruff linter and format check |
| **Auto-Format** | `.\tasks.ps1 format` | `make format` | Fix formatting and safe linter issues |
| **Type Check** | `.\tasks.ps1 type-check` | `make type-check` | Run strict Mypy validation |
| **Run Tests** | `.\tasks.ps1 test` | `make test` | Run complete Pytest test suite |
| **Enforce Coverage** | `.\tasks.ps1 test-cov` | `make test-cov` | Run tests with $\ge 90\%$ coverage gate |
| **Security Audit** | `.\tasks.ps1 security` | `make security` | Run Bandit SAST & pip-audit scans |
| **Run Dev Server** | `.\tasks.ps1 run` | `make run` | Launch FastAPI at `http://127.0.0.1:8000` |
| **Clean Artifacts** | `.\tasks.ps1 clean` | `make clean` | Remove temporary cache files |

---

## 4. Coding Standards & Guidelines

1. **Type Annotations**:
   - Every function and method must include strict Python type hints.
   - Code must pass `mypy --strict src/` with zero warnings or ignores unless documented.
2. **Zero Live Network Calls in Tests**:
   - Unit and integration tests must strictly mock external HTTP services using `respx` and JSON fixtures located in `tests/fixtures/`.
   - Never place real API tokens in test files.
3. **Line Length & Formatting**:
   - Enforce maximum line length of 100 characters.
   - Use standard Ruff rules configured in `pyproject.toml`.
4. **Error Handling**:
   - Providers must never throw raw HTTP exceptions out of `lookup()`. Return normalized `ProviderResult` objects with appropriate status codes (`"error"`, `"rate_limited"`, `"not_found"`).
5. **Security Gates**:
   - Verify that code passes `bandit -r src/ -c pyproject.toml` without high or medium vulnerabilities.

---

## 5. Pull Request Process

1. Fork the repository and create your feature branch from `master`:
   ```bash
   git checkout -b feature/urlhaus-provider
   ```
2. Ensure all tests, linters, and type checks pass:
   ```powershell
   .\tasks.ps1 lint
   .\tasks.ps1 type-check
   .\tasks.ps1 test-cov
   .\tasks.ps1 security
   ```
3. Commit with concise, descriptive commit messages adhering to Conventional Commits:
   - `feat: add URLhaus provider adapter`
   - `fix: resolve race condition in token bucket refill`
   - `docs: update architecture sequence diagram`
4. Submit a Pull Request targeting `master`.
