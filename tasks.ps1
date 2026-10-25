<#
.SYNOPSIS
    ThreatLens Task Runner for PowerShell (Windows).
    Mirrors Makefile commands.

.EXAMPLE
    .\tasks.ps1 install
    .\tasks.ps1 test
    .\tasks.ps1 lint
#>

param (
    [Parameter(Position=0, Mandatory=$false)]
    [ValidateSet("help", "install", "lock", "lint", "format", "type-check", "test", "test-cov", "security", "run", "clean", "docker-build", "docker-up", "docker-down")]
    [string]$Task = "help"
)

$ErrorActionPreference = "Stop"

function Show-Help {
    Write-Host "ThreatLens PowerShell Task Runner commands:" -ForegroundColor Cyan
    Write-Host "  .\tasks.ps1 install       Install all dependencies (including dev) using uv"
    Write-Host "  .\tasks.ps1 lock          Generate or update uv.lock"
    Write-Host "  .\tasks.ps1 lint          Run ruff lint check and format check"
    Write-Host "  .\tasks.ps1 format        Auto-format code with ruff"
    Write-Host "  .\tasks.ps1 type-check    Run strict mypy type checking"
    Write-Host "  .\tasks.ps1 test          Run pytest suite"
    Write-Host "  .\tasks.ps1 test-cov      Run pytest with coverage enforcement (>=90%)"
    Write-Host "  .\tasks.ps1 security      Run bandit SAST and pip-audit vulnerability scans"
    Write-Host "  .\tasks.ps1 run           Run FastAPI dev server via uvicorn"
    Write-Host "  .\tasks.ps1 clean         Remove cache and temporary build files"
    Write-Host "  .\tasks.ps1 docker-build  Build Docker image"
    Write-Host "  .\tasks.ps1 docker-up     Start service via docker compose"
    Write-Host "  .\tasks.ps1 docker-down   Stop service via docker compose"
}

switch ($Task) {
    "help" { Show-Help }
    "install" {
        uv sync --all-extras --python 3.11
    }
    "lock" {
        uv lock
    }
    "lint" {
        uv run ruff check src/ tests/
        uv run ruff format --check src/ tests/
    }
    "format" {
        uv run ruff format src/ tests/
        uv run ruff check --fix src/ tests/
    }
    "type-check" {
        uv run mypy src/
    }
    "test" {
        uv run pytest
    }
    "test-cov" {
        uv run pytest --cov=src/threatlens --cov-report=term-missing --cov-fail-under=90
    }
    "security" {
        uv run bandit -r src/ -c pyproject.toml
        uv run pip-audit
    }
    "run" {
        uv run uvicorn threatlens.api.app:create_app --factory --host 0.0.0.0 --port 8000 --reload
    }
    "clean" {
        Get-ChildItem -Path . -Include .pytest_cache, .ruff_cache, .mypy_cache, htmlcov, dist, build, *.egg-info -Directory -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force
        Get-ChildItem -Path . -Filter __pycache__ -Directory -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force
        Get-ChildItem -Path . -Filter "*.pyc" -File -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Force
        Remove-Item -Path .coverage, coverage.xml -Force -ErrorAction SilentlyContinue
        Write-Host "Clean completed." -ForegroundColor Green
    }
    "docker-build" {
        docker build -t threatlens:latest .
    }
    "docker-up" {
        docker compose up -d
    }
    "docker-down" {
        docker compose down
    }
}
