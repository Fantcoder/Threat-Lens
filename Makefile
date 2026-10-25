# ThreatLens Task Runner (Makefile)
# Mirrors tasks.ps1 for Unix/Linux/macOS or environments with make installed.

.PHONY: help install lock lint format type-check test test-cov security run clean docker-build docker-up docker-down

PYTHON ?= python
UV ?= uv

help:
	@echo "ThreatLens Makefile commands:"
	@echo "  make install       Install all dependencies (including dev) using uv"
	@echo "  make lock          Generate or update uv.lock"
	@echo "  make lint          Run ruff lint check and format check"
	@echo "  make format        Auto-format code with ruff"
	@echo "  make type-check    Run strict mypy type checking"
	@echo "  make test          Run pytest suite"
	@echo "  make test-cov      Run pytest with coverage enforcement (>=90%)"
	@echo "  make security      Run bandit SAST and pip-audit vulnerability scans"
	@echo "  make run           Run FastAPI dev server via uvicorn"
	@echo "  make clean         Remove cache and temporary build files"
	@echo "  make docker-build  Build Docker image"
	@echo "  make docker-up     Start service via docker compose"
	@echo "  make docker-down   Stop service via docker compose"

install:
	$(UV) sync --all-extras

lock:
	$(UV) lock

lint:
	$(UV) run ruff check src/ tests/
	$(UV) run ruff format --check src/ tests/

format:
	$(UV) run ruff format src/ tests/
	$(UV) run ruff check --fix src/ tests/

type-check:
	$(UV) run mypy src/

test:
	$(UV) run pytest

test-cov:
	$(UV) run pytest --cov=src/threatlens --cov-report=term-missing --cov-fail-under=90

security:
	$(UV) run bandit -r src/ -c pyproject.toml
	$(UV) run pip-audit

run:
	$(UV) run uvicorn threatlens.api.app:create_app --factory --host 0.0.0.0 --port 8000 --reload

clean:
	rm -rf .pytest_cache .ruff_cache .mypy_cache htmlcov .coverage coverage.xml dist build *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

docker-build:
	docker build -t threatlens:latest .

docker-up:
	docker compose up -d

docker-down:
	docker compose down
