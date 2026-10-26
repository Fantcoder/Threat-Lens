# syntax=docker/dockerfile:1
# Multi-stage production Dockerfile for ThreatLens
# Stage 1: Build virtualenv with uv
# Stage 2: Minimal hardened runtime image with non-root user

# ==============================================================================
# Builder Stage
# ==============================================================================
FROM python:3.11-slim AS builder

# Install uv binary from official image
COPY --from=ghcr.io/astral-sh/uv:0.10.9 /uv /bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Copy dependency manifests first for layer caching
COPY pyproject.toml README.md ./
COPY uv.lock ./

# Install dependencies into /app/.venv without development tools
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-project

# Copy source tree and install project into site-packages (non-editable)
COPY src/ ./src/
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-editable

# ==============================================================================
# Runtime Stage
# ==============================================================================
FROM python:3.11-slim AS runtime

# Security: Remove unused build tools (pip, setuptools, wheel) from base image system site-packages
# to eliminate vendored vulnerabilities (CVE-2026-23949, CVE-2026-24049). ThreatLens runs
# entirely within its isolated virtual environment in /app/.venv.
RUN rm -rf /usr/local/lib/python3.11/site-packages/*

# Security: Create non-root system user and group (UID/GID 10001)
RUN groupadd -r threatlens -g 10001 && \
    useradd -u 10001 -r -g threatlens -s /sbin/nologin -d /app threatlens

# Set working directory and create data directory owned by threatlens user
WORKDIR /app
RUN mkdir -p /app/data && chown -R threatlens:threatlens /app

# Copy isolated virtual environment containing site-packages package from builder stage
COPY --from=builder --chown=threatlens:threatlens /app/.venv /app/.venv

# Set environment paths and runtime configurations
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    THREATLENS_CACHE_DIR=/app/data \
    THREATLENS_HOST=0.0.0.0 \
    THREATLENS_PORT=8000

# Drop privileges to non-root user
USER threatlens

# Expose HTTP port
EXPOSE 8000

# Health check probe against /health endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')" || exit 1

# Default entrypoint starts Uvicorn REST service
ENTRYPOINT ["uvicorn", "threatlens.api.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
