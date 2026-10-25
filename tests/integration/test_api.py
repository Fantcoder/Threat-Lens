"""Integration tests for ThreatLens FastAPI endpoints, auth, and logging."""

from __future__ import annotations

import io
import json
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
import pytest
import respx
from httpx import ASGITransport
from pydantic import SecretStr

from threatlens.api.app import create_app
from threatlens.config import Settings
from threatlens.logging import (
    JSONFormatter,
    SecretRedactionFilter,
    register_secret_for_redaction,
)


@pytest.fixture
def app_settings(tmp_path: Path) -> Settings:
    return Settings(
        cache_dir=tmp_path / "data",
        virustotal_api_key=SecretStr("mock_vt_secret"),
        otx_api_key=SecretStr("mock_otx_secret"),
        abuseipdb_api_key=SecretStr("mock_abuse_secret"),
        api_key=None,  # Disabled by default
        client_rate_limit=100,
    )


@pytest.fixture
def auth_settings(tmp_path: Path) -> Settings:
    return Settings(
        cache_dir=tmp_path / "data_auth",
        api_key=SecretStr("super_secret_service_key"),
        client_rate_limit=100,
    )


@asynccontextmanager
async def make_test_client(settings: Settings) -> AsyncIterator[httpx.AsyncClient]:
    """Helper context manager to guarantee FastAPI ASGI lifespan execution."""
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            yield client


# ==============================================================================
# Health and Readiness Endpoints
# ==============================================================================


@pytest.mark.asyncio
async def test_health_endpoint(app_settings: Settings) -> None:
    async with make_test_client(app_settings) as client:
        response = await client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["service"] == "threatlens"
        assert "timestamp" in data
        assert "X-Request-ID" in response.headers


@pytest.mark.asyncio
async def test_readiness_endpoint(app_settings: Settings) -> None:
    async with make_test_client(app_settings) as client:
        response = await client.get("/ready")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ready"


# ==============================================================================
# Threat Intelligence Lookup Endpoints
# ==============================================================================


@pytest.mark.asyncio
@respx.mock
async def test_lookup_valid_ioc(app_settings: Settings, fixtures_dir: Path) -> None:
    # Mock VT, OTX, and AbuseIPDB
    vt_data = json.loads(
        (fixtures_dir / "virustotal" / "ip_success.json").read_text(encoding="utf-8")
    )
    otx_data = json.loads((fixtures_dir / "otx" / "ip_success.json").read_text(encoding="utf-8"))
    abuse_data = json.loads(
        (fixtures_dir / "abuseipdb" / "ip_success.json").read_text(encoding="utf-8")
    )

    respx.get("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8").respond(
        status_code=200, json=vt_data, headers={"content-type": "application/json"}
    )
    respx.get("https://otx.alienvault.com/api/v1/indicators/IPv4/8.8.8.8/general").respond(
        status_code=200, json=otx_data, headers={"content-type": "application/json"}
    )
    respx.get("https://api.abuseipdb.com/api/v2/check").respond(
        status_code=200, json=abuse_data, headers={"content-type": "application/json"}
    )

    async with make_test_client(app_settings) as client:
        resp = await client.get(
            "/api/v1/lookup?ioc=8.8.8.8", headers={"X-Request-ID": "custom-trace-123"}
        )
        assert resp.status_code == 200
        assert resp.headers["X-Request-ID"] == "custom-trace-123"

        data = resp.json()
        assert data["ioc"] == "8.8.8.8"
        assert data["normalized_value"] == "8.8.8.8"
        assert data["verdict"] in ("clean", "low_risk", "suspicious", "malicious")
        assert len(data["providers"]) == 3
        assert len(data["score_breakdown"]) > 0


@pytest.mark.asyncio
async def test_lookup_invalid_ioc(app_settings: Settings) -> None:
    async with make_test_client(app_settings) as client:
        # 1. Non-parseable IoC
        resp1 = await client.get("/api/v1/lookup?ioc=not-a-valid-ioc")
        assert resp1.status_code == 400
        prob1 = resp1.json()
        assert "Invalid IoC" in prob1["title"]
        assert prob1["status"] == 400

        # 2. Private IP address
        resp2 = await client.get("/api/v1/lookup?ioc=192.168.1.1")
        assert resp2.status_code == 400
        prob2 = resp2.json()
        assert "private" in prob2["detail"].lower()


@pytest.mark.asyncio
@respx.mock
async def test_batch_lookup_endpoint(app_settings: Settings, fixtures_dir: Path) -> None:
    vt_data = json.loads(
        (fixtures_dir / "virustotal" / "ip_success.json").read_text(encoding="utf-8")
    )
    respx.get("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8").respond(
        status_code=200, json=vt_data, headers={"content-type": "application/json"}
    )
    respx.get("https://otx.alienvault.com/api/v1/indicators/IPv4/8.8.8.8/general").respond(
        status_code=200, json={"pulse_info": {"count": 0, "pulses": []}}
    )
    respx.get("https://api.abuseipdb.com/api/v2/check").respond(
        status_code=200, json={"data": {"abuseConfidenceScore": 0, "totalReports": 0}}
    )

    async with make_test_client(app_settings) as client:
        payload = {"iocs": ["8.8.8.8", "invalid_ioc", "10.0.0.1"]}
        resp = await client.post("/api/v1/lookup/batch", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 3
        assert data["successful"] == 1
        assert data["failed"] == 2


# ==============================================================================
# History & Providers Endpoints
# ==============================================================================


@pytest.mark.asyncio
async def test_history_and_providers_endpoints(app_settings: Settings) -> None:
    async with make_test_client(app_settings) as client:
        hist_resp = await client.get("/api/v1/history?limit=10")
        assert hist_resp.status_code == 200
        assert isinstance(hist_resp.json(), list)

        prov_resp = await client.get("/api/v1/providers")
        assert prov_resp.status_code == 200
        data = prov_resp.json()
        assert len(data["providers"]) == 3
        names = [p["name"] for p in data["providers"]]
        assert "virustotal" in names
        assert "otx" in names
        assert "abuseipdb" in names


# ==============================================================================
# Authentication & Client Rate Limiting
# ==============================================================================


@pytest.mark.asyncio
async def test_api_authentication(auth_settings: Settings) -> None:
    async with make_test_client(auth_settings) as client:
        # Public health check accessible without key
        health_resp = await client.get("/health")
        assert health_resp.status_code == 200

        # Protected lookup without key -> 401
        unauth_resp = await client.get("/api/v1/history")
        assert unauth_resp.status_code == 401
        assert unauth_resp.json()["title"] == "Unauthorized"

        # Protected lookup with wrong key -> 401
        wrong_resp = await client.get("/api/v1/history", headers={"X-API-Key": "wrong_key"})
        assert wrong_resp.status_code == 401

        # Protected lookup with correct key -> 200
        auth_resp = await client.get(
            "/api/v1/history", headers={"X-API-Key": "super_secret_service_key"}
        )
        assert auth_resp.status_code == 200


@pytest.mark.asyncio
async def test_client_rate_limiting(tmp_path: Path) -> None:
    limited_settings = Settings(
        cache_dir=tmp_path / "data_limit",
        client_rate_limit=2,  # Only 2 requests allowed
    )
    async with make_test_client(limited_settings) as client:
        r1 = await client.get("/api/v1/history")
        assert r1.status_code == 200
        r2 = await client.get("/api/v1/history")
        assert r2.status_code == 200
        # 3rd request trips client rate limit
        r3 = await client.get("/api/v1/history")
        assert r3.status_code == 429
        assert "rate limit" in r3.json()["detail"].lower()


# ==============================================================================
# Secret Redaction Test (Proof that API keys are never logged)
# ==============================================================================


def test_secret_redaction_in_logs() -> None:
    secret_key = "sensitive_super_secret_token_xyz_999"  # noqa: S105
    register_secret_for_redaction(secret_key)

    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JSONFormatter())
    handler.addFilter(SecretRedactionFilter())

    logger = logging.getLogger("threatlens.test_redaction")
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)

    try:
        logger.info(
            "Attempted query with token: %s and direct string sensitive_super_secret_token_xyz_999",
            secret_key,
        )
        handler.flush()
        output = stream.getvalue()

        # The raw secret MUST NEVER appear in the log output
        assert secret_key not in output
        # Must be replaced with the redaction mask
        assert "***REDACTED***" in output
    finally:
        logger.removeHandler(handler)
