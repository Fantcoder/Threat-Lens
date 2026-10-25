"""Unit tests for AbuseIPDB provider using respx mocks."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx

from threatlens.models import IoCType
from threatlens.providers.abuseipdb import AbuseIPDBProvider


@pytest.fixture
def abuseipdb_fixtures_dir(fixtures_dir: Path) -> Path:
    return fixtures_dir / "abuseipdb"


@pytest.fixture
def provider() -> AbuseIPDBProvider:
    return AbuseIPDBProvider(api_key="mock_abuseipdb_key", timeout=5.0)


@pytest.mark.asyncio
@respx.mock
async def test_abuseipdb_success(provider: AbuseIPDBProvider, abuseipdb_fixtures_dir: Path) -> None:
    fixture_data = json.loads(
        (abuseipdb_fixtures_dir / "ip_success.json").read_text(encoding="utf-8")
    )
    respx.get("https://api.abuseipdb.com/api/v2/check").respond(
        status_code=200,
        json=fixture_data,
        headers={"content-type": "application/json"},
    )

    async with httpx.AsyncClient() as client:
        result = await provider.lookup("1.2.3.4", IoCType.IPV4, client, include_raw=True)

    assert result.provider == "abuseipdb"
    assert result.status == "ok"
    assert result.abuse_confidence == 85
    assert result.total_reports == 42
    assert result.geo is not None
    assert result.geo.country == "RU"
    assert result.geo.as_owner == "BadHost Networks"
    assert "data center/web hosting/transit" in result.tags
    assert result.references == ["https://www.abuseipdb.com/check/1.2.3.4"]
    assert result.raw is not None


@pytest.mark.asyncio
async def test_abuseipdb_unsupported_non_ip(provider: AbuseIPDBProvider) -> None:
    # Domains, URLs, and Hashes should return unsupported without network calls
    async with httpx.AsyncClient() as client:
        dom_res = await provider.lookup("evil.com", IoCType.DOMAIN, client)
        hash_res = await provider.lookup("e3b0c44", IoCType.SHA256, client)
        url_res = await provider.lookup("http://bad.com", IoCType.URL, client)

    assert dom_res.status == "unsupported"
    assert hash_res.status == "unsupported"
    assert url_res.status == "unsupported"


@pytest.mark.asyncio
@respx.mock
async def test_abuseipdb_not_found_404(
    provider: AbuseIPDBProvider, abuseipdb_fixtures_dir: Path
) -> None:
    fixture_data = json.loads(
        (abuseipdb_fixtures_dir / "not_found.json").read_text(encoding="utf-8")
    )
    respx.get("https://api.abuseipdb.com/api/v2/check").respond(
        status_code=404,
        json=fixture_data,
        headers={"content-type": "application/json"},
    )

    async with httpx.AsyncClient() as client:
        result = await provider.lookup("1.1.1.1", IoCType.IPV4, client)

    assert result.status == "not_found"
    assert result.references == ["https://www.abuseipdb.com/check/1.1.1.1"]


@pytest.mark.asyncio
@respx.mock
async def test_abuseipdb_rate_limited_429(provider: AbuseIPDBProvider) -> None:
    respx.get("https://api.abuseipdb.com/api/v2/check").respond(
        status_code=429,
        text="Rate limit exceeded",
    )

    async with httpx.AsyncClient() as client:
        result = await provider.lookup("1.1.1.1", IoCType.IPV4, client)

    assert result.status == "rate_limited"
    assert "429" in (result.error_message or "")


@pytest.mark.asyncio
@respx.mock
async def test_abuseipdb_server_error_and_unexpected(provider: AbuseIPDBProvider) -> None:
    respx.get("https://api.abuseipdb.com/api/v2/check").respond(
        status_code=503,
        text="Service Unavailable",
    )

    async with httpx.AsyncClient() as client:
        err_res = await provider.lookup("1.1.1.1", IoCType.IPV4, client)

    assert err_res.status == "error"
    assert "503" in (err_res.error_message or "")


@pytest.mark.asyncio
@respx.mock
async def test_abuseipdb_malformed_json(provider: AbuseIPDBProvider) -> None:
    respx.get("https://api.abuseipdb.com/api/v2/check").respond(
        status_code=200,
        text="invalid json string",
        headers={"content-type": "application/json"},
    )

    async with httpx.AsyncClient() as client:
        result = await provider.lookup("1.1.1.1", IoCType.IPV4, client)

    assert result.status == "error"
    assert "JSON" in (result.error_message or "")


@pytest.mark.asyncio
@respx.mock
async def test_abuseipdb_timeout_and_network_error(provider: AbuseIPDBProvider) -> None:
    respx.get("https://api.abuseipdb.com/api/v2/check").mock(
        side_effect=httpx.TimeoutException("Timeout")
    )

    async with httpx.AsyncClient() as client:
        result = await provider.lookup("1.1.1.1", IoCType.IPV4, client)

    assert result.status == "error"
    assert "timed out" in (result.error_message or "").lower()


@pytest.mark.asyncio
async def test_abuseipdb_missing_api_key() -> None:
    provider = AbuseIPDBProvider(api_key=None)
    assert provider.is_configured() is False
    async with httpx.AsyncClient() as client:
        result = await provider.lookup("8.8.8.8", IoCType.IPV4, client)

    assert result.status == "skipped"
    assert "not configured" in (result.error_message or "")
