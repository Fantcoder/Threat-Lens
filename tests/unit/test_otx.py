"""Unit tests for AlienVault OTX provider using respx mocks."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx

from threatlens.models import IoCType
from threatlens.providers.otx import OTXProvider


@pytest.fixture
def otx_fixtures_dir(fixtures_dir: Path) -> Path:
    return fixtures_dir / "otx"


@pytest.fixture
def provider() -> OTXProvider:
    return OTXProvider(api_key="mock_otx_key", timeout=5.0)


@pytest.mark.asyncio
@respx.mock
async def test_otx_ip_success(provider: OTXProvider, otx_fixtures_dir: Path) -> None:
    fixture_data = json.loads((otx_fixtures_dir / "ip_success.json").read_text(encoding="utf-8"))
    respx.get("https://otx.alienvault.com/api/v1/indicators/IPv4/8.8.8.8/general").respond(
        status_code=200,
        json=fixture_data,
        headers={"content-type": "application/json"},
    )

    async with httpx.AsyncClient() as client:
        result = await provider.lookup("8.8.8.8", IoCType.IPV4, client, include_raw=True)

    assert result.provider == "otx"
    assert result.status == "ok"
    assert result.pulse_count == 5
    assert "dns" in result.tags
    assert "c2" in result.tags
    assert "Sofacy" in result.malware_families
    assert "APT28" in result.threat_actors
    assert result.geo is not None
    assert result.geo.country == "United States"
    assert result.geo.asn == 15169
    assert result.references == ["https://otx.alienvault.com/indicator/ipv4/8.8.8.8"]
    assert result.raw is not None


@pytest.mark.asyncio
@respx.mock
async def test_otx_type_mappings(provider: OTXProvider) -> None:
    respx.get("https://otx.alienvault.com/api/v1/indicators/domain/example.com/general").respond(
        status_code=200,
        json={"pulse_info": {"count": 2, "pulses": []}},
        headers={"content-type": "application/json"},
    )
    respx.get("https://otx.alienvault.com/api/v1/indicators/url/http://bad.com/general").respond(
        status_code=200,
        json={"pulse_info": {"count": 1, "pulses": []}},
        headers={"content-type": "application/json"},
    )
    respx.get("https://otx.alienvault.com/api/v1/indicators/file/e3b0c44/general").respond(
        status_code=200,
        json={"pulse_info": {"count": 0, "pulses": []}},
        headers={"content-type": "application/json"},
    )

    async with httpx.AsyncClient() as client:
        dom_res = await provider.lookup("example.com", IoCType.DOMAIN, client)
        url_res = await provider.lookup("http://bad.com", IoCType.URL, client)
        hash_res = await provider.lookup("e3b0c44", IoCType.SHA256, client)

    assert dom_res.status == "ok"
    assert url_res.status == "ok"
    assert hash_res.status == "ok"


@pytest.mark.asyncio
@respx.mock
async def test_otx_not_found_404(provider: OTXProvider, otx_fixtures_dir: Path) -> None:
    fixture_data = json.loads((otx_fixtures_dir / "not_found.json").read_text(encoding="utf-8"))
    respx.get("https://otx.alienvault.com/api/v1/indicators/IPv4/1.1.1.1/general").respond(
        status_code=404,
        json=fixture_data,
        headers={"content-type": "application/json"},
    )

    async with httpx.AsyncClient() as client:
        result = await provider.lookup("1.1.1.1", IoCType.IPV4, client)

    assert result.status == "not_found"
    assert "otx.alienvault.com/indicator/ipv4/1.1.1.1" in result.references[0]


@pytest.mark.asyncio
@respx.mock
async def test_otx_rate_limited_429(provider: OTXProvider) -> None:
    respx.get("https://otx.alienvault.com/api/v1/indicators/IPv4/1.1.1.1/general").respond(
        status_code=429,
        text="Too Many Requests",
    )

    async with httpx.AsyncClient() as client:
        result = await provider.lookup("1.1.1.1", IoCType.IPV4, client)

    assert result.status == "rate_limited"
    assert "429" in (result.error_message or "")


@pytest.mark.asyncio
@respx.mock
async def test_otx_server_error_and_unexpected(provider: OTXProvider) -> None:
    respx.get("https://otx.alienvault.com/api/v1/indicators/IPv4/1.1.1.1/general").respond(
        status_code=502,
        text="Bad Gateway",
    )
    respx.get("https://otx.alienvault.com/api/v1/indicators/IPv4/2.2.2.2/general").respond(
        status_code=401,
        text="Unauthorized",
    )

    async with httpx.AsyncClient() as client:
        err_res = await provider.lookup("1.1.1.1", IoCType.IPV4, client)
        unexp_res = await provider.lookup("2.2.2.2", IoCType.IPV4, client)

    assert err_res.status == "error"
    assert "502" in (err_res.error_message or "")
    assert unexp_res.status == "error"
    assert "401" in (unexp_res.error_message or "")


@pytest.mark.asyncio
@respx.mock
async def test_otx_malformed_json(provider: OTXProvider) -> None:
    respx.get("https://otx.alienvault.com/api/v1/indicators/IPv4/1.1.1.1/general").respond(
        status_code=200,
        text="not json",
        headers={"content-type": "application/json"},
    )

    async with httpx.AsyncClient() as client:
        result = await provider.lookup("1.1.1.1", IoCType.IPV4, client)

    assert result.status == "error"
    assert "JSON" in (result.error_message or "")


@pytest.mark.asyncio
@respx.mock
async def test_otx_timeout_and_network_error(provider: OTXProvider) -> None:
    respx.get("https://otx.alienvault.com/api/v1/indicators/IPv4/1.1.1.1/general").mock(
        side_effect=httpx.TimeoutException("Read timeout")
    )
    respx.get("https://otx.alienvault.com/api/v1/indicators/IPv4/2.2.2.2/general").mock(
        side_effect=httpx.ConnectError("Failed to connect")
    )

    async with httpx.AsyncClient() as client:
        timeout_res = await provider.lookup("1.1.1.1", IoCType.IPV4, client)
        conn_res = await provider.lookup("2.2.2.2", IoCType.IPV4, client)

    assert timeout_res.status == "error"
    assert "timed out" in (timeout_res.error_message or "").lower()
    assert conn_res.status == "error"
    assert "network error" in (conn_res.error_message or "").lower()


@pytest.mark.asyncio
async def test_otx_missing_api_key() -> None:
    provider = OTXProvider(api_key=None)
    async with httpx.AsyncClient() as client:
        result = await provider.lookup("8.8.8.8", IoCType.IPV4, client)

    assert result.status == "skipped"
    assert "not configured" in (result.error_message or "")


@pytest.mark.asyncio
async def test_otx_unsupported_type() -> None:
    provider = OTXProvider(api_key="key")
    provider.supported_types = frozenset()  # type: ignore[assignment]
    async with httpx.AsyncClient() as client:
        result = await provider.lookup("8.8.8.8", IoCType.IPV4, client)

    assert result.status == "unsupported"
