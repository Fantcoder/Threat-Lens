"""Unit tests for VirusTotal v3 provider using respx mocks."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx

from threatlens.models import IoCType
from threatlens.providers.virustotal import VirusTotalProvider


@pytest.fixture
def vt_fixtures_dir(fixtures_dir: Path) -> Path:
    return fixtures_dir / "virustotal"


@pytest.fixture
def provider() -> VirusTotalProvider:
    return VirusTotalProvider(api_key="mock_vt_key", timeout=5.0)


@pytest.mark.asyncio
@respx.mock
async def test_virustotal_ip_success(provider: VirusTotalProvider, vt_fixtures_dir: Path) -> None:
    fixture_data = json.loads((vt_fixtures_dir / "ip_success.json").read_text(encoding="utf-8"))
    respx.get("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8").respond(
        status_code=200,
        json=fixture_data,
        headers={"content-type": "application/json"},
    )

    async with httpx.AsyncClient() as client:
        result = await provider.lookup("8.8.8.8", IoCType.IPV4, client, include_raw=True)

    assert result.provider == "virustotal"
    assert result.status == "ok"
    assert result.malicious_votes == 3
    assert result.total_engines == 74  # 68+3+1+2
    assert result.confidence == 1.0
    assert result.reputation == 15
    assert result.geo is not None
    assert result.geo.country == "US"
    assert result.geo.asn == 15169
    assert result.geo.as_owner == "GOOGLE"
    assert "dns" in result.tags
    assert result.references == ["https://www.virustotal.com/gui/ip-address/8.8.8.8"]
    assert result.raw is not None


@pytest.mark.asyncio
@respx.mock
async def test_virustotal_file_success(provider: VirusTotalProvider, vt_fixtures_dir: Path) -> None:
    file_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    fixture_data = json.loads((vt_fixtures_dir / "file_success.json").read_text(encoding="utf-8"))
    respx.get(f"https://www.virustotal.com/api/v3/files/{file_hash}").respond(
        status_code=200,
        json=fixture_data,
        headers={"content-type": "application/json"},
    )

    async with httpx.AsyncClient() as client:
        result = await provider.lookup(file_hash, IoCType.SHA256, client)

    assert result.status == "ok"
    assert result.malicious_votes == 10
    assert result.total_engines == 78
    assert result.reputation == -5
    assert "trojan" in result.tags
    assert result.references == [f"https://www.virustotal.com/gui/file/{file_hash}"]


@pytest.mark.asyncio
@respx.mock
async def test_virustotal_url_and_domain_mapping(provider: VirusTotalProvider) -> None:
    # Test URL ID base64 encoding without padding
    url = "https://example.com/bad"
    url_id = provider.encode_url_id(url)
    assert "=" not in url_id

    respx.get(f"https://www.virustotal.com/api/v3/urls/{url_id}").respond(
        status_code=200,
        json={"data": {"attributes": {"last_analysis_stats": {"malicious": 1}}}},
        headers={"content-type": "application/json"},
    )
    respx.get("https://www.virustotal.com/api/v3/domains/example.com").respond(
        status_code=200,
        json={"data": {"attributes": {"last_analysis_stats": {"malicious": 0}}}},
        headers={"content-type": "application/json"},
    )

    async with httpx.AsyncClient() as client:
        url_res = await provider.lookup(url, IoCType.URL, client)
        dom_res = await provider.lookup("example.com", IoCType.DOMAIN, client)

    assert url_res.status == "ok"
    assert url_res.malicious_votes == 1
    assert dom_res.status == "ok"
    assert dom_res.malicious_votes == 0


@pytest.mark.asyncio
@respx.mock
async def test_virustotal_not_found_404(
    provider: VirusTotalProvider, vt_fixtures_dir: Path
) -> None:
    fixture_data = json.loads((vt_fixtures_dir / "not_found.json").read_text(encoding="utf-8"))
    respx.get("https://www.virustotal.com/api/v3/ip_addresses/1.1.1.1").respond(
        status_code=404,
        json=fixture_data,
        headers={"content-type": "application/json"},
    )

    async with httpx.AsyncClient() as client:
        result = await provider.lookup("1.1.1.1", IoCType.IPV4, client)

    assert result.status == "not_found"
    assert result.malicious_votes is None
    assert "virustotal.com/gui/ip-address/1.1.1.1" in result.references[0]


@pytest.mark.asyncio
@respx.mock
async def test_virustotal_rate_limited_429(
    provider: VirusTotalProvider, vt_fixtures_dir: Path
) -> None:
    fixture_data = json.loads((vt_fixtures_dir / "rate_limited.json").read_text(encoding="utf-8"))
    respx.get("https://www.virustotal.com/api/v3/ip_addresses/1.1.1.1").respond(
        status_code=429,
        json=fixture_data,
        headers={"content-type": "application/json"},
    )

    async with httpx.AsyncClient() as client:
        result = await provider.lookup("1.1.1.1", IoCType.IPV4, client)

    assert result.status == "rate_limited"
    assert "429" in (result.error_message or "")


@pytest.mark.asyncio
@respx.mock
async def test_virustotal_server_error_500(provider: VirusTotalProvider) -> None:
    respx.get("https://www.virustotal.com/api/v3/ip_addresses/1.1.1.1").respond(
        status_code=500,
        text="Internal Server Error",
    )

    async with httpx.AsyncClient() as client:
        result = await provider.lookup("1.1.1.1", IoCType.IPV4, client)

    assert result.status == "error"
    assert "500" in (result.error_message or "")


@pytest.mark.asyncio
@respx.mock
async def test_virustotal_unexpected_4xx(provider: VirusTotalProvider) -> None:
    respx.get("https://www.virustotal.com/api/v3/ip_addresses/1.1.1.1").respond(
        status_code=403,
        json={"error": "Forbidden"},
        headers={"content-type": "application/json"},
    )

    async with httpx.AsyncClient() as client:
        result = await provider.lookup("1.1.1.1", IoCType.IPV4, client)

    assert result.status == "error"
    assert "403" in (result.error_message or "")


@pytest.mark.asyncio
@respx.mock
async def test_virustotal_malformed_json(provider: VirusTotalProvider) -> None:
    respx.get("https://www.virustotal.com/api/v3/ip_addresses/1.1.1.1").respond(
        status_code=200,
        text="<xml>not json</xml>",
        headers={"content-type": "application/json"},
    )

    async with httpx.AsyncClient() as client:
        result = await provider.lookup("1.1.1.1", IoCType.IPV4, client)

    assert result.status == "error"
    assert "JSON" in (result.error_message or "")


@pytest.mark.asyncio
@respx.mock
async def test_virustotal_timeout_and_network_error(provider: VirusTotalProvider) -> None:
    respx.get("https://www.virustotal.com/api/v3/ip_addresses/1.1.1.1").mock(
        side_effect=httpx.TimeoutException("Read timed out")
    )
    respx.get("https://www.virustotal.com/api/v3/ip_addresses/2.2.2.2").mock(
        side_effect=httpx.ConnectError("Connection refused")
    )

    async with httpx.AsyncClient() as client:
        timeout_res = await provider.lookup("1.1.1.1", IoCType.IPV4, client)
        conn_res = await provider.lookup("2.2.2.2", IoCType.IPV4, client)

    assert timeout_res.status == "error"
    assert "timed out" in (timeout_res.error_message or "").lower()
    assert conn_res.status == "error"
    assert "network error" in (conn_res.error_message or "").lower()


@pytest.mark.asyncio
async def test_virustotal_missing_api_key() -> None:
    provider = VirusTotalProvider(api_key=None)
    assert provider.is_configured() is False
    async with httpx.AsyncClient() as client:
        result = await provider.lookup("8.8.8.8", IoCType.IPV4, client)

    assert result.status == "skipped"
    assert "not configured" in (result.error_message or "")


@pytest.mark.asyncio
async def test_virustotal_unsupported_type() -> None:
    provider = VirusTotalProvider(api_key="key")
    # Temporarily check an invalid ioc_type
    provider.supported_types = frozenset()  # type: ignore[assignment]
    async with httpx.AsyncClient() as client:
        result = await provider.lookup("8.8.8.8", IoCType.IPV4, client)

    assert result.status == "unsupported"
