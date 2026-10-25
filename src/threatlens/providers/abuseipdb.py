"""AbuseIPDB Threat Intelligence Provider (IPs only)."""

from __future__ import annotations

import time
from datetime import datetime
from typing import Any

import httpx

from threatlens.models import GeoInfo, IoCType, ProviderResult
from threatlens.providers.base import BaseProvider


class AbuseIPDBProvider(BaseProvider):
    """AbuseIPDB v2 API provider. Analyzes IPv4 and IPv6 addresses."""

    name = "abuseipdb"
    base_url = "https://api.abuseipdb.com/api/v2/check"
    supported_types = frozenset({IoCType.IPV4, IoCType.IPV6})

    def __init__(
        self,
        api_key: str | None = None,
        rpm: int = 10,
        daily: int = 1000,
        timeout: float = 15.0,
    ) -> None:
        self.api_key = api_key
        self.rate_limit_rpm = rpm
        self.rate_limit_daily = daily
        self.timeout_seconds = timeout

    def is_configured(self) -> bool:
        """Return True if AbuseIPDB API key is present."""
        return bool(self.api_key)

    async def lookup(
        self,
        ioc: str,
        ioc_type: IoCType,
        client: httpx.AsyncClient,
        include_raw: bool = False,
    ) -> ProviderResult:
        start_time = time.perf_counter()

        # Non-IP IoC types are unsupported by AbuseIPDB
        if not self.supports(ioc_type):
            return self._create_result(
                status="unsupported",
                start_time=start_time,
                error_message="AbuseIPDB only supports IPv4 and IPv6 addresses",
            )

        if not self.api_key:
            return self._create_result(
                status="skipped",
                start_time=start_time,
                error_message="AbuseIPDB API key not configured",
            )

        headers = {
            "Key": self.api_key,
            "Accept": "application/json",
        }
        params: dict[str, Any] = {
            "ipAddress": ioc,
            "maxAgeInDays": 90,
            "verbose": True,
        }
        gui_ref = f"https://www.abuseipdb.com/check/{ioc}"

        try:
            response = await client.get(
                self.base_url,
                headers=headers,
                params=params,
                timeout=self.timeout_seconds,
            )
        except httpx.TimeoutException:
            return self._create_result(
                status="error",
                start_time=start_time,
                error_message=f"AbuseIPDB request timed out after {self.timeout_seconds}s",
            )
        except httpx.RequestError as exc:
            return self._create_result(
                status="error",
                start_time=start_time,
                error_message=f"AbuseIPDB network error: {exc}",
            )

        if response.status_code == 404:
            return self._create_result(
                status="not_found",
                start_time=start_time,
                references=[gui_ref],
                raw=response.json() if include_raw and self._is_json(response) else None,
            )

        if response.status_code == 429:
            return self._create_result(
                status="rate_limited",
                start_time=start_time,
                error_message="AbuseIPDB rate limit exceeded (HTTP 429)",
            )

        if response.status_code >= 500:
            return self._create_result(
                status="error",
                start_time=start_time,
                error_message=f"AbuseIPDB server error (HTTP {response.status_code})",
            )

        if response.status_code != 200:
            return self._create_result(
                status="error",
                start_time=start_time,
                error_message=f"AbuseIPDB returned unexpected status {response.status_code}",
            )

        try:
            payload: dict[str, Any] = response.json()
        except Exception:
            return self._create_result(
                status="error",
                start_time=start_time,
                error_message="Failed to parse AbuseIPDB JSON response",
            )

        return self._parse_payload(payload, gui_ref, start_time, include_raw)

    def _parse_payload(
        self,
        payload: dict[str, Any],
        gui_ref: str,
        start_time: float,
        include_raw: bool,
    ) -> ProviderResult:
        data = payload.get("data", {})
        abuse_confidence = data.get("abuseConfidenceScore", 0)
        total_reports = data.get("totalReports", 0)

        country = data.get("countryCode")
        isp = data.get("isp")
        geo = None
        if country or isp:
            geo = GeoInfo(country=country, as_owner=isp)

        tags = []
        usage_type = data.get("usageType")
        if usage_type:
            tags.append(str(usage_type).lower())
        if data.get("isTor"):
            tags.append("tor-exit-node")

        last_reported_str = data.get("lastReportedAt")
        last_seen = None
        if last_reported_str:
            try:
                last_seen = datetime.fromisoformat(last_reported_str.replace("Z", "+00:00"))
            except Exception:
                last_seen = None

        return self._create_result(
            status="ok",
            start_time=start_time,
            abuse_confidence=abuse_confidence,
            total_reports=total_reports,
            geo=geo,
            tags=tags,
            last_seen=last_seen,
            references=[gui_ref],
            raw=payload if include_raw else None,
        )

    @staticmethod
    def _is_json(response: httpx.Response) -> bool:
        return "application/json" in response.headers.get("content-type", "")
