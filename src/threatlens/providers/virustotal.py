"""VirusTotal (API v3) Threat Intelligence Provider."""

from __future__ import annotations

import base64
import time
from datetime import UTC, datetime
from typing import Any

import httpx

from threatlens.models import GeoInfo, IoCType, ProviderResult
from threatlens.providers.base import BaseProvider


class VirusTotalProvider(BaseProvider):
    """VirusTotal API v3 provider."""

    name = "virustotal"
    base_url = "https://www.virustotal.com/api/v3"
    supported_types = frozenset(
        {
            IoCType.IPV4,
            IoCType.IPV6,
            IoCType.DOMAIN,
            IoCType.URL,
            IoCType.MD5,
            IoCType.SHA1,
            IoCType.SHA256,
        }
    )

    def __init__(
        self,
        api_key: str | None = None,
        rpm: int = 4,
        daily: int = 500,
        timeout: float = 15.0,
    ) -> None:
        self.api_key = api_key
        self.rate_limit_rpm = rpm
        self.rate_limit_daily = daily
        self.timeout_seconds = timeout

    @staticmethod
    def encode_url_id(url: str) -> str:
        """Encode URL as URL-safe base64 without padding for VirusTotal v3."""
        return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")

    def _get_endpoint_and_ref(self, ioc: str, ioc_type: IoCType) -> tuple[str, str]:
        """Map IoC type to VirusTotal API v3 endpoint and GUI reference link."""
        if ioc_type in (IoCType.IPV4, IoCType.IPV6):
            return f"/ip_addresses/{ioc}", f"https://www.virustotal.com/gui/ip-address/{ioc}"
        if ioc_type == IoCType.DOMAIN:
            return f"/domains/{ioc}", f"https://www.virustotal.com/gui/domain/{ioc}"
        if ioc_type in (IoCType.MD5, IoCType.SHA1, IoCType.SHA256):
            return f"/files/{ioc}", f"https://www.virustotal.com/gui/file/{ioc}"
        if ioc_type == IoCType.URL:
            url_id = self.encode_url_id(ioc)
            return f"/urls/{url_id}", f"https://www.virustotal.com/gui/url/{url_id}"
        raise ValueError(f"Unsupported IoC type for VirusTotal: {ioc_type}")

    async def lookup(
        self,
        ioc: str,
        ioc_type: IoCType,
        client: httpx.AsyncClient,
        include_raw: bool = False,
    ) -> ProviderResult:
        start_time = time.perf_counter()

        if not self.supports(ioc_type):
            return self._create_result(status="unsupported", start_time=start_time)

        if not self.api_key:
            return self._create_result(
                status="skipped",
                start_time=start_time,
                error_message="VirusTotal API key not configured",
            )

        endpoint, gui_ref = self._get_endpoint_and_ref(ioc, ioc_type)
        url = f"{self.base_url}{endpoint}"
        headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json",
        }

        try:
            response = await client.get(url, headers=headers, timeout=self.timeout_seconds)
        except httpx.TimeoutException:
            return self._create_result(
                status="error",
                start_time=start_time,
                error_message=f"VirusTotal request timed out after {self.timeout_seconds}s",
            )
        except httpx.RequestError as exc:
            return self._create_result(
                status="error",
                start_time=start_time,
                error_message=f"VirusTotal network error: {exc}",
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
                error_message="VirusTotal rate limit exceeded (HTTP 429)",
            )

        if response.status_code >= 500:
            return self._create_result(
                status="error",
                start_time=start_time,
                error_message=f"VirusTotal server error (HTTP {response.status_code})",
            )

        if response.status_code != 200:
            return self._create_result(
                status="error",
                start_time=start_time,
                error_message=f"VirusTotal returned unexpected status {response.status_code}",
            )

        try:
            payload: dict[str, Any] = response.json()
        except Exception:
            return self._create_result(
                status="error",
                start_time=start_time,
                error_message="Failed to parse VirusTotal JSON response",
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
        attributes = data.get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        timeout = stats.get("timeout", 0)
        total_engines = malicious + suspicious + harmless + undetected + timeout

        reputation = attributes.get("reputation")
        tags = attributes.get("tags", [])

        # Geo info
        geo = None
        country = attributes.get("country")
        as_owner = attributes.get("as_owner")
        asn = attributes.get("asn")
        if country or as_owner or asn:
            geo = GeoInfo(country=country, as_owner=as_owner, asn=asn)

        # Dates
        last_analysis_epoch = attributes.get("last_analysis_date")
        last_seen = None
        if last_analysis_epoch:
            last_seen = datetime.fromtimestamp(last_analysis_epoch, tz=UTC)

        first_seen_epoch = attributes.get("first_submission_date")
        first_seen = None
        if first_seen_epoch:
            first_seen = datetime.fromtimestamp(first_seen_epoch, tz=UTC)

        confidence = 1.0 if total_engines > 0 else None

        return self._create_result(
            status="ok",
            start_time=start_time,
            malicious_votes=malicious,
            total_engines=total_engines,
            confidence=confidence,
            reputation=reputation,
            tags=tags[:20],
            geo=geo,
            first_seen=first_seen,
            last_seen=last_seen,
            references=[gui_ref],
            raw=payload if include_raw else None,
        )

    @staticmethod
    def _is_json(response: httpx.Response) -> bool:
        return "application/json" in response.headers.get("content-type", "")
