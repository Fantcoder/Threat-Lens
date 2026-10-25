"""AlienVault OTX (Open Threat Exchange) Intelligence Provider."""

from __future__ import annotations

import time
from typing import Any

import httpx

from threatlens.models import GeoInfo, IoCType, ProviderResult
from threatlens.providers.base import BaseProvider


class OTXProvider(BaseProvider):
    """AlienVault OTX intelligence provider."""

    name = "otx"
    base_url = "https://otx.alienvault.com/api/v1/indicators"
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
        rpm: int = 10,
        daily: int = 1000,
        timeout: float = 15.0,
    ) -> None:
        self.api_key = api_key
        self.rate_limit_rpm = rpm
        self.rate_limit_daily = daily
        self.timeout_seconds = timeout

    def _map_ioc_type(self, ioc_type: IoCType) -> str:
        """Map IoCType to AlienVault OTX indicator type."""
        if ioc_type == IoCType.IPV4:
            return "IPv4"
        if ioc_type == IoCType.IPV6:
            return "IPv6"
        if ioc_type == IoCType.DOMAIN:
            return "domain"
        if ioc_type == IoCType.URL:
            return "url"
        if ioc_type in (IoCType.MD5, IoCType.SHA1, IoCType.SHA256):
            return "file"
        raise ValueError(f"Unsupported IoC type for OTX: {ioc_type}")

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
                error_message="AlienVault OTX API key not configured",
            )

        otx_type = self._map_ioc_type(ioc_type)
        url = f"{self.base_url}/{otx_type}/{ioc}/general"
        gui_ref = f"https://otx.alienvault.com/indicator/{otx_type.lower()}/{ioc}"
        headers = {
            "X-OTX-API-KEY": self.api_key,
            "Accept": "application/json",
        }

        try:
            response = await client.get(url, headers=headers, timeout=self.timeout_seconds)
        except httpx.TimeoutException:
            return self._create_result(
                status="error",
                start_time=start_time,
                error_message=f"AlienVault OTX timed out after {self.timeout_seconds}s",
            )
        except httpx.RequestError as exc:
            return self._create_result(
                status="error",
                start_time=start_time,
                error_message=f"AlienVault OTX network error: {exc}",
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
                error_message="AlienVault OTX rate limit exceeded (HTTP 429)",
            )

        if response.status_code >= 500:
            return self._create_result(
                status="error",
                start_time=start_time,
                error_message=f"AlienVault OTX server error (HTTP {response.status_code})",
            )

        if response.status_code != 200:
            return self._create_result(
                status="error",
                start_time=start_time,
                error_message=f"AlienVault OTX returned unexpected status {response.status_code}",
            )

        try:
            payload: dict[str, Any] = response.json()
        except Exception:
            return self._create_result(
                status="error",
                start_time=start_time,
                error_message="Failed to parse AlienVault OTX JSON response",
            )

        return self._parse_payload(payload, gui_ref, start_time, include_raw)

    def _parse_payload(
        self,
        payload: dict[str, Any],
        gui_ref: str,
        start_time: float,
        include_raw: bool,
    ) -> ProviderResult:
        pulse_info = payload.get("pulse_info", {})
        pulse_count = pulse_info.get("count", 0)
        pulses = pulse_info.get("pulses", [])

        tags_set: set[str] = set()
        malware_families_set: set[str] = set()
        adversaries_set: set[str] = set()

        for p in pulses:
            for t in p.get("tags", []):
                if t:
                    tags_set.add(str(t).lower())
            for mf in p.get("malware_families", []):
                display = mf.get("display_name") or mf.get("name")
                if display:
                    malware_families_set.add(str(display))
            adv = p.get("adversary")
            if adv:
                adversaries_set.add(str(adv))

        # Geo info
        geo = None
        country = payload.get("country_name") or payload.get("country_code")
        asn_str = payload.get("asn")
        asn = None
        if asn_str:
            # Extract digits from e.g. "AS15169"
            digits = "".join(filter(str.isdigit, str(asn_str)))
            if digits:
                asn = int(digits)
        if country or asn:
            geo = GeoInfo(country=country, asn=asn)

        return self._create_result(
            status="ok",
            start_time=start_time,
            pulse_count=pulse_count,
            tags=sorted(tags_set)[:20],
            malware_families=sorted(malware_families_set)[:20],
            threat_actors=sorted(adversaries_set)[:20],
            geo=geo,
            references=[gui_ref],
            raw=payload if include_raw else None,
        )

    @staticmethod
    def _is_json(response: httpx.Response) -> bool:
        return "application/json" in response.headers.get("content-type", "")
