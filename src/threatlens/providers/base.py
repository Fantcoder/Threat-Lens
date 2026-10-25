"""Abstract base class for threat intelligence providers."""

from __future__ import annotations

import abc
import time
from typing import Any

import httpx

from threatlens.models import IoCType, ProviderResult


class BaseProvider(abc.ABC):
    """Abstract threat intelligence provider.

    Each provider defines its supported IoC types, API rate limit characteristics,
    and lookup logic.

    Guarantees:
    - Providers NEVER raise exceptions out for expected failures (404, 429, timeouts,
      network drops, or malformed JSON).
    - If an API key is not configured, the provider returns status='skipped'.
    - If the IoC type is not supported, the provider returns status='unsupported'.
    """

    name: str
    supported_types: frozenset[IoCType]
    rate_limit_rpm: int
    rate_limit_daily: int
    timeout_seconds: float

    def supports(self, ioc_type: IoCType) -> bool:
        """Check if this provider supports analyzing the given IoCType."""
        return ioc_type in self.supported_types

    def is_configured(self) -> bool:
        """Check if this provider has required credentials/configuration to perform lookups."""
        return True

    @abc.abstractmethod
    async def lookup(
        self,
        ioc: str,
        ioc_type: IoCType,
        client: httpx.AsyncClient,
        include_raw: bool = False,
    ) -> ProviderResult:
        """Query the provider API for intelligence on the specified IoC.

        Args:
            ioc: Normalized IoC value.
            ioc_type: Detected IoC type.
            client: Shared async HTTP client.
            include_raw: Whether to include the raw provider JSON response.

        Returns:
            ProviderResult: Normalized intelligence result with status code.
        """
        raise NotImplementedError

    def _create_result(
        self,
        status: str,
        start_time: float,
        error_message: str | None = None,
        raw: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> ProviderResult:
        """Helper to build a standardized ProviderResult with measured latency."""
        latency_ms = int((time.perf_counter() - start_time) * 1000)
        return ProviderResult(
            provider=self.name,
            status=status,  # type: ignore[arg-type]
            latency_ms=max(0, latency_ms),
            error_message=error_message,
            raw=raw,
            **kwargs,
        )
