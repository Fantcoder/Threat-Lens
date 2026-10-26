"""Threat Intelligence Aggregator.

Orchestrates concurrent provider queries, handles partial failures gracefully,
enforces token buckets and daily quotas, wraps operations in circuit breakers,
coalesces in-flight identical lookups, and caches normalized reports.
"""

from __future__ import annotations

import asyncio
import contextlib
import random
import time
from collections.abc import Callable, Coroutine
from typing import Any

import httpx

from threatlens.cache import LookupCache
from threatlens.config import Settings
from threatlens.detector import detect_ioc
from threatlens.models import AggregatedReport, IoCType, ProviderResult
from threatlens.providers.abuseipdb import AbuseIPDBProvider
from threatlens.providers.base import BaseProvider
from threatlens.providers.otx import OTXProvider
from threatlens.providers.virustotal import VirusTotalProvider
from threatlens.ratelimit import (
    CircuitBreaker,
    DailyQuotaTracker,
    TokenBucket,
)
from threatlens.scoring import score_report


class Aggregator:
    """Central orchestrator aggregating threat intelligence across providers."""

    def __init__(
        self,
        providers: list[BaseProvider],
        cache: LookupCache,
        quota_tracker: DailyQuotaTracker,
        settings: Settings,
        client: httpx.AsyncClient,
        token_buckets: dict[str, TokenBucket] | None = None,
        circuit_breakers: dict[str, CircuitBreaker] | None = None,
        sleep_fn: Callable[[float], Coroutine[Any, Any, None]] = asyncio.sleep,
    ) -> None:
        self.providers = providers
        self.cache = cache
        self.quota_tracker = quota_tracker
        self.settings = settings
        self.client = client
        self.sleep_fn = sleep_fn

        # Token buckets (per-minute)
        self.token_buckets: dict[str, TokenBucket] = token_buckets or {
            p.name: TokenBucket(
                capacity=p.rate_limit_rpm,
                refill_rate=p.rate_limit_rpm / 60.0,
            )
            for p in providers
        }

        # Circuit breakers (per-provider)
        self.circuit_breakers: dict[str, CircuitBreaker] = circuit_breakers or {
            p.name: CircuitBreaker(
                provider=p.name,
                failure_threshold=settings.circuit_breaker_failure_threshold,
                recovery_timeout=settings.circuit_breaker_recovery_timeout,
            )
            for p in providers
        }

        # In-flight lookup coalescing map: ioc_hash -> Future[AggregatedReport]
        self._inflight: dict[str, asyncio.Future[AggregatedReport]] = {}
        self._inflight_lock = asyncio.Lock()

    @classmethod
    async def create(
        cls,
        settings: Settings | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> Aggregator:
        """Factory method constructing an Aggregator with default providers and storage."""
        active_settings = settings or Settings()
        active_settings.cache_dir.mkdir(parents=True, exist_ok=True)

        http_client = client or httpx.AsyncClient(timeout=30.0)
        cache = LookupCache(active_settings.cache_dir / "cache.sqlite")
        await cache.initialize()

        quota_tracker = DailyQuotaTracker(active_settings.cache_dir / "quotas.sqlite")
        await quota_tracker.initialize()

        vt_key = (
            active_settings.virustotal_api_key.get_secret_value()
            if active_settings.virustotal_api_key
            else None
        )
        otx_key = (
            active_settings.otx_api_key.get_secret_value() if active_settings.otx_api_key else None
        )
        abuse_key = (
            active_settings.abuseipdb_api_key.get_secret_value()
            if active_settings.abuseipdb_api_key
            else None
        )

        providers: list[BaseProvider] = [
            VirusTotalProvider(
                api_key=vt_key,
                rpm=active_settings.virustotal_rpm,
                daily=active_settings.virustotal_daily,
                timeout=active_settings.virustotal_timeout,
            ),
            OTXProvider(
                api_key=otx_key,
                rpm=active_settings.otx_rpm,
                daily=active_settings.otx_daily,
                timeout=active_settings.otx_timeout,
            ),
            AbuseIPDBProvider(
                api_key=abuse_key,
                rpm=active_settings.abuseipdb_rpm,
                daily=active_settings.abuseipdb_daily,
                timeout=active_settings.abuseipdb_timeout,
            ),
        ]

        return cls(
            providers=providers,
            cache=cache,
            quota_tracker=quota_tracker,
            settings=active_settings,
            client=http_client,
        )

    async def close(self) -> None:
        """Release underlying HTTP client resources."""
        await self.client.aclose()

    async def lookup(
        self,
        raw_ioc: str,
        refresh: bool = False,
        include_raw: bool = False,
    ) -> AggregatedReport:
        """Analyze an IoC across all configured providers.

        Args:
            raw_ioc: Input IoC string (may be defanged or raw).
            refresh: If True, bypass cache and re-query providers.
            include_raw: Whether to include raw JSON responses in provider results.

        Returns:
            AggregatedReport: Consolidated intelligence report with explainable score.
        """
        ioc_type, normalized_value = detect_ioc(raw_ioc)
        ioc_hash = self.cache.compute_hash(normalized_value, ioc_type)

        # 1. Check persistent cache unless refresh requested or raw payloads requested
        if not refresh and not include_raw:
            cached_report = await self.cache.get(ioc_hash)
            if cached_report is not None:
                return cached_report

        # 2. Request coalescing: share in-flight upstream lookups for identical indicator and mode
        coalesce_key = f"{ioc_hash}:{int(include_raw)}"
        async with self._inflight_lock:
            if coalesce_key in self._inflight:
                # Piggyback on in-flight request
                return await self._inflight[coalesce_key]

            loop = asyncio.get_running_loop()
            future: asyncio.Future[AggregatedReport] = loop.create_future()
            self._inflight[coalesce_key] = future

        try:
            report = await self._execute_fanout(raw_ioc, ioc_type, normalized_value, include_raw)
            future.set_result(report)
            return report
        except Exception as exc:
            future.set_exception(exc)
            raise
        finally:
            async with self._inflight_lock:
                self._inflight.pop(coalesce_key, None)
            if future.done() and not future.cancelled():
                # Avoid "Future exception was never retrieved" warnings if no other waiters joined
                with contextlib.suppress(Exception):
                    future.exception()

    async def _execute_fanout(
        self,
        raw_ioc: str,
        ioc_type: IoCType,
        normalized_value: str,
        include_raw: bool,
    ) -> AggregatedReport:
        """Query all applicable providers concurrently with isolated exception safety."""
        tasks = [
            self._query_provider(p, normalized_value, ioc_type, include_raw) for p in self.providers
        ]
        gathered_results = await asyncio.gather(*tasks, return_exceptions=True)

        provider_results: list[ProviderResult] = []
        for i, res in enumerate(gathered_results):
            if isinstance(res, ProviderResult):
                provider_results.append(res)
            elif isinstance(res, Exception):
                provider_results.append(
                    ProviderResult(
                        provider=self.providers[i].name,
                        status="error",
                        error_message=f"Unexpected exception during lookup: {res}",
                    )
                )

        # Score results
        verdict, score, confidence, breakdown = score_report(provider_results, self.settings)

        # Short TTL (ttl_unknown) if any applicable provider had an error or was rate limited
        has_partial_failure = any(
            p.status in ("error", "rate_limited")
            for p in provider_results
            if p.status != "unsupported"
        )
        if has_partial_failure:
            ttl = self.settings.ttl_unknown
        else:
            ttl = self.cache.get_ttl_for_verdict(verdict, self.settings)

        report = AggregatedReport(
            ioc=raw_ioc,
            ioc_type=ioc_type,
            normalized_value=normalized_value,
            verdict=verdict,
            risk_score=score,
            score_confidence=confidence,
            score_breakdown=breakdown,
            providers=provider_results,
            cached=False,
            ttl_remaining=ttl,
        )

        # Strip raw payloads from provider results before caching
        if any(p.raw is not None for p in provider_results):
            cleaned_providers = [p.model_copy(update={"raw": None}) for p in provider_results]
            report_to_cache = report.model_copy(update={"providers": cleaned_providers})
        else:
            report_to_cache = report

        # Cache sanitized report and insert into audit history
        await self.cache.put(report_to_cache, ttl)
        await self.cache.add_history(report_to_cache)

        return report

    async def _query_provider(
        self,
        provider: BaseProvider,
        normalized_value: str,
        ioc_type: IoCType,
        include_raw: bool,
    ) -> ProviderResult:
        """Query a single provider guarded by quotas, token bucket, and circuit breaker."""
        start_time = time.perf_counter()

        # 1. Check type support
        if not provider.supports(ioc_type):
            return ProviderResult(
                provider=provider.name,
                status="unsupported",
                error_message=f"{provider.name} does not support {ioc_type.value}",
            )

        # 2. Check configuration (keyless mode returns skipped without burning quota)
        if not provider.is_configured():
            return ProviderResult(
                provider=provider.name,
                status="skipped",
                error_message=f"{provider.name} API key not configured",
            )

        # 3. Check circuit breaker (open breaker must not consume quota or tokens)
        cb = self.circuit_breakers.get(provider.name)
        if cb and not await cb.can_execute():
            return ProviderResult(
                provider=provider.name,
                status="error",
                error_message=f"Circuit breaker is OPEN for {provider.name}",
            )

        # 4. Check daily quota
        has_quota = await self.quota_tracker.check_and_increment(
            provider.name, provider.rate_limit_daily
        )
        if not has_quota:
            if cb:
                await cb.release_probe()
            msg = f"Daily quota ({provider.rate_limit_daily}) exhausted for {provider.name}"
            return ProviderResult(
                provider=provider.name,
                status="rate_limited",
                error_message=msg,
            )

        # 5. Check token bucket (per-minute rate limit); refund quota if refused
        bucket = self.token_buckets.get(provider.name)
        if bucket:
            acquired = await bucket.acquire(1.0, max_wait=self.settings.max_rate_limit_wait)
            if not acquired:
                if cb:
                    await cb.release_probe()
                await self.quota_tracker.refund(provider.name)
                msg = (
                    f"Per-minute rate limit ({provider.rate_limit_rpm}) "
                    f"exceeded for {provider.name}"
                )
                return ProviderResult(
                    provider=provider.name,
                    status="rate_limited",
                    error_message=msg,
                )

        # 6. Execute provider call with retry policy on retryable status codes (5xx, 429, timeouts)
        max_attempts = 3
        result: ProviderResult | None = None

        for attempt in range(1, max_attempts + 1):
            try:
                result = await provider.lookup(
                    normalized_value,
                    ioc_type,
                    self.client,
                    include_raw=include_raw,
                )
            except Exception as exc:
                latency_ms = int((time.perf_counter() - start_time) * 1000)
                result = ProviderResult(
                    provider=provider.name,
                    status="error",
                    latency_ms=max(0, latency_ms),
                    error_message=f"Provider lookup failed: {exc}",
                    retryable=False,
                )

            # Retry only retryable failures (5xx, 429, timeout, network error)
            if result.retryable and attempt < max_attempts:
                if result.retry_after is not None:
                    backoff = min(result.retry_after, self.settings.max_rate_limit_wait)
                else:
                    base_delay = 0.1 * (2 ** (attempt - 1))
                    jitter = random.uniform(0.0, 0.05)  # nosec B311
                    backoff = min(base_delay + jitter, self.settings.max_rate_limit_wait)

                await self.sleep_fn(backoff)
                continue

            break

        if result is None:
            raise RuntimeError("Unreachable: aggregator result is None")

        # Update circuit breaker state: record ONE failure/success per exhausted lookup
        if cb:
            if result.status in ("ok", "not_found", "skipped", "unsupported"):
                await cb.record_success()
            elif result.status in ("error", "rate_limited"):
                await cb.record_failure()

        return result
