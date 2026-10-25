"""Unit tests for Threat Intelligence Aggregator."""

from __future__ import annotations

import asyncio
from pathlib import Path

import httpx
import pytest

from threatlens.aggregator import Aggregator
from threatlens.cache import LookupCache
from threatlens.config import Settings
from threatlens.models import IoCType, ProviderResult, Verdict
from threatlens.providers.base import BaseProvider
from threatlens.ratelimit import DailyQuotaTracker


class MockProvider(BaseProvider):
    def __init__(
        self,
        name: str,
        result_to_return: ProviderResult | None = None,
        exception_to_raise: Exception | None = None,
        delay: float = 0.0,
        supported_types: frozenset[IoCType] | None = None,
    ) -> None:
        self.name = name
        self.result_to_return = result_to_return
        self.exception_to_raise = exception_to_raise
        self.delay = delay
        self.call_count = 0
        self.supported_types = supported_types or frozenset({IoCType.IPV4})
        self.rate_limit_rpm = 10
        self.rate_limit_daily = 100
        self.timeout_seconds = 5.0

    async def lookup(
        self,
        ioc: str,
        ioc_type: IoCType,
        client: httpx.AsyncClient,
        include_raw: bool = False,
    ) -> ProviderResult:
        self.call_count += 1
        if self.delay > 0:
            await asyncio.sleep(self.delay)
        if self.exception_to_raise:
            raise self.exception_to_raise
        if self.result_to_return:
            return self.result_to_return
        return ProviderResult(
            provider=self.name,
            status="ok",
            malicious_votes=0,
            total_engines=50,
        )


@pytest.fixture
async def setup_aggregator(tmp_path: Path) -> Aggregator:
    cache = LookupCache(tmp_path / "cache.sqlite")
    await cache.initialize()
    quota = DailyQuotaTracker(tmp_path / "quota.sqlite")
    await quota.initialize()
    settings = Settings()
    client = httpx.AsyncClient()

    p1 = MockProvider(
        "virustotal",
        result_to_return=ProviderResult(
            provider="virustotal", status="ok", malicious_votes=15, total_engines=70
        ),
    )
    p2 = MockProvider(
        "otx",
        result_to_return=ProviderResult(provider="otx", status="ok", pulse_count=4),
    )

    agg = Aggregator(
        providers=[p1, p2],
        cache=cache,
        quota_tracker=quota,
        settings=settings,
        client=client,
    )
    return agg


@pytest.mark.asyncio
async def test_aggregator_all_providers_success(setup_aggregator: Aggregator) -> None:
    report = await setup_aggregator.lookup("8.8.8.8")
    assert report.ioc == "8.8.8.8"
    assert report.normalized_value == "8.8.8.8"
    assert report.cached is False
    assert len(report.providers) == 2
    assert report.verdict in (Verdict.SUSPICIOUS, Verdict.MALICIOUS)
    assert report.score_confidence == 1.0


@pytest.mark.asyncio
async def test_aggregator_partial_failure_degradation(
    setup_aggregator: Aggregator,
) -> None:
    # Make OTX fail
    setup_aggregator.providers[1].result_to_return = ProviderResult(
        provider="otx", status="error", error_message="API connection failed"
    )

    report = await setup_aggregator.lookup("8.8.8.8")
    assert len(report.providers) == 2
    # One ok, one error
    statuses = [p.status for p in report.providers]
    assert "ok" in statuses
    assert "error" in statuses
    # Confidence is degraded
    assert report.score_confidence < 1.0


@pytest.mark.asyncio
async def test_aggregator_all_providers_fail(setup_aggregator: Aggregator) -> None:
    setup_aggregator.providers[0].result_to_return = ProviderResult(
        provider="virustotal", status="rate_limited"
    )
    setup_aggregator.providers[1].result_to_return = ProviderResult(provider="otx", status="error")

    report = await setup_aggregator.lookup("8.8.8.8")
    assert report.verdict == Verdict.UNKNOWN
    assert report.risk_score == 0
    assert report.score_confidence == 0.0


@pytest.mark.asyncio
async def test_aggregator_caching_and_refresh(setup_aggregator: Aggregator) -> None:
    # First lookup: cache miss
    r1 = await setup_aggregator.lookup("8.8.8.8")
    assert r1.cached is False
    assert setup_aggregator.providers[0].call_count == 1

    # Second lookup: cache hit (provider call_count should stay 1)
    r2 = await setup_aggregator.lookup("8.8.8.8")
    assert r2.cached is True
    assert setup_aggregator.providers[0].call_count == 1

    # Third lookup with refresh=True: bypass cache
    r3 = await setup_aggregator.lookup("8.8.8.8", refresh=True)
    assert r3.cached is False
    assert setup_aggregator.providers[0].call_count == 2


@pytest.mark.asyncio
async def test_aggregator_request_coalescing(setup_aggregator: Aggregator) -> None:
    # Add delay to provider lookup
    setup_aggregator.providers[0].delay = 0.05
    setup_aggregator.providers[1].delay = 0.05

    # Launch two concurrent lookups for the same indicator
    task1 = asyncio.create_task(setup_aggregator.lookup("8.8.8.8", refresh=True))
    task2 = asyncio.create_task(setup_aggregator.lookup("8.8.8.8", refresh=True))

    rep1, rep2 = await asyncio.gather(task1, task2)

    assert rep1.normalized_value == "8.8.8.8"
    assert rep2.normalized_value == "8.8.8.8"
    # Even though two requests were made simultaneously, provider was only called once!
    assert setup_aggregator.providers[0].call_count == 1


@pytest.mark.asyncio
async def test_aggregator_quota_exhaustion(setup_aggregator: Aggregator) -> None:
    # Pre-exhaust daily quota for virustotal
    setup_aggregator.providers[0].rate_limit_daily = 1
    await setup_aggregator.quota_tracker.check_and_increment("virustotal", 1)

    report = await setup_aggregator.lookup("8.8.8.8")
    vt_res = next(p for p in report.providers if p.provider == "virustotal")
    assert vt_res.status == "rate_limited"
    assert "Daily quota" in (vt_res.error_message or "")


@pytest.mark.asyncio
async def test_aggregator_circuit_breaker_open(setup_aggregator: Aggregator) -> None:
    # Manually trip circuit breaker
    cb = setup_aggregator.circuit_breakers["virustotal"]
    for _ in range(5):
        await cb.record_failure()

    report = await setup_aggregator.lookup("8.8.8.8")
    vt_res = next(p for p in report.providers if p.provider == "virustotal")
    assert vt_res.status == "error"
    assert "Circuit breaker is OPEN" in (vt_res.error_message or "")


@pytest.mark.asyncio
async def test_aggregator_provider_exception_handling(
    setup_aggregator: Aggregator,
) -> None:
    setup_aggregator.providers[0].exception_to_raise = RuntimeError("Unexpected crash")
    report = await setup_aggregator.lookup("8.8.8.8")
    vt_res = next(p for p in report.providers if p.provider == "virustotal")
    assert vt_res.status == "error"
    assert "Unexpected crash" in (vt_res.error_message or "")
