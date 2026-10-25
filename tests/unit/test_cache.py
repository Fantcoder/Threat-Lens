"""Unit tests for SQLite cache and audit history repository."""

from __future__ import annotations

from pathlib import Path

import pytest

from threatlens.cache import LookupCache
from threatlens.config import Settings
from threatlens.models import AggregatedReport, IoCType, Verdict


@pytest.fixture
def cache(tmp_path: Path) -> LookupCache:
    return LookupCache(tmp_path / "test_cache.sqlite")


@pytest.fixture
def sample_report() -> AggregatedReport:
    return AggregatedReport(
        ioc="8.8.8.8",
        ioc_type=IoCType.IPV4,
        normalized_value="8.8.8.8",
        verdict=Verdict.CLEAN,
        risk_score=0,
        score_confidence=1.0,
        providers=[],
    )


@pytest.mark.asyncio
async def test_cache_put_and_get(cache: LookupCache, sample_report: AggregatedReport) -> None:
    await cache.initialize()

    ioc_hash = cache.compute_hash(sample_report.normalized_value, sample_report.ioc_type)

    # Initial get: miss
    assert await cache.get(ioc_hash) is None

    # Put with 100s TTL
    await cache.put(sample_report, ttl_seconds=100)

    cached = await cache.get(ioc_hash)
    assert cached is not None
    assert cached.normalized_value == "8.8.8.8"
    assert cached.cached is True
    assert cached.ttl_remaining > 0


@pytest.mark.asyncio
async def test_cache_expiry_and_cleanup(
    cache: LookupCache, sample_report: AggregatedReport
) -> None:
    await cache.initialize()
    ioc_hash = cache.compute_hash(sample_report.normalized_value, sample_report.ioc_type)

    # Put with -10s TTL (already expired)
    await cache.put(sample_report, ttl_seconds=-10)

    # Should not be returned by get
    assert await cache.get(ioc_hash) is None

    # Cleanup should delete the expired row
    deleted = await cache.cleanup_expired()
    assert deleted >= 1


@pytest.mark.asyncio
async def test_history_logging_and_retrieval(
    cache: LookupCache, sample_report: AggregatedReport
) -> None:
    await cache.initialize()

    await cache.add_history(sample_report)

    # Second report with different verdict
    second_report = AggregatedReport(
        ioc="1.2.3.4",
        ioc_type=IoCType.IPV4,
        normalized_value="1.2.3.4",
        verdict=Verdict.MALICIOUS,
        risk_score=90,
        score_confidence=0.8,
        providers=[],
    )
    await cache.add_history(second_report)

    history = await cache.get_history(limit=10)
    assert len(history) == 2
    # Newest first
    assert history[0].ioc == "1.2.3.4"
    assert history[0].verdict == Verdict.MALICIOUS
    assert history[1].ioc == "8.8.8.8"


def test_ttl_for_verdict() -> None:
    settings = Settings()
    assert LookupCache.get_ttl_for_verdict(Verdict.MALICIOUS, settings) == settings.ttl_malicious
    assert LookupCache.get_ttl_for_verdict(Verdict.SUSPICIOUS, settings) == settings.ttl_suspicious
    assert LookupCache.get_ttl_for_verdict(Verdict.CLEAN, settings) == settings.ttl_clean
    assert LookupCache.get_ttl_for_verdict(Verdict.LOW_RISK, settings) == settings.ttl_low_risk
    assert LookupCache.get_ttl_for_verdict(Verdict.UNKNOWN, settings) == settings.ttl_unknown
