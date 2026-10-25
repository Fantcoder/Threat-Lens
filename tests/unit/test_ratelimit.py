"""Unit tests for Rate Limiting, Daily Quota, Circuit Breaker, and Retries.

All time-dependent tests use injectable clocks and sleepers (zero sleep time in tests).
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from threatlens.errors import CircuitBreakerOpenError
from threatlens.ratelimit import (
    CircuitBreaker,
    CircuitState,
    DailyQuotaTracker,
    TokenBucket,
    create_retry_retrying,
    parse_retry_after,
)

# ==============================================================================
# Token Bucket Tests (Fake Monotonic Clock + Fake Sleeper)
# ==============================================================================


class FakeClock:
    def __init__(self, start: float = 0.0) -> None:
        self.current_time = start

    def __call__(self) -> float:
        return self.current_time

    def advance(self, seconds: float) -> None:
        self.current_time += seconds


@pytest.mark.asyncio
async def test_token_bucket_acquire_and_depletion() -> None:
    clock = FakeClock(100.0)
    # Bucket capacity 2, refill rate 1 token/sec
    bucket = TokenBucket(capacity=2, refill_rate=1.0, clock=clock)

    assert await bucket.acquire(1.0) is True
    assert await bucket.acquire(1.0) is True

    # Empty now, with max_wait=0.0 it should fail immediately
    assert await bucket.acquire(1.0, max_wait=0.0) is False

    # Advance clock by 1.5 seconds -> 1.5 tokens refilled
    clock.advance(1.5)
    assert await bucket.acquire(1.0) is True


@pytest.mark.asyncio
async def test_token_bucket_wait_and_acquire() -> None:
    clock = FakeClock(100.0)

    async def fake_sleep(seconds: float) -> None:
        clock.advance(seconds)

    bucket = TokenBucket(capacity=2, refill_rate=2.0, clock=clock, sleep_fn=fake_sleep)
    await bucket.acquire(2.0)  # Emptied

    # Need 1 token at 2 tokens/sec = 0.5s wait
    # Allowed max_wait=1.0s, so fake_sleep will advance clock and acquire succeeds
    success = await bucket.acquire(1.0, max_wait=1.0)
    assert success is True
    assert clock.current_time >= 100.5


@pytest.mark.asyncio
async def test_token_bucket_exceed_capacity_error() -> None:
    bucket = TokenBucket(capacity=5, refill_rate=1.0)
    with pytest.raises(ValueError):
        await bucket.acquire(10.0)


# ==============================================================================
# Daily Quota Tracker Tests (SQLite Persistence & Midnight Rollover)
# ==============================================================================


@pytest.mark.asyncio
async def test_daily_quota_tracker_workflow(tmp_path: Path) -> None:
    db_path = tmp_path / "quota.sqlite"
    current_dt = datetime(2026, 10, 24, 15, 0, 0, tzinfo=UTC)

    def fake_now() -> datetime:
        return current_dt

    tracker = DailyQuotaTracker(db_path, now_fn=fake_now)
    await tracker.initialize()

    # Limit = 3 requests
    assert await tracker.check_and_increment("virustotal", limit=3) is True
    assert await tracker.check_and_increment("virustotal", limit=3) is True
    assert await tracker.check_and_increment("virustotal", limit=3) is True

    # 4th request must be rejected
    assert await tracker.check_and_increment("virustotal", limit=3) is False

    used, limit = await tracker.get_usage("virustotal", limit=3)
    assert used == 3
    assert limit == 3

    # Midnight rollover: advance time to next day
    current_dt = datetime(2026, 10, 25, 0, 1, 0, tzinfo=UTC)
    # New day resets quota
    assert await tracker.check_and_increment("virustotal", limit=3) is True
    used_next_day, _ = await tracker.get_usage("virustotal", limit=3)
    assert used_next_day == 1


@pytest.mark.asyncio
async def test_daily_quota_persistence_across_instances(tmp_path: Path) -> None:
    db_path = tmp_path / "quota.sqlite"
    t1 = DailyQuotaTracker(db_path)
    await t1.initialize()
    await t1.check_and_increment("otx", limit=5)
    await t1.check_and_increment("otx", limit=5)

    # New instance pointing to same database
    t2 = DailyQuotaTracker(db_path)
    used, _ = await t2.get_usage("otx", limit=5)
    assert used == 2


# ==============================================================================
# Circuit Breaker Tests (Closed -> Open -> Half-Open -> Closed)
# ==============================================================================


@pytest.mark.asyncio
async def test_circuit_breaker_state_transitions() -> None:
    clock = FakeClock(100.0)
    breaker = CircuitBreaker(
        provider="virustotal",
        failure_threshold=3,
        recovery_timeout=30.0,
        clock=clock,
    )

    assert breaker.state == CircuitState.CLOSED
    assert await breaker.can_execute() is True

    # 2 failures do not trip
    await breaker.record_failure()
    await breaker.record_failure()
    assert breaker.state == CircuitState.CLOSED

    # 3rd failure trips breaker
    await breaker.record_failure()
    assert breaker.state == CircuitState.OPEN
    assert await breaker.can_execute() is False

    with pytest.raises(CircuitBreakerOpenError):
        async with breaker:
            pass

    # Advance clock by 20s (still within 30s recovery timeout)
    clock.advance(20.0)
    assert await breaker.can_execute() is False

    # Advance clock past recovery timeout (35s total) -> transitions to HALF_OPEN
    clock.advance(15.0)
    assert await breaker.can_execute() is True
    assert breaker.state == CircuitState.HALF_OPEN

    # A failure in HALF_OPEN trips immediately back to OPEN
    await breaker.record_failure()
    assert breaker.state == CircuitState.OPEN

    # Advance past recovery again
    clock.advance(31.0)
    assert await breaker.can_execute() is True
    assert breaker.state == CircuitState.HALF_OPEN

    # Success in HALF_OPEN resets to CLOSED
    await breaker.record_success()
    assert breaker.state == CircuitState.CLOSED
    assert breaker.failure_count == 0


@pytest.mark.asyncio
async def test_circuit_breaker_context_manager() -> None:
    breaker = CircuitBreaker("abuseipdb", failure_threshold=2)

    # Success execution
    async with breaker:
        pass
    assert breaker.state == CircuitState.CLOSED

    # Exception inside block records failure
    with pytest.raises(RuntimeError):
        async with breaker:
            raise RuntimeError("API failure")

    assert breaker.failure_count == 1


# ==============================================================================
# Retries & Retry-After Parsing Tests
# ==============================================================================


def test_parse_retry_after() -> None:
    resp1 = httpx.Response(429, headers={"Retry-After": "15"})
    assert parse_retry_after(resp1) == 15.0

    resp2 = httpx.Response(429, headers={"Retry-After": "0.5"})
    assert parse_retry_after(resp2) == 0.5

    resp3 = httpx.Response(429)  # Missing header
    assert parse_retry_after(resp3, default=2.0) == 2.0

    resp4 = httpx.Response(429, headers={"Retry-After": "invalid"})
    assert parse_retry_after(resp4, default=3.0) == 3.0


@pytest.mark.asyncio
async def test_retry_policy_exhaustion() -> None:
    attempts = 0

    async def fake_sleep(_: float) -> None:
        pass

    retrying = create_retry_retrying(max_attempts=3, min_wait=0.01, sleep_fn=fake_sleep)

    with pytest.raises(httpx.TimeoutException):
        async for attempt in retrying:
            with attempt:
                attempts += 1
                raise httpx.TimeoutException("Persistent connection timeout")

    assert attempts == 3
