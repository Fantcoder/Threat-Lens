"""Rate limiting, Daily Quotas, Circuit Breakers, and Retries.

Demonstrates resilient async backend architecture:
- TokenBucket (per-minute) with lazy refill and timeout protection.
- DailyQuotaTracker backed by SQLite, surviving process restarts with UTC midnight rollover.
- CircuitBreaker pattern (Closed -> Open -> Half-Open).
- Injectable clocks and sleepers for fast, deterministic unit testing without sleeps.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable, Coroutine
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

import aiosqlite
import httpx
import tenacity

from threatlens.errors import CircuitBreakerOpenError


class TokenBucket:
    """Async token bucket rate limiter with lazy refilling and injectable clock."""

    def __init__(
        self,
        capacity: float,
        refill_rate: float,  # tokens per second
        clock: Callable[[], float] = time.monotonic,
        sleep_fn: Callable[[float], Coroutine[Any, Any, None]] = asyncio.sleep,
    ) -> None:
        self.capacity = float(capacity)
        self.refill_rate = float(refill_rate)
        self.tokens = float(capacity)
        self.clock = clock
        self.sleep_fn = sleep_fn
        self.last_refill = self.clock()
        self._lock = asyncio.Lock()

    def _refill(self) -> None:
        now = self.clock()
        elapsed = now - self.last_refill
        self.last_refill = now
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)

    async def acquire(self, tokens: float = 1.0, max_wait: float | None = None) -> bool:
        """Attempt to acquire tokens.

        If tokens are not immediately available, waits up to max_wait seconds.
        Returns True if acquired, False if waiting would exceed max_wait.
        """
        if tokens > self.capacity:
            raise ValueError(
                f"Requested tokens ({tokens}) exceeds bucket capacity ({self.capacity})"
            )

        while True:
            async with self._lock:
                self._refill()
                if self.tokens >= tokens:
                    self.tokens -= tokens
                    return True

                deficit = tokens - self.tokens
                wait_time = deficit / self.refill_rate

                if max_wait is not None and wait_time > max_wait:
                    return False

            # Yield control back to event loop while waiting for tokens
            await self.sleep_fn(wait_time)


class DailyQuotaTracker:
    """Persistent SQLite-backed daily quota tracker with UTC midnight rollover."""

    def __init__(
        self,
        db_path: Path,
        now_fn: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.db_path = db_path
        self.now_fn = now_fn
        self._lock = asyncio.Lock()

    async def initialize(self) -> None:
        """Create the quota tracking table if it does not already exist."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS daily_quotas (
                    provider TEXT NOT NULL,
                    date TEXT NOT NULL,
                    count INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (provider, date)
                )
                """
            )
            await db.commit()

    def _current_date(self) -> str:
        return self.now_fn().strftime("%Y-%m-%d")

    async def check_and_increment(self, provider: str, limit: int) -> bool:
        """Check if daily quota is available and increment if so.

        Returns:
            bool: True if request was within quota and counted, False if quota exhausted.
        """
        date_str = self._current_date()
        async with self._lock, aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute(
                "SELECT count FROM daily_quotas WHERE provider = ? AND date = ?",
                (provider, date_str),
            )
            row = await cursor.fetchone()
            current_count = row[0] if row else 0

            if current_count >= limit:
                return False

            await db.execute(
                """
                INSERT INTO daily_quotas (provider, date, count)
                VALUES (?, ?, 1)
                ON CONFLICT(provider, date) DO UPDATE SET count = count + 1
                """,
                (provider, date_str),
            )
            await db.commit()
            return True

    async def refund(self, provider: str, date_str: str | None = None) -> None:
        """Refund 1 request count (e.g. if token bucket refused after quota increment)."""
        if date_str is None:
            date_str = self._current_date()
        async with self._lock, aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                UPDATE daily_quotas
                SET count = MAX(0, count - 1)
                WHERE provider = ? AND date = ?
                """,
                (provider, date_str),
            )
            await db.commit()

    async def get_usage(self, provider: str, limit: int) -> tuple[int, int]:
        """Return (used_today, daily_limit)."""
        date_str = self._current_date()
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute(
                "SELECT count FROM daily_quotas WHERE provider = ? AND date = ?",
                (provider, date_str),
            )
            row = await cursor.fetchone()
            used = row[0] if row else 0
            return used, limit


class CircuitState(StrEnum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreaker:
    """Async circuit breaker guarding against repeated cascading calls to failing providers."""

    def __init__(
        self,
        provider: str,
        failure_threshold: int = 5,
        recovery_timeout: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.provider = provider
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.clock = clock

        self.state: CircuitState = CircuitState.CLOSED
        self.failure_count: int = 0
        self.last_failure_time: float = 0.0
        self._half_open_probe_in_flight: bool = False
        self._lock = asyncio.Lock()

    async def can_execute(self) -> bool:
        """Check if request execution is allowed under current circuit state.

        In HALF_OPEN state, only ONE caller may acquire permission to probe.
        Subsequent callers receive False until the probe completes (record_success/failure).
        """
        async with self._lock:
            now = self.clock()
            if self.state == CircuitState.OPEN:
                if now - self.last_failure_time > self.recovery_timeout:
                    self.state = CircuitState.HALF_OPEN
                    self._half_open_probe_in_flight = True
                    return True
                return False
            if self.state == CircuitState.HALF_OPEN:
                if not self._half_open_probe_in_flight:
                    self._half_open_probe_in_flight = True
                    return True
                return False
            return True

    async def release_probe(self) -> None:
        """Release the probe gate if a probe attempt was aborted before execution."""
        async with self._lock:
            self._half_open_probe_in_flight = False

    async def record_success(self) -> None:
        """Record a successful operation."""
        async with self._lock:
            self.failure_count = 0
            self.state = CircuitState.CLOSED
            self._half_open_probe_in_flight = False

    async def record_failure(self) -> None:
        """Record an operation failure and trip breaker if threshold is reached."""
        async with self._lock:
            self.failure_count += 1
            self.last_failure_time = self.clock()
            self._half_open_probe_in_flight = False

            if self.state == CircuitState.HALF_OPEN or self.failure_count >= self.failure_threshold:
                self.state = CircuitState.OPEN

    async def __aenter__(self) -> CircuitBreaker:
        if not await self.can_execute():
            raise CircuitBreakerOpenError(self.provider)
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> bool:
        if exc_type is not None:
            await self.record_failure()
            return False  # Do not suppress exception
        await self.record_success()
        return True


def parse_retry_after(response: httpx.Response, default: float = 1.0) -> float:
    """Extract Retry-After header in seconds (integer or float), falling back to default."""
    retry_header = response.headers.get("Retry-After")
    if not retry_header:
        return default
    try:
        return max(0.1, float(retry_header))
    except ValueError:
        return default


def create_retry_retrying(
    max_attempts: int = 3,
    min_wait: float = 0.5,
    max_wait: float = 4.0,
    sleep_fn: Callable[[float], Coroutine[Any, Any, None]] = asyncio.sleep,
) -> tenacity.AsyncRetrying:
    """Create tenacity retry policy for external HTTP provider requests.

    Retries on:
    - Network drops (httpx.NetworkError)
    - Timeouts (httpx.TimeoutException)
    - Server errors (5xx)
    - Rate limits (429)
    """

    def is_retryable_exception(exc: BaseException) -> bool:
        return isinstance(exc, (httpx.NetworkError, httpx.TimeoutException))

    return tenacity.AsyncRetrying(
        stop=tenacity.stop_after_attempt(max_attempts),
        wait=tenacity.wait_exponential(multiplier=min_wait, min=min_wait, max=max_wait)
        + tenacity.wait_random(0.0, 0.5),
        retry=tenacity.retry_if_exception(is_retryable_exception),
        reraise=True,
        sleep=sleep_fn,
    )
