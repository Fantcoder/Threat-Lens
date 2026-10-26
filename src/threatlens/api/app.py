"""FastAPI Application Factory, Lifespan, and Middleware Configuration."""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import logging
import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from threatlens.aggregator import Aggregator
from threatlens.api.routes import router
from threatlens.api.schemas import ProblemDetail
from threatlens.cache import LookupCache
from threatlens.config import Settings, get_settings
from threatlens.errors import InvalidIoCError, RateLimitExceededError
from threatlens.logging import (
    register_secret_for_redaction,
    request_id_ctx,
    setup_logging,
)
from threatlens.providers.abuseipdb import AbuseIPDBProvider
from threatlens.providers.otx import OTXProvider
from threatlens.providers.virustotal import VirusTotalProvider
from threatlens.ratelimit import DailyQuotaTracker, TokenBucket

logger = logging.getLogger("threatlens.api")


class ClientRateLimiter:
    """Bounded per-IP token bucket container with automatic idle bucket eviction."""

    def __init__(
        self,
        capacity: int,
        max_clients: int = 10_000,
        idle_ttl: float = 300.0,
    ) -> None:
        self.capacity = capacity
        self.max_clients = max_clients
        self.idle_ttl = idle_ttl
        self._buckets: dict[str, tuple[TokenBucket, float]] = {}
        self._lock = asyncio.Lock()

    async def acquire(self, client_ip: str) -> bool:
        now = time.monotonic()
        async with self._lock:
            if len(self._buckets) >= self.max_clients:
                to_del = [
                    ip for ip, (_, last) in self._buckets.items() if now - last > self.idle_ttl
                ]
                for ip in to_del:
                    del self._buckets[ip]
                if len(self._buckets) >= self.max_clients:
                    oldest = min(self._buckets, key=lambda k: self._buckets[k][1])
                    del self._buckets[oldest]

            if client_ip in self._buckets:
                bucket, _ = self._buckets[client_ip]
            else:
                bucket = TokenBucket(
                    capacity=self.capacity,
                    refill_rate=self.capacity / 60.0,
                )
            self._buckets[client_ip] = (bucket, now)
            return await bucket.acquire(1.0, max_wait=0.0)


def create_app(settings: Settings | None = None) -> FastAPI:
    """Create and configure a production-ready ThreatLens FastAPI application."""
    active_settings = settings or get_settings()

    # Configure structured logging and register secrets for redaction
    setup_logging(active_settings.log_level)
    if active_settings.virustotal_api_key:
        register_secret_for_redaction(active_settings.virustotal_api_key.get_secret_value())
    if active_settings.otx_api_key:
        register_secret_for_redaction(active_settings.otx_api_key.get_secret_value())
    if active_settings.abuseipdb_api_key:
        register_secret_for_redaction(active_settings.abuseipdb_api_key.get_secret_value())
    if active_settings.api_key:
        register_secret_for_redaction(active_settings.api_key.get_secret_value())

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        # --- Startup Phase ---
        logger.info("Initializing ThreatLens service resources...")
        active_settings.cache_dir.mkdir(parents=True, exist_ok=True)

        http_client = httpx.AsyncClient(timeout=30.0)
        cache = LookupCache(active_settings.cache_dir / "cache.sqlite")
        await cache.initialize()
        await cache.cleanup_expired()

        # Start periodic background cleanup task (every 5 minutes)
        cleanup_stop = asyncio.Event()

        async def periodic_cache_cleanup() -> None:
            while not cleanup_stop.is_set():
                try:
                    await asyncio.wait_for(cleanup_stop.wait(), timeout=300.0)
                except TimeoutError:
                    try:
                        await cache.cleanup_expired()
                    except Exception as exc:
                        logger.warning("Periodic cache cleanup failed: %s", exc)

        cleanup_task = asyncio.create_task(periodic_cache_cleanup())

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

        providers = [
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

        aggregator = Aggregator(
            providers=providers,
            cache=cache,
            quota_tracker=quota_tracker,
            settings=active_settings,
            client=http_client,
        )

        # Attach dependencies to app state for handler access
        app.state.settings = active_settings
        app.state.http_client = http_client
        app.state.cache = cache
        app.state.quota_tracker = quota_tracker
        app.state.aggregator = aggregator

        logger.info("ThreatLens service ready.")
        yield

        # --- Shutdown Phase ---
        logger.info("Shutting down ThreatLens service resources...")
        cleanup_stop.set()
        cleanup_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await cleanup_task
        await http_client.aclose()
        logger.info("Shutdown complete.")

    app = FastAPI(
        title="ThreatLens",
        description="Production-grade Threat Intelligence Aggregator & Normalizer API",
        version="1.0.0",
        lifespan=lifespan,
    )

    # Configurable CORS (restricted to configured origins without credentials)
    if active_settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=active_settings.cors_origins,
            allow_credentials=False,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    # In-memory bounded per-client IP rate limiter
    client_limiter = ClientRateLimiter(capacity=active_settings.client_rate_limit)

    # Middleware: Request ID tracking, Client Rate Limiting & API Key Auth
    @app.middleware("http")
    async def threatlens_middleware(request: Request, call_next: Any) -> Response:
        req_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        request_id_ctx.set(req_id)

        # Exclude public endpoints from authentication & client rate-limiting
        path = request.url.path
        is_public = path in ("/health", "/ready", "/docs", "/openapi.json", "/redoc")

        if not is_public and path.startswith("/api/"):
            # Client IP Rate Limiting (Bounded)
            client_ip = request.client.host if request.client else "unknown"
            if not await client_limiter.acquire(client_ip):
                problem = ProblemDetail(
                    title="Too Many Requests",
                    status=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=(
                        f"Client rate limit ({active_settings.client_rate_limit} req/min) exceeded"
                    ),
                    instance=path,
                )
                return JSONResponse(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    content=problem.model_dump(),
                    headers={"X-Request-ID": req_id},
                )

            # Service API-Key Authentication (Timing-Safe Comparison)
            if active_settings.api_key:
                provided_key = request.headers.get("X-API-Key")
                expected_key = active_settings.api_key.get_secret_value()
                if not provided_key or not hmac.compare_digest(
                    provided_key.encode("utf-8"), expected_key.encode("utf-8")
                ):
                    problem = ProblemDetail(
                        title="Unauthorized",
                        status=status.HTTP_401_UNAUTHORIZED,
                        detail="Invalid or missing X-API-Key header",
                        instance=path,
                    )
                    return JSONResponse(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        content=problem.model_dump(),
                        headers={"X-Request-ID": req_id},
                    )

        response: Response = await call_next(request)
        response.headers["X-Request-ID"] = req_id
        return response

    # RFC 7807 Problem Details Exception Handlers
    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
        problem = ProblemDetail(
            title=exc.detail if isinstance(exc.detail, str) else "HTTP Error",
            status=exc.status_code,
            detail=str(exc.detail),
            instance=request.url.path,
        )
        return JSONResponse(
            status_code=exc.status_code,
            content=problem.model_dump(),
            headers={"content-type": "application/problem+json"},
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        problem = ProblemDetail(
            title="Validation Error",
            status=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc.errors()),
            instance=request.url.path,
        )
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=problem.model_dump(),
            headers={"content-type": "application/problem+json"},
        )

    @app.exception_handler(InvalidIoCError)
    async def invalid_ioc_handler(request: Request, exc: InvalidIoCError) -> JSONResponse:
        problem = ProblemDetail(
            title="Invalid IoC Indicator",
            status=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
            instance=request.url.path,
        )
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=problem.model_dump(),
            headers={"content-type": "application/problem+json"},
        )

    @app.exception_handler(RateLimitExceededError)
    async def rate_limit_handler(request: Request, exc: RateLimitExceededError) -> JSONResponse:
        problem = ProblemDetail(
            title="Rate Limit Exceeded",
            status=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(exc),
            instance=request.url.path,
        )
        headers = {"content-type": "application/problem+json"}
        if exc.retry_after:
            headers["Retry-After"] = str(int(exc.retry_after))
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content=problem.model_dump(),
            headers=headers,
        )

    app.include_router(router)
    return app
