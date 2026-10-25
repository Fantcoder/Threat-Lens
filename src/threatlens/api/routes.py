"""FastAPI Route Handlers for ThreatLens."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from threatlens.aggregator import Aggregator
from threatlens.api.schemas import (
    BatchLookupItem,
    BatchLookupRequest,
    BatchLookupResponse,
    HealthResponse,
    ProvidersResponse,
    ProviderStatusItem,
)
from threatlens.cache import HistoryEntry
from threatlens.errors import InvalidIoCError
from threatlens.models import AggregatedReport

router = APIRouter()


def get_aggregator(request: Request) -> Aggregator:
    """Dependency extracting initialized Aggregator from application state."""
    aggregator: Aggregator = request.app.state.aggregator
    return aggregator


# ==============================================================================
# Health & Readiness Endpoints
# ==============================================================================


@router.get(
    "/health",
    response_model=HealthResponse,
    tags=["System"],
    summary="Service Liveness Probe",
)
async def health() -> HealthResponse:
    """Liveness probe indicating the service process is up and handling traffic."""
    return HealthResponse(
        status="ok",
        service="threatlens",
        timestamp=datetime.now(UTC).isoformat(),
    )


@router.get(
    "/ready",
    tags=["System"],
    summary="Service Readiness Probe",
    responses={
        200: {"description": "Service and database storage are ready."},
        503: {"description": "Database or storage unavailable."},
    },
)
async def readiness(request: Request) -> dict[str, str]:
    """Readiness probe verifying persistent SQLite database connectivity."""
    try:
        aggregator: Aggregator = request.app.state.aggregator
        await aggregator.cache.cleanup_expired()
        return {"status": "ready", "database": "connected"}
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Storage readiness check failed: {exc}",
        ) from exc


# ==============================================================================
# Threat Intelligence Endpoints
# ==============================================================================


@router.get(
    "/api/v1/lookup",
    response_model=AggregatedReport,
    tags=["Threat Intelligence"],
    summary="Lookup Single Indicator of Compromise",
    responses={
        200: {"description": "Successfully aggregated intelligence report."},
        400: {"description": "Invalid IoC format or private/reserved IP."},
        429: {"description": "Client rate limit exceeded."},
        502: {"description": "All threat intelligence providers failed."},
    },
)
async def lookup_ioc(
    ioc: Annotated[str, Query(description="Indicator to analyze (IP, domain, URL, or hash)")],
    aggregator: Annotated[Aggregator, Depends(get_aggregator)],
    refresh: Annotated[bool, Query(description="Bypass cache and force upstream refresh")] = False,
    include_raw: Annotated[bool, Query(description="Include raw provider JSON in result")] = False,
) -> AggregatedReport:
    """Auto-detects indicator type, queries providers concurrently,
    and returns normalized threat score.
    """
    try:
        report = await aggregator.lookup(ioc, refresh=refresh, include_raw=include_raw)
        return report
    except InvalidIoCError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc


@router.post(
    "/api/v1/lookup/batch",
    response_model=BatchLookupResponse,
    tags=["Threat Intelligence"],
    summary="Batch Lookup Indicators (Bounded Concurrency)",
)
async def batch_lookup(
    payload: BatchLookupRequest,
    aggregator: Annotated[Aggregator, Depends(get_aggregator)],
    refresh: Annotated[bool, Query(description="Bypass cache for all indicators")] = False,
    concurrency: Annotated[int, Query(ge=1, le=20, description="Max concurrent lookups")] = 5,
) -> BatchLookupResponse:
    """Analyze up to 100 indicators concurrently with bounded semaphore isolation."""
    semaphore = asyncio.Semaphore(concurrency)

    async def _process_single(single_ioc: str) -> BatchLookupItem:
        async with semaphore:
            try:
                report = await aggregator.lookup(single_ioc, refresh=refresh)
                return BatchLookupItem(ioc=single_ioc, success=True, report=report)
            except Exception as exc:
                return BatchLookupItem(ioc=single_ioc, success=False, error=str(exc))

    tasks = [_process_single(item) for item in payload.iocs]
    items = await asyncio.gather(*tasks)

    successful = sum(1 for it in items if it.success)
    failed = len(items) - successful

    return BatchLookupResponse(
        total=len(items),
        successful=successful,
        failed=failed,
        results=items,
    )


@router.get(
    "/api/v1/history",
    response_model=list[HistoryEntry],
    tags=["Audit & History"],
    summary="Query Recent Lookup Audit Log",
)
async def get_history(
    aggregator: Annotated[Aggregator, Depends(get_aggregator)],
    limit: Annotated[int, Query(ge=1, le=200, description="Max history entries to retrieve")] = 50,
) -> list[HistoryEntry]:
    """Retrieve audit history of evaluated indicators in reverse chronological order."""
    return await aggregator.cache.get_history(limit=limit)


@router.get(
    "/api/v1/providers",
    response_model=ProvidersResponse,
    tags=["System"],
    summary="List Configured Providers, Quotas, and Circuit States",
)
async def get_providers(
    aggregator: Annotated[Aggregator, Depends(get_aggregator)],
) -> ProvidersResponse:
    """Inspect provider operational telemetry, circuit states, and remaining daily quotas."""
    items: list[ProviderStatusItem] = []

    for p in aggregator.providers:
        # Check quota usage
        used, daily_limit = await aggregator.quota_tracker.get_usage(p.name, p.rate_limit_daily)

        # Check circuit breaker state
        cb = aggregator.circuit_breakers.get(p.name)
        circuit_state = cb.state.value if cb else "closed"

        # Check if API key is configured
        has_key = getattr(p, "api_key", None) is not None

        items.append(
            ProviderStatusItem(
                name=p.name,
                configured=has_key,
                supported_types=[t.value for t in p.supported_types],
                quota_used=used,
                quota_limit=daily_limit,
                circuit_state=circuit_state,
            )
        )

    return ProvidersResponse(providers=items)
