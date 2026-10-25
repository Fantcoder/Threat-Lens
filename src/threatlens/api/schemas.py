"""API Request and Response Pydantic Schemas."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from threatlens.models import AggregatedReport


class ProblemDetail(BaseModel):
    """RFC 7807 Problem Details representation for HTTP error responses."""

    model_config = ConfigDict(extra="allow")

    type: str = "about:blank"
    title: str
    status: int
    detail: str
    instance: str | None = None


class BatchLookupRequest(BaseModel):
    """Request payload for batch indicator analysis."""

    model_config = ConfigDict(extra="forbid")

    iocs: list[str] = Field(
        ...,
        min_length=1,
        max_length=100,
        description="List of Indicator of Compromise strings (max 100).",
        examples=[["8.8.8.8", "hxxp://malicious[.]org", "44d88612fea8a8f36de82e1278abb02f"]],
    )


class BatchLookupItem(BaseModel):
    """Evaluation result for an individual indicator within a batch."""

    model_config = ConfigDict(extra="forbid")

    ioc: str
    success: bool
    report: AggregatedReport | None = None
    error: str | None = None


class BatchLookupResponse(BaseModel):
    """Aggregated batch lookup response containing individual indicator outcomes."""

    model_config = ConfigDict(extra="forbid")

    total: int
    successful: int
    failed: int
    results: list[BatchLookupItem]


class ProviderStatusItem(BaseModel):
    """Operational telemetry and quota state of an individual provider."""

    model_config = ConfigDict(extra="forbid")

    name: str
    configured: bool
    supported_types: list[str]
    quota_used: int
    quota_limit: int
    circuit_state: str


class ProvidersResponse(BaseModel):
    """System-wide provider status and quota summary."""

    model_config = ConfigDict(extra="forbid")

    providers: list[ProviderStatusItem]


class HealthResponse(BaseModel):
    """Service liveness response schema."""

    status: str
    service: str = "threatlens"
    timestamp: str
