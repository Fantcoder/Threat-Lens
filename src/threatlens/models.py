"""Unified data models for ThreatLens."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class IoCType(StrEnum):
    """Supported Indicator of Compromise (IoC) types."""

    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"


ProviderStatus = Literal[
    "ok",
    "not_found",
    "rate_limited",
    "error",
    "unsupported",
    "skipped",
]


class Verdict(StrEnum):
    """Categorical threat verdict computed from aggregate risk score."""

    CLEAN = "clean"
    LOW_RISK = "low_risk"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"


class GeoInfo(BaseModel):
    """Geographical and network autonomy context."""

    model_config = ConfigDict(extra="forbid")

    country: str | None = None
    asn: int | None = None
    as_owner: str | None = None


class ProviderResult(BaseModel):
    """Normalized response from a single threat intelligence provider."""

    model_config = ConfigDict(extra="forbid")

    provider: str
    status: ProviderStatus
    malicious_votes: int | None = None
    total_engines: int | None = None
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    reputation: int | None = None
    tags: list[str] = Field(default_factory=list)
    malware_families: list[str] = Field(default_factory=list)
    threat_actors: list[str] = Field(default_factory=list)
    pulse_count: int | None = None
    abuse_confidence: int | None = None
    total_reports: int | None = None
    geo: GeoInfo | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    references: list[str] = Field(default_factory=list)
    latency_ms: int = 0
    error_message: str | None = None
    raw: dict[str, Any] | None = None


class ScoreComponent(BaseModel):
    """Explainable breakdown element of how an individual provider contributed to the score."""

    model_config = ConfigDict(extra="forbid")

    provider: str
    subscore: float = Field(ge=0.0, le=100.0)
    weight: float = Field(ge=0.0)
    contribution: float = Field(ge=0.0, le=100.0)
    reason: str


class AggregatedReport(BaseModel):
    """Unified threat intelligence report aggregated across all configured providers."""

    model_config = ConfigDict(extra="forbid")

    ioc: str
    ioc_type: IoCType
    normalized_value: str
    verdict: Verdict
    risk_score: int = Field(ge=0, le=100)
    score_confidence: float = Field(ge=0.0, le=1.0)
    score_breakdown: list[ScoreComponent] = Field(default_factory=list)
    providers: list[ProviderResult] = Field(default_factory=list)
    cached: bool = False
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    ttl_remaining: int = 0
