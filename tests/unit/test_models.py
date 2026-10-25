"""Tests for core data models."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from threatlens.models import (
    AggregatedReport,
    GeoInfo,
    IoCType,
    ProviderResult,
    ScoreComponent,
    Verdict,
)


def test_ioc_type_enum() -> None:
    assert IoCType.IPV4 == "ipv4"
    assert IoCType.IPV6 == "ipv6"
    assert IoCType.DOMAIN == "domain"
    assert IoCType.URL == "url"
    assert IoCType.MD5 == "md5"
    assert IoCType.SHA1 == "sha1"
    assert IoCType.SHA256 == "sha256"


def test_provider_result_instantiation() -> None:
    now = datetime.now(UTC)
    geo = GeoInfo(country="US", asn=15169, as_owner="GOOGLE")
    res = ProviderResult(
        provider="virustotal",
        status="ok",
        malicious_votes=5,
        total_engines=72,
        confidence=0.85,
        reputation=10,
        tags=["malware", "c2"],
        malware_families=["emotet"],
        threat_actors=["apt29"],
        geo=geo,
        first_seen=now,
        last_seen=now,
        references=["https://virustotal.com/gui/file/123"],
        latency_ms=120,
        raw={"key": "val"},
    )
    assert res.provider == "virustotal"
    assert res.status == "ok"
    assert res.geo is not None and res.geo.asn == 15169
    assert res.confidence == 0.85
    assert len(res.tags) == 2


def test_provider_result_confidence_validation() -> None:
    with pytest.raises(ValidationError):
        ProviderResult(provider="test", status="ok", confidence=1.5)
    with pytest.raises(ValidationError):
        ProviderResult(provider="test", status="ok", confidence=-0.1)


def test_aggregated_report_instantiation() -> None:
    comp = ScoreComponent(
        provider="virustotal",
        subscore=80.0,
        weight=0.5,
        contribution=40.0,
        reason="15 engines flagged as malicious",
    )
    report = AggregatedReport(
        ioc="8.8.8.8",
        ioc_type=IoCType.IPV4,
        normalized_value="8.8.8.8",
        verdict=Verdict.MALICIOUS,
        risk_score=75,
        score_confidence=0.8,
        score_breakdown=[comp],
        providers=[],
    )
    assert report.risk_score == 75
    assert report.verdict == Verdict.MALICIOUS
    assert report.cached is False
    assert report.ttl_remaining == 0
