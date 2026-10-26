"""Unit tests for multi-format report generator (JSON, CSV, Markdown, HTML)."""

from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime
from typing import Any

import pytest

from threatlens.models import (
    AggregatedReport,
    IoCType,
    ProviderResult,
    ScoreComponent,
    Verdict,
)
from threatlens.report import (
    ReportFormat,
    generate_report,
    get_failed_providers,
    get_report_first_seen,
    get_report_last_seen,
    get_report_malware_families,
    get_report_tags,
    get_succeeded_providers,
    render_csv,
    render_html,
    render_json,
    render_markdown,
)


@pytest.fixture
def sample_reports() -> list[AggregatedReport]:
    """Generate diverse sample reports representing all verdicts and provider states."""
    t1 = datetime(2026, 1, 15, 10, 0, 0, tzinfo=UTC)
    t2 = datetime(2026, 5, 20, 15, 30, 0, tzinfo=UTC)

    r_malicious = AggregatedReport(
        ioc="185.220.101.5",
        ioc_type=IoCType.IPV4,
        normalized_value="185.220.101.5",
        verdict=Verdict.MALICIOUS,
        risk_score=85,
        score_confidence=0.95,
        score_breakdown=[
            ScoreComponent(
                provider="VirusTotal",
                subscore=90.0,
                weight=0.45,
                contribution=40.5,
                reason="High detection ratio: 45/90 engines",
            ),
            ScoreComponent(
                provider="AbuseIPDB",
                subscore=80.0,
                weight=0.35,
                contribution=28.0,
                reason="Abuse confidence 100% across 520 reports",
            ),
        ],
        providers=[
            ProviderResult(
                provider="virustotal",
                status="ok",
                malicious_votes=45,
                total_engines=90,
                tags=["tor", "scanner", "brute-force"],
                malware_families=["Mirai", "Mozi"],
                first_seen=t1,
                last_seen=t2,
            ),
            ProviderResult(
                provider="abuseipdb",
                status="ok",
                abuse_confidence=100,
                total_reports=520,
                first_seen=t1,
                last_seen=t2,
            ),
            ProviderResult(
                provider="otx",
                status="rate_limited",
                error_message="Daily quota exceeded",
            ),
        ],
        cached=False,
    )

    r_suspicious = AggregatedReport(
        ioc="evil-phishing.com",
        ioc_type=IoCType.DOMAIN,
        normalized_value="evil-phishing.com",
        verdict=Verdict.SUSPICIOUS,
        risk_score=50,
        score_confidence=0.75,
        score_breakdown=[
            ScoreComponent(
                provider="VirusTotal",
                subscore=50.0,
                weight=0.6,
                contribution=30.0,
                reason="3 engines detected phishing",
            )
        ],
        providers=[
            ProviderResult(
                provider="virustotal",
                status="ok",
                malicious_votes=3,
                total_engines=85,
                tags=["phishing"],
            )
        ],
        cached=True,
    )

    r_clean = AggregatedReport(
        ioc="1.1.1.1",
        ioc_type=IoCType.IPV4,
        normalized_value="1.1.1.1",
        verdict=Verdict.CLEAN,
        risk_score=0,
        score_confidence=1.0,
        score_breakdown=[],
        providers=[
            ProviderResult(
                provider="virustotal",
                status="ok",
                malicious_votes=0,
                total_engines=90,
            ),
            ProviderResult(
                provider="abuseipdb",
                status="ok",
                abuse_confidence=0,
                total_reports=0,
            ),
        ],
        cached=True,
    )

    r_low_risk = AggregatedReport(
        ioc="example.org",
        ioc_type=IoCType.DOMAIN,
        normalized_value="example.org",
        verdict=Verdict.LOW_RISK,
        risk_score=15,
        score_confidence=0.5,
        score_breakdown=[],
        providers=[],
        cached=False,
    )

    return [r_malicious, r_suspicious, r_clean, r_low_risk]


def test_helper_accessors(sample_reports: list[AggregatedReport]) -> None:
    mal = sample_reports[0]
    tags = get_report_tags(mal)
    assert "tor" in tags
    assert "scanner" in tags

    fams = get_report_malware_families(mal)
    assert "Mirai" in fams
    assert "Mozi" in fams

    f_seen = get_report_first_seen(mal)
    assert f_seen is not None
    assert f_seen.year == 2026

    l_seen = get_report_last_seen(mal)
    assert l_seen is not None

    succ = get_succeeded_providers(mal)
    assert "virustotal" in succ
    assert "abuseipdb" in succ

    failed = get_failed_providers(mal)
    assert "otx" in failed

    # Empty providers check
    empty_rep = sample_reports[3]
    assert get_report_first_seen(empty_rep) is None
    assert get_report_last_seen(empty_rep) is None
    assert get_report_tags(empty_rep) == []
    assert get_report_malware_families(empty_rep) == []


def test_render_json_single_and_multiple(sample_reports: list[AggregatedReport]) -> None:
    # Single
    single_json = render_json(sample_reports[0])
    parsed_single: dict[str, Any] = json.loads(single_json)
    assert parsed_single["ioc"] == "185.220.101.5"
    assert parsed_single["verdict"] == "malicious"

    # Multiple
    multi_json = render_json(sample_reports)
    parsed_multi: list[dict[str, Any]] = json.loads(multi_json)
    assert len(parsed_multi) == 4
    assert parsed_multi[1]["ioc"] == "evil-phishing.com"


def test_render_csv(sample_reports: list[AggregatedReport]) -> None:
    csv_str = render_csv(sample_reports)
    reader = csv.DictReader(io.StringIO(csv_str))
    rows = list(reader)

    assert len(rows) == 4
    # Header check
    assert "ioc" in rows[0]
    assert "risk_score" in rows[0]
    assert "verdict" in rows[0]
    assert "tags" in rows[0]
    assert "malware_families" in rows[0]
    assert "virustotal_score" in rows[0]

    # Row 0 (Malicious)
    assert rows[0]["ioc"] == "185.220.101.5"
    assert rows[0]["verdict"] == "malicious"
    assert rows[0]["risk_score"] == "85"
    assert "tor" in rows[0]["tags"]
    assert "Mirai" in rows[0]["malware_families"]
    assert rows[0]["virustotal_score"] == "90.0"
    assert rows[0]["abuseipdb_score"] == "80.0"


def test_render_markdown(sample_reports: list[AggregatedReport]) -> None:
    md_str = render_markdown(sample_reports)

    # Title & summary counts
    assert "# ThreatLens Threat Intelligence Report" in md_str
    assert "Total Indicators:** 4" in md_str
    assert "Malicious:** 1" in md_str
    assert "Suspicious:** 1" in md_str
    assert "Clean:** 1" in md_str

    # Table format
    assert "| `185.220.101.5` | ipv4 | 🔴 `MALICIOUS` | **85**/100" in md_str
    assert "| `evil-phishing.com` | domain | 🟠 `SUSPICIOUS` | **50**/100" in md_str
    assert "| `1.1.1.1` | ipv4 | 🟢 `CLEAN` | **0**/100" in md_str

    # Detailed breakdown
    assert "### Indicator: `185.220.101.5` (ipv4)" in md_str
    assert "Mirai" in md_str
    assert "High detection ratio" in md_str


def test_render_html(sample_reports: list[AggregatedReport]) -> None:
    html_str = render_html(sample_reports)

    # Basic page structure
    assert "<!DOCTYPE html>" in html_str
    assert "<title>ThreatLens Intelligence Report</title>" in html_str
    assert "ThreatLens Intelligence Report" in html_str

    # KPI counts
    assert '<div class="kpi-val">4</div>' in html_str  # Total
    assert '<div class="kpi-val" style="color: var(--malicious);">1</div>' in html_str

    # Indicators present in table cells
    for r in sample_reports:
        assert f'<td class="font-mono">{r.normalized_value}</td>' in html_str
    assert "Mirai" in html_str

    # Vanilla JS and inline CSS
    assert "function sortTable(" in html_str
    assert "function filterRows(" in html_str
    assert "function toggleDetails(" in html_str
    assert "details-pane" in html_str


def test_generate_report_dispatcher(sample_reports: list[AggregatedReport]) -> None:
    j = generate_report(sample_reports, ReportFormat.JSON)
    assert j.startswith("[")

    c = generate_report(sample_reports, "csv")
    assert "ioc,ioc_type" in c

    m1 = generate_report(sample_reports, ReportFormat.MARKDOWN)
    assert "# ThreatLens" in m1

    m2 = generate_report(sample_reports, "md")
    assert "# ThreatLens" in m2

    h = generate_report(sample_reports, ReportFormat.HTML)
    assert "<!DOCTYPE html>" in h

    with pytest.raises(ValueError, match="Unsupported report format"):
        generate_report(sample_reports, "xml")


def test_batch_50_synthetic_indicators() -> None:
    """Generate 50 synthetic reports to ensure report generation scales smoothly."""
    reports: list[AggregatedReport] = []
    verdicts = [Verdict.CLEAN, Verdict.LOW_RISK, Verdict.SUSPICIOUS, Verdict.MALICIOUS]

    for i in range(1, 51):
        v = verdicts[i % 4]
        score = (i * 2) % 100
        reports.append(
            AggregatedReport(
                ioc=f"192.0.2.{i}",
                ioc_type=IoCType.IPV4,
                normalized_value=f"192.0.2.{i}",
                verdict=v,
                risk_score=score,
                score_confidence=0.8,
                providers=[
                    ProviderResult(
                        provider="virustotal",
                        status="ok",
                        tags=[f"tag_{i}"] if i % 2 == 0 else [],
                    )
                ],
            )
        )

    assert len(reports) == 50

    json_rep = generate_report(reports, ReportFormat.JSON)
    assert len(json.loads(json_rep)) == 50

    csv_rep = generate_report(reports, ReportFormat.CSV)
    assert len(csv_rep.strip().split("\n")) == 51  # 50 rows + header

    md_rep = generate_report(reports, ReportFormat.MARKDOWN)
    assert "Total Indicators:** 50" in md_rep

    html_rep = generate_report(reports, ReportFormat.HTML)
    assert 'class="kpi-val">50</div>' in html_rep
