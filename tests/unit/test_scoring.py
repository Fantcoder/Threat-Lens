"""Unit tests for the Scoring Engine with 100% branch coverage enforcement."""

from __future__ import annotations

import pytest

from threatlens.config import Settings
from threatlens.models import ProviderResult, Verdict
from threatlens.scoring import (
    compute_abuseipdb_subscore,
    compute_otx_subscore,
    compute_virustotal_subscore,
    score_report,
)


@pytest.fixture
def default_settings() -> Settings:
    return Settings()


# ==============================================================================
# VirusTotal Subscore Branch Coverage
# ==============================================================================


def test_virustotal_subscore_zero_engines() -> None:
    res = ProviderResult(provider="virustotal", status="ok", total_engines=0)
    score, reason = compute_virustotal_subscore(res)
    assert score == 0.0
    assert "No detection engine" in reason


def test_virustotal_subscore_clean() -> None:
    res = ProviderResult(provider="virustotal", status="ok", malicious_votes=0, total_engines=70)
    score, reason = compute_virustotal_subscore(res)
    assert score == 0.0
    assert "0/70 engines detected threats" in reason


def test_virustotal_subscore_low_detection_no_tags() -> None:
    # 2 / 70 = 0.0285 (< 0.25)
    res = ProviderResult(provider="virustotal", status="ok", malicious_votes=2, total_engines=70)
    score, reason = compute_virustotal_subscore(res)
    assert 20.0 <= score < 90.0
    assert "malware tag bonus" not in reason


def test_virustotal_subscore_low_detection_with_tags() -> None:
    res = ProviderResult(
        provider="virustotal",
        status="ok",
        malicious_votes=2,
        total_engines=70,
        tags=["trojan", "scanner"],
    )
    score, reason = compute_virustotal_subscore(res)
    assert score >= 25.0
    assert "malware tag bonus applied" in reason


def test_virustotal_subscore_high_detection_capped() -> None:
    # 40 / 70 = 0.571 (> 0.25)
    res = ProviderResult(
        provider="virustotal",
        status="ok",
        malicious_votes=40,
        total_engines=70,
        tags=["ransomware"],
    )
    score, _reason = compute_virustotal_subscore(res)
    assert score >= 90.0
    assert score <= 100.0


# ==============================================================================
# AlienVault OTX Subscore Branch Coverage
# ==============================================================================


def test_otx_subscore_zero_pulses() -> None:
    res = ProviderResult(provider="otx", status="ok", pulse_count=0)
    score, reason = compute_otx_subscore(res)
    assert score == 0.0
    assert "0 threat pulses" in reason


def test_otx_subscore_single_pulse_singular_reason() -> None:
    res = ProviderResult(provider="otx", status="ok", pulse_count=1)
    score, reason = compute_otx_subscore(res)
    assert 15.0 <= score <= 30.0
    assert "1 threat pulse" in reason
    assert "threat pulses" not in reason


def test_otx_subscore_with_adversary_and_malware() -> None:
    res = ProviderResult(
        provider="otx",
        status="ok",
        pulse_count=10,
        threat_actors=["APT29"],
        malware_families=["Cobalt Strike"],
    )
    score, reason = compute_otx_subscore(res)
    assert score > 65.0
    assert "actors: APT29" in reason
    assert "malware: Cobalt Strike" in reason


def test_otx_subscore_with_adversary_only() -> None:
    res = ProviderResult(
        provider="otx",
        status="ok",
        pulse_count=5,
        threat_actors=["Lazarus"],
    )
    score, reason = compute_otx_subscore(res)
    assert score > 50.0
    assert "actors: Lazarus" in reason
    assert "malware:" not in reason


def test_otx_subscore_with_malware_only() -> None:
    res = ProviderResult(
        provider="otx",
        status="ok",
        pulse_count=5,
        malware_families=["Emotet"],
    )
    score, reason = compute_otx_subscore(res)
    assert score > 50.0
    assert "malware: Emotet" in reason
    assert "actors:" not in reason


# ==============================================================================
# AbuseIPDB Subscore Branch Coverage
# ==============================================================================


def test_abuseipdb_subscore_zero_reports() -> None:
    res = ProviderResult(provider="abuseipdb", status="ok", abuse_confidence=0, total_reports=0)
    score, reason = compute_abuseipdb_subscore(res)
    assert score == 0.0
    assert "0% abuse confidence" in reason


def test_abuseipdb_subscore_low_reports_damped() -> None:
    # 1 report (< 3) -> 50% damping
    res = ProviderResult(provider="abuseipdb", status="ok", abuse_confidence=80, total_reports=1)
    score, reason = compute_abuseipdb_subscore(res)
    assert score == 40.0
    assert "low-report volume damping applied" in reason
    assert "1 report" in reason


def test_abuseipdb_subscore_high_reports() -> None:
    # 10 reports (>= 3) -> no damping
    res = ProviderResult(provider="abuseipdb", status="ok", abuse_confidence=85, total_reports=10)
    score, reason = compute_abuseipdb_subscore(res)
    assert score == 85.0
    assert "damping" not in reason
    assert "10 reports" in reason


# ==============================================================================
# Score Report Aggregation & Thresholds
# ==============================================================================


def test_score_report_no_ok_providers(default_settings: Settings) -> None:
    results = [
        ProviderResult(provider="virustotal", status="rate_limited"),
        ProviderResult(provider="otx", status="error"),
    ]
    verdict, score, conf, breakdown = score_report(results, default_settings)
    assert verdict == Verdict.UNKNOWN
    assert score == 0
    assert conf == 0.0
    assert breakdown == []


def test_score_report_clean_verdict(default_settings: Settings) -> None:
    results = [
        ProviderResult(provider="virustotal", status="ok", malicious_votes=0, total_engines=70),
        ProviderResult(provider="otx", status="ok", pulse_count=0),
    ]
    verdict, score, conf, breakdown = score_report(results, default_settings)
    assert verdict == Verdict.CLEAN
    assert score <= default_settings.threshold_clean_max
    assert conf == 1.0
    assert len(breakdown) == 2


def test_score_report_low_risk_verdict(default_settings: Settings) -> None:
    # VT ratio ~ 0.02 -> ~25
    results = [
        ProviderResult(provider="virustotal", status="ok", malicious_votes=1, total_engines=70),
        ProviderResult(provider="otx", status="ok", pulse_count=0),
    ]
    verdict, score, _, _ = score_report(results, default_settings)
    assert verdict == Verdict.LOW_RISK
    assert default_settings.threshold_clean_max < score <= default_settings.threshold_low_risk_max


def test_score_report_suspicious_verdict(default_settings: Settings) -> None:
    results = [
        ProviderResult(provider="virustotal", status="ok", malicious_votes=7, total_engines=70),
        ProviderResult(provider="otx", status="ok", pulse_count=3),
    ]
    verdict, score, _, _ = score_report(results, default_settings)
    assert verdict == Verdict.SUSPICIOUS
    assert (
        default_settings.threshold_low_risk_max < score <= default_settings.threshold_suspicious_max
    )


def test_score_report_malicious_verdict(default_settings: Settings) -> None:
    results = [
        ProviderResult(
            provider="virustotal",
            status="ok",
            malicious_votes=35,
            total_engines=70,
            tags=["trojan"],
        ),
        ProviderResult(provider="otx", status="ok", pulse_count=15, threat_actors=["APT28"]),
        ProviderResult(provider="abuseipdb", status="ok", abuse_confidence=95, total_reports=30),
    ]
    verdict, score, conf, breakdown = score_report(results, default_settings)
    assert verdict == Verdict.MALICIOUS
    assert score > default_settings.threshold_suspicious_max
    assert conf == 1.0
    assert len(breakdown) == 3


def test_score_report_partial_failure_renormalization(default_settings: Settings) -> None:
    # VT fails, only OTX succeeds
    results = [
        ProviderResult(provider="virustotal", status="rate_limited"),
        ProviderResult(provider="otx", status="ok", pulse_count=5),
    ]
    _verdict, _score, conf, breakdown = score_report(results, default_settings)
    # VT weight is 0.50, OTX is 0.25 -> total applicable is 0.75
    # ok weight is 0.25 -> confidence = 0.25 / 0.75 = 0.33
    assert conf == 0.33
    assert len(breakdown) == 1
    # OTX normalized weight should be 1.0 (100% of active)
    assert breakdown[0].weight == 1.0
    assert breakdown[0].contribution == breakdown[0].subscore


def test_score_report_zero_weight_fallback(default_settings: Settings) -> None:
    settings = Settings(
        weight_virustotal=0.0,
        weight_otx=0.0,
        weight_abuseipdb=0.0,
    )
    results = [
        ProviderResult(provider="virustotal", status="ok", malicious_votes=10, total_engines=70),
    ]
    _verdict, _score, conf, breakdown = score_report(results, settings)
    assert conf == 1.0
    assert breakdown[0].weight == 1.0


def test_score_report_unknown_provider(default_settings: Settings) -> None:
    results = [
        ProviderResult(provider="custom_unregistered", status="ok"),
    ]
    verdict, score, _conf, breakdown = score_report(results, default_settings)
    assert verdict == Verdict.CLEAN
    assert score == 0
    assert "Unknown provider custom_unregistered" in breakdown[0].reason


def test_virustotal_subscore_suspicious_votes_counted() -> None:
    # 0 malicious, 20 suspicious out of 90 -> effective_bad = 10, ratio = 10/90 = 0.111
    res = ProviderResult(
        provider="virustotal",
        status="ok",
        malicious_votes=0,
        suspicious_votes=20,
        total_engines=90,
    )
    score, reason = compute_virustotal_subscore(res)
    assert score > 0.0, f"Expected positive subscore from suspicious votes, got {score}"
    assert "suspicious" in reason.lower()


def test_strong_signal_floor_vt_45_90_otx_0_abuse_0_malicious(
    default_settings: Settings,
) -> None:
    # VT 45/90 (ratio 0.5, subscore 93.3), OTX 0 (subscore 0), AbuseIPDB 0 (subscore 0)
    # Weighted average: 93.3 * 0.5 = 46.65 (47, which would be suspicious)
    # Strong signal floor: 0.8 * 93.3 = 74.64 (75 -> malicious)
    results = [
        ProviderResult(provider="virustotal", status="ok", malicious_votes=45, total_engines=90),
        ProviderResult(provider="otx", status="ok", pulse_count=0),
        ProviderResult(provider="abuseipdb", status="ok", abuse_confidence=0, total_reports=0),
    ]
    verdict, score, _conf, breakdown = score_report(results, default_settings)
    assert verdict == Verdict.MALICIOUS, f"Expected MALICIOUS, got {verdict}"
    assert score >= 65
    assert any("strong-signal floor" in b.reason for b in breakdown)


def test_vt_1_90_alone_gives_low_risk(default_settings: Settings) -> None:
    # VT 1/90 alone -> ratio 1/90 = 0.011, subscore 23.1, floor 18.5, final_score = 23 -> LOW_RISK
    results = [
        ProviderResult(provider="virustotal", status="ok", malicious_votes=1, total_engines=90),
    ]
    verdict, score, _, _ = score_report(results, default_settings)
    assert verdict == Verdict.LOW_RISK, f"Expected LOW_RISK, got {verdict}"
    assert score <= default_settings.threshold_low_risk_max


def test_strong_signal_floor_vt_60_70_trojan_otx_0_malicious(
    default_settings: Settings,
) -> None:
    # VT 60/70 with trojan tag -> subscore 100.0, OTX 0 -> subscore 0.0
    # Weighted average: 100 * (0.5 / 0.75) = 66.7
    # Strong signal floor: 0.8 * 100 = 80.0 -> score >= 80 -> MALICIOUS
    results = [
        ProviderResult(
            provider="virustotal",
            status="ok",
            malicious_votes=60,
            total_engines=70,
            tags=["trojan"],
        ),
        ProviderResult(provider="otx", status="ok", pulse_count=0),
    ]
    verdict, score, _, breakdown = score_report(results, default_settings)
    assert verdict == Verdict.MALICIOUS, f"Expected MALICIOUS, got {verdict}"
    assert score >= 80, f"Expected score >= 80, got {score}"
    assert any("strong-signal floor" in b.reason for b in breakdown)


def test_everything_clean_stays_clean(default_settings: Settings) -> None:
    results = [
        ProviderResult(provider="virustotal", status="ok", malicious_votes=0, total_engines=70),
        ProviderResult(provider="otx", status="ok", pulse_count=0),
        ProviderResult(provider="abuseipdb", status="ok", abuse_confidence=0, total_reports=0),
    ]
    verdict, score, conf, _ = score_report(results, default_settings)
    assert verdict == Verdict.CLEAN
    assert score == 0
    assert conf == 1.0


def test_score_report_low_confidence_downgraded_to_unknown(default_settings: Settings) -> None:
    # VT fails, only OTX returns clean -> confidence = 0.33 (< 0.60)
    results = [
        ProviderResult(provider="virustotal", status="rate_limited"),
        ProviderResult(provider="otx", status="ok", pulse_count=0),
    ]
    verdict, score, conf, breakdown = score_report(results, default_settings)
    assert verdict == Verdict.UNKNOWN
    assert score == 0
    assert conf == 0.33
    assert any("inconclusive: provider(s) unavailable" in b.reason for b in breakdown)
