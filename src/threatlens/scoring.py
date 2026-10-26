"""ThreatLens Scoring Engine.

Pure, deterministic functions computing explainable threat scores and verdicts.
- VirusTotal nonlinear ratio mapping with malware tag bonuses.
- AlienVault OTX logarithmic pulse scaling with adversary/family bonuses.
- AbuseIPDB confidence score with low-report volume damping.
- Dynamic weight renormalization over responsive ('ok') providers.
- Fully explainable breakdown per provider.
"""

from __future__ import annotations

import math
from collections.abc import Mapping

from threatlens.config import Settings
from threatlens.models import ProviderResult, ScoreComponent, Verdict

# High-threat keywords that indicate confirmed malware attribution
_KNOWN_MALWARE_TAGS = frozenset(
    {
        "trojan",
        "ransomware",
        "malware",
        "botnet",
        "c2",
        "backdoor",
        "stealer",
        "rootkit",
        "spyware",
        "miner",
        "worm",
    }
)


def compute_virustotal_subscore(result: ProviderResult) -> tuple[float, str]:
    """Calculate VirusTotal subscore (0-100) and human-readable explanation.

    Formula:
      ratio = (malicious + 0.5 * suspicious) / max(total_engines, 1)
      - ratio == 0: 0.0
      - 0 < ratio < 0.25: maps smoothly from 20.0 to 90.0
      - ratio >= 0.25: maps smoothly from 90.0 to 100.0
      - Bonus +5 if tags contain high-threat malware indicators (max 100).
    """
    total = result.total_engines or 0
    malicious = result.malicious_votes or 0
    suspicious = result.suspicious_votes or 0

    if total == 0:
        return 0.0, "No detection engine statistics available"

    effective_bad = float(malicious) + 0.5 * float(suspicious)
    ratio = effective_bad / float(total)

    if ratio == 0.0:
        return 0.0, f"0/{total} engines detected threats (clean)"

    if ratio < 0.25:
        # Non-linear curve: starts at 20 for any positive detection, reaches 90 at 25%
        base = 20.0 + (ratio / 0.25) * 70.0
    else:
        # 25% to 100%: 90 to 100
        base = 90.0 + min(1.0, (ratio - 0.25) / 0.75) * 10.0

    # Malware family/tag bonus
    has_malware_tag = any(t.lower() in _KNOWN_MALWARE_TAGS for t in result.tags)
    bonus = 5.0 if has_malware_tag else 0.0

    subscore = min(100.0, base + bonus)
    if suspicious > 0:
        reason = (
            f"{malicious}/{total} engines flagged malicious, "
            f"{suspicious} suspicious (ratio {ratio:.1%})"
        )
    else:
        reason = f"{malicious}/{total} engines flagged malicious (ratio {ratio:.1%})"
    if bonus > 0.0:
        reason += "; malware tag bonus applied"

    return round(subscore, 1), reason


def compute_otx_subscore(result: ProviderResult) -> tuple[float, str]:
    """Calculate AlienVault OTX subscore (0-100) and explanation.

    Formula:
      Logarithmic curve on pulse count:
      - 0 pulses -> 0.0
      - 1-20 pulses -> log-scaled up to 85.0
      - Bonus +10 if named threat actor (adversary) or malware family is linked (max 100).
    """
    pulses = result.pulse_count or 0
    if pulses == 0:
        return 0.0, "0 threat pulses recorded in OTX"

    # Log2 curve: 1 pulse -> ~20, 5 pulses -> ~52, 20 pulses -> 85
    base = min(85.0, 20.0 * math.log2(pulses + 1.0))

    has_threat_intel = bool(result.threat_actors or result.malware_families)
    bonus = 10.0 if has_threat_intel else 0.0

    subscore = min(100.0, base + bonus)
    details = []
    if result.threat_actors:
        details.append(f"actors: {', '.join(result.threat_actors[:2])}")
    if result.malware_families:
        details.append(f"malware: {', '.join(result.malware_families[:2])}")

    reason = f"{pulses} threat pulse{'s' if pulses != 1 else ''}"
    if details:
        reason += f" ({'; '.join(details)})"

    return round(subscore, 1), reason


def compute_abuseipdb_subscore(result: ProviderResult) -> tuple[float, str]:
    """Calculate AbuseIPDB subscore (0-100) and explanation.

    Formula:
      Base = abuse_confidence (0-100).
      Damping: if total_reports < 3, damped by 50% to prevent single-report false positives.
    """
    raw_confidence = float(result.abuse_confidence or 0)
    reports = result.total_reports or 0

    if raw_confidence == 0.0 or reports == 0:
        return 0.0, "0% abuse confidence (0 reports)"

    damped = False
    if reports < 3:
        subscore = raw_confidence * 0.5
        damped = True
    else:
        subscore = raw_confidence

    subscore = min(100.0, max(0.0, subscore))
    reason = (
        f"{int(raw_confidence)}% confidence across {reports} report{'s' if reports != 1 else ''}"
    )
    if damped:
        reason += " (low-report volume damping applied)"

    return round(subscore, 1), reason


def score_report(
    provider_results: list[ProviderResult],
    settings: Settings,
    applicable_types_count: int | None = None,
) -> tuple[Verdict, int, float, list[ScoreComponent]]:
    """Aggregate provider results into an explainable verdict and score.

    Args:
        provider_results: Results from all queried providers.
        settings: Application settings with weights and thresholds.
        applicable_types_count: Total number of providers that support this IoC type.

    Returns:
        tuple[Verdict, int, float, list[ScoreComponent]]:
          - verdict: clean, low_risk, suspicious, malicious, or unknown
          - risk_score: 0-100 integer
          - score_confidence: 0.0-1.0 float based on responsive provider weights
          - score_breakdown: detailed per-provider contributions
    """
    # Filter to providers that returned 'ok'
    ok_results = [r for r in provider_results if r.status == "ok"]

    weights_map: Mapping[str, float] = {
        "virustotal": settings.weight_virustotal,
        "otx": settings.weight_otx,
        "abuseipdb": settings.weight_abuseipdb,
    }

    # If no provider succeeded, return UNKNOWN
    if not ok_results:
        return Verdict.UNKNOWN, 0, 0.0, []

    # Compute subscores
    subscores: dict[str, tuple[float, str]] = {}
    for r in ok_results:
        if r.provider == "virustotal":
            subscores[r.provider] = compute_virustotal_subscore(r)
        elif r.provider == "otx":
            subscores[r.provider] = compute_otx_subscore(r)
        elif r.provider == "abuseipdb":
            subscores[r.provider] = compute_abuseipdb_subscore(r)
        else:
            subscores[r.provider] = (0.0, f"Unknown provider {r.provider}")

    # Renormalize weights over providers that returned 'ok'
    total_ok_weight = sum(weights_map.get(r.provider, 0.0) for r in ok_results)
    if total_ok_weight <= 0.0:
        total_ok_weight = float(len(ok_results))
        active_weights = {r.provider: 1.0 / float(len(ok_results)) for r in ok_results}
    else:
        active_weights = {
            r.provider: weights_map.get(r.provider, 0.0) / total_ok_weight for r in ok_results
        }

    # Compute total applicable weight for score_confidence
    applicable_weight = sum(
        weights_map.get(r.provider, 0.0) for r in provider_results if r.status != "unsupported"
    )
    if applicable_weight > 0.0:
        score_confidence = min(1.0, total_ok_weight / applicable_weight)
    else:
        score_confidence = 1.0

    # Compute weighted sum
    breakdown: list[ScoreComponent] = []
    total_weighted_score = 0.0

    for r in ok_results:
        subscore, reason = subscores[r.provider]
        normalized_weight = active_weights[r.provider]
        contribution = subscore * normalized_weight
        total_weighted_score += contribution

        breakdown.append(
            ScoreComponent(
                provider=r.provider,
                subscore=subscore,
                weight=round(normalized_weight, 3),
                contribution=round(contribution, 1),
                reason=reason,
            )
        )

    weighted_average = total_weighted_score

    # Strong-signal floor: max(weighted_average, strong_signal_factor * max_subscore)
    max_subscore = 0.0
    max_provider: str | None = None
    for r in ok_results:
        subscore, _ = subscores[r.provider]
        if subscore > max_subscore:
            max_subscore = subscore
            max_provider = r.provider

    floor_score = settings.strong_signal_factor * max_subscore

    if floor_score > weighted_average:
        final_score = round(floor_score)
        for item in breakdown:
            if item.provider == max_provider:
                item.reason = f"{item.reason} (strong-signal floor applied: {final_score})"
    else:
        final_score = round(weighted_average)

    final_score = max(0, min(100, final_score))

    # Map to verdict thresholds
    if final_score <= settings.threshold_clean_max:
        verdict = Verdict.CLEAN
    elif final_score <= settings.threshold_low_risk_max:
        verdict = Verdict.LOW_RISK
    elif final_score <= settings.threshold_suspicious_max:
        verdict = Verdict.SUSPICIOUS
    else:
        verdict = Verdict.MALICIOUS

    # Guard against false-clean verdicts when confidence is too low due to unavailable providers
    if score_confidence < settings.min_confidence_for_clean and verdict in (
        Verdict.CLEAN,
        Verdict.LOW_RISK,
    ):
        verdict = Verdict.UNKNOWN
        for item in breakdown:
            item.reason = f"{item.reason} (inconclusive: provider(s) unavailable)"

    return verdict, final_score, round(score_confidence, 2), breakdown
