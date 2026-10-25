# ThreatLens Scoring Engine Documentation

ThreatLens calculates a deterministic, explainable risk score (0–100) and assigns a categorical verdict to an Indicator of Compromise (IoC) based on normalized multi-provider intelligence.

---

## 1. Core Principles

1. **Heuristic, Not Ground Truth**: Threat intelligence aggregation is a statistical and reputational heuristic. ThreatLens synthesizes third-party observations; a clean score indicates an absence of reported malice, not guaranteed safety.
2. **Dynamic Weight Renormalization**: When one or more providers fail, time out, or are rate-limited, remaining responsive (`ok`) providers have their weights dynamically renormalized so the composite score remains calibrated on a 0–100 scale.
3. **Transparent Explainability**: Every aggregated score includes a full breakdown specifying each provider's subscore, active weight, arithmetic contribution, and a plain-text audit explanation.
4. **Degraded Confidence Reporting**: If only a fraction of applicable providers return results, the `score_confidence` metric is scaled down proportionally to reflect reduced visibility.

---

## 2. Verdict Thresholds

| Risk Score | Verdict | Interpretation |
|---|---|---|
| **0 – 9** | `clean` | No meaningful malicious indicators or threat engine detections. |
| **10 – 34** | `low_risk` | Low-volume or isolated scan reports; unlikely to be active malware infrastructure. |
| **35 – 64** | `suspicious` | Multiple detection engines, active threat pulses, or moderate abuse reports. |
| **65 – 100** | `malicious` | Significant consensus among AV engines, high confidence abuse reports, or confirmed adversary attribution. |
| **N/A** | `unknown` | No provider returned responsive (`ok`) data (e.g. all rate-limited or offline). |

---

## 3. Sub-Score Formulas

### A. VirusTotal (v3)

Let:
$$D_{\text{effective}} = \text{malicious} + 0.5 \times \text{suspicious}$$
$$R = \frac{D_{\text{effective}}}{\max(\text{total\_engines}, 1)}$$

The detection ratio $R \in [0, 1]$ is mapped across two non-linear zones:

1. **Clean**: If $R = 0$, $\text{Base} = 0.0$.
2. **Low to Moderate Detection** ($0 < R < 0.25$):
   $$\text{Base} = 20.0 + \left(\frac{R}{0.25}\right) \times 70.0$$
   *Even a single engine flagging an IoC provides a minimum score of 20, scaling up to 90 at a 25% detection ratio.*
3. **High Consensus** ($R \ge 0.25$):
   $$\text{Base} = 90.0 + \min\left(1.0, \frac{R - 0.25}{0.75}\right) \times 10.0$$

**Malware Tag Bonus**: An additional $+5.0$ bonus is added if provider tags include high-confidence malware keywords (e.g., `trojan`, `ransomware`, `c2`, `botnet`). Subscore is clamped to $[0, 100]$.

---

### B. AlienVault OTX

OTX scores are scaled logarithmically based on the number of community threat pulses referencing the indicator:

$$\text{Base} = \min\left(85.0, 20.0 \times \log_2(\text{pulse\_count} + 1)\right)$$

*Example curve:*
- 0 pulses $\rightarrow$ 0.0
- 1 pulse $\rightarrow$ 20.0
- 3 pulses $\rightarrow$ 40.0
- 5 pulses $\rightarrow$ 51.7
- 10 pulses $\rightarrow$ 69.2
- $\ge 20$ pulses $\rightarrow$ 85.0

**Adversary / Threat Actor Bonus**: $+10.0$ bonus is awarded if the indicator is explicitly tied to an adversary (e.g. `APT28`) or identified malware family. Subscore is clamped to $[0, 100]$.

---

### C. AbuseIPDB (IPs only)

$$\text{Base} = \text{abuseConfidenceScore} \in [0, 100]$$

**Low-Report Volume Damping**:
Single reports can often stem from port scans, misconfigured routers, or crawler noise. If $\text{totalReports} < 3$:
$$\text{SubScore} = \text{Base} \times 0.5$$

Otherwise, $\text{SubScore} = \text{Base}$.

---

## 4. Aggregate Scoring and Renormalization

Default configured weights:
- VirusTotal: $W_{\text{VT}} = 0.50$
- AlienVault OTX: $W_{\text{OTX}} = 0.25$
- AbuseIPDB: $W_{\text{Abuse}} = 0.25$

For a set of responsive providers $\mathcal{P}_{\text{ok}} \subseteq \{\text{VT}, \text{OTX}, \text{Abuse}\}$:

1. **Total Active Weight**:
   $$W_{\text{total}} = \sum_{p \in \mathcal{P}_{\text{ok}}} W_p$$

2. **Normalized Provider Weights**:
   $$w_p = \frac{W_p}{W_{\text{total}}}$$

3. **Composite Risk Score**:
   $$\text{RiskScore} = \text{round}\left( \sum_{p \in \mathcal{P}_{\text{ok}}} S_p \times w_p \right)$$

4. **Score Confidence**:
   $$\text{ScoreConfidence} = \frac{W_{\text{total}}}{W_{\text{applicable}}}$$
   where $W_{\text{applicable}}$ is the sum of weights of providers supporting this indicator type.

---

## 5. Worked Examples

### Example 1: Known Malicious IP (All Providers Responsive)
- **VirusTotal**: 18/74 engines flagged $\rightarrow$ ratio $0.243$, tag bonus applied $\rightarrow$ SubScore = 93.1
- **OTX**: 8 pulses with `APT28` adversary $\rightarrow$ base $63.4 + 10 = 73.4$
- **AbuseIPDB**: 85% confidence across 52 reports $\rightarrow$ SubScore = 85.0

$$\text{RiskScore} = 93.1 \times 0.50 + 73.4 \times 0.25 + 85.0 \times 0.25 = 46.55 + 18.35 + 21.25 = 86$$
- **Verdict**: `malicious` (Risk score 86/100, Confidence 1.0)

---

### Example 2: Clean Domain
- **VirusTotal**: 0/72 engines $\rightarrow$ SubScore = 0.0
- **OTX**: 0 pulses $\rightarrow$ SubScore = 0.0
- **AbuseIPDB**: Unsupported for domain type (not queried).

Active weights (VT 0.50, OTX 0.25):
$$w_{\text{VT}} = \frac{0.50}{0.75} \approx 0.667, \quad w_{\text{OTX}} = \frac{0.25}{0.75} \approx 0.333$$
$$\text{RiskScore} = 0$$
- **Verdict**: `clean` (Risk score 0/100, Confidence 1.0)

---

### Example 3: Partial Outage (VirusTotal Rate-Limited)
- **VirusTotal**: Rate limited (`status="rate_limited"`).
- **OTX**: 4 pulses $\rightarrow$ SubScore = 46.4
- **AbuseIPDB**: 70% confidence across 10 reports $\rightarrow$ SubScore = 70.0

Active weights: OTX (0.25) and AbuseIPDB (0.25), renormalized to 0.50 each:
$$\text{RiskScore} = 46.4 \times 0.50 + 70.0 \times 0.50 = 58$$
- **Verdict**: `suspicious` (Risk score 58/100)
- **Confidence**: $\frac{0.25 + 0.25}{0.50 + 0.25 + 0.25} = 0.50$ (50% confidence because VT did not respond).

---

## 6. Limitations and Caveats

1. **Temporal Lag**: New zero-day campaigns may have 0 detections on VirusTotal and 0 pulses on OTX for hours before signatures are created.
2. **Shared Hosting / Cloud IPs**: IP addresses associated with CDNs (Cloudflare, Fastly) or cloud providers (AWS, Azure) may receive abuse reports due to transient malicious tenants, while legitimate services share the same IP.
3. **Heuristic Calibration**: Weights are empirically balanced for common SOC triaging workflows. They can be tuned via `THREATLENS_WEIGHT_*` environment variables.
