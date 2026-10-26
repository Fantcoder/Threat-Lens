# ThreatLens Scoring Engine Documentation

ThreatLens calculates a deterministic, explainable risk score (0–100) and assigns a categorical verdict to an Indicator of Compromise (IoC) based on normalized multi-provider threat intelligence.

> [!NOTE]
> Threat intelligence scoring is inherently a statistical and reputational heuristic, not ground truth. ThreatLens synthesizes third-party security telemetry; a clean score indicates an absence of reported malice, not guaranteed safety.

---

## 1. Core Principles

1. **Heuristic Assessment**: Threat intelligence scores are heuristic indicators of risk based on vendor consensus, telemetry feeds, and community pulses.
2. **Strong-Signal Preservation**: Neutral or non-reporting feeds ("nothing known") do not dilute overwhelming evidence of malice from high-detection feeds.
3. **Dynamic Weight Renormalization**: When one or more providers fail, time out, or are rate-limited, remaining responsive (`ok`) providers have their weights dynamically renormalized so the composite score remains calibrated on a 0–100 scale.
4. **Inconclusive Result Protection**: If key providers are offline and score confidence falls below `min_confidence_for_clean` (0.60), a potentially false `clean` or `low_risk` verdict is guarded and reported as `unknown` with a short cache TTL (15 minutes).
5. **Transparent Explainability**: Every aggregated score includes a full breakdown specifying each provider's subscore, active weight, arithmetic contribution, and plain-text audit explanation.

---

## 2. Verdict Thresholds

| Risk Score | Verdict | Interpretation |
|---|---|---|
| **0 – 9** | `clean` | No meaningful malicious indicators or threat engine detections. |
| **10 – 34** | `low_risk` | Low-volume or isolated scan reports; unlikely to be active malware infrastructure. |
| **35 – 64** | `suspicious` | Multiple detection engines, active threat pulses, or moderate abuse reports. |
| **65 – 100** | `malicious` | Significant consensus among AV engines, high confidence abuse reports, or confirmed adversary attribution. |
| **N/A** | `unknown` | Inconclusive intelligence (low confidence due to provider outages or all skipped/offline). |

---

## 3. Sub-Score Formulas

### A. VirusTotal (v3)

Let:
$$D_{\text{effective}} = \text{malicious\_votes} + 0.5 \times \text{suspicious\_votes}$$
$$R = \frac{D_{\text{effective}}}{\max(\text{total\_engines}, 1)}$$

The detection ratio $R \in [0, 1]$ is mapped across two non-linear zones:

1. **Clean**: If $R = 0$, $\text{Base} = 0.0$.
2. **Low to Moderate Detection** ($0 < R < 0.25$):
   $$\text{Base} = 20.0 + \left(\frac{R}{0.25}\right) \times 70.0$$
   *Even a single engine flagging an IoC provides a baseline score of 20, scaling up to 90 at a 25% detection ratio.*
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

## 4. Composite Scoring and Strong-Signal Floor

Configured default weights:
- VirusTotal: $W_{\text{VT}} = 0.50$
- AlienVault OTX: $W_{\text{OTX}} = 0.25$
- AbuseIPDB: $W_{\text{Abuse}} = 0.25$

For responsive providers $\mathcal{P}_{\text{ok}} \subseteq \{\text{VT}, \text{OTX}, \text{Abuse}\}$:

1. **Active Weight Renormalization**:
   $$W_{\text{total}} = \sum_{p \in \mathcal{P}_{\text{ok}}} W_p, \quad w_p = \frac{W_p}{W_{\text{total}}}$$

2. **Weighted Average**:
   $$\text{WeightedAverage} = \sum_{p \in \mathcal{P}_{\text{ok}}} S_p \times w_p$$

3. **Strong-Signal Floor**:
   To prevent passive/clean feeds from dragging down strong, high-detection signals:
   $$\text{FloorScore} = \text{round}\left(\text{strong\_signal\_factor} \times \max_{p \in \mathcal{P}_{\text{ok}}} S_p\right)$$
   $$\text{FinalScore} = \max\left(\text{round}(\text{WeightedAverage}), \text{FloorScore}\right)$$
   *(default `strong_signal_factor = 0.8`)*

   When $\text{FloorScore} > \text{WeightedAverage}$, the provider with the maximum subscore includes an explicit note in the audit breakdown: `(strong-signal floor applied: <score>)`.

4. **Inconclusive Confidence Guard**:
   $$\text{ScoreConfidence} = \frac{W_{\text{total}}}{W_{\text{applicable}}}$$
   If $\text{ScoreConfidence} < \text{min\_confidence\_for\_clean}$ ($0.60$) and the preliminary verdict is `clean` or `low_risk`, the verdict is adjusted to `unknown` with the note `(inconclusive: provider(s) unavailable)` and cached with the short 15-minute TTL (`ttl_unknown = 900`).

---

## 5. Worked Examples

### Example 1: Strong Detection vs Neutral Feeds (Strong-Signal Floor)
- **VirusTotal**: 45/90 engines $\rightarrow$ ratio $0.50 \ge 0.25 \rightarrow \text{base} = 90.0 + (0.25 / 0.75) \times 10 = 93.3$
- **OTX**: 0 pulses $\rightarrow$ SubScore = 0.0
- **AbuseIPDB**: 0% confidence, 0 reports $\rightarrow$ SubScore = 0.0
- **Weighted Average**: $93.3 \times 0.50 + 0 \times 0.25 + 0 \times 0.25 = 46.65 \approx 47$ (would dilute to `suspicious`).
- **Strong-Signal Floor**: $0.8 \times 93.3 = 74.64 \approx 75$.
- **Final Score**: $\max(47, 75) = 75$.
- **Verdict**: `malicious` (Risk score 75/100, Confidence 1.0).

---

### Example 2: Single Engine Scan Flag
- **VirusTotal**: 1/90 engines $\rightarrow$ ratio $1/90 = 0.0111 < 0.25 \rightarrow \text{base} = 20.0 + (0.0111 / 0.25) \times 70 = 23.1$
- **VT alone** (e.g. domain or hash not in OTX):
  - Weighted Average = 23.1.
  - Floor = $0.8 \times 23.1 = 18.5$.
  - Final Score = $\max(23, 18) = 23$.
- **Verdict**: `low_risk` (Risk score 23/100, $10 \le \text{score} \le 34$).

---

### Example 3: High Detection with Malware Tag
- **VirusTotal**: 60/70 engines, tags = `["trojan"]` $\rightarrow$ base $98.1 + 5.0 = 103.1 \rightarrow$ SubScore = 100.0 (clamped).
- **OTX**: 0 pulses $\rightarrow$ SubScore = 0.0.
- **Active Weights**: VT ($0.50/0.75 = 0.667$), OTX ($0.25/0.75 = 0.333$).
- **Weighted Average**: $100.0 \times 0.667 + 0.0 \times 0.333 = 66.67$.
- **Strong-Signal Floor**: $0.8 \times 100.0 = 80.0$.
- **Final Score**: $\max(67, 80) = 80$.
- **Verdict**: `malicious` (Risk score 80/100 $\ge 80$).

---

### Example 4: Completely Clean Indicator
- **VirusTotal**: 0/70 engines $\rightarrow$ SubScore = 0.0
- **OTX**: 0 pulses $\rightarrow$ SubScore = 0.0
- **AbuseIPDB**: 0% confidence, 0 reports $\rightarrow$ SubScore = 0.0
- **Weighted Average**: 0.0.
- **Strong-Signal Floor**: $0.8 \times 0.0 = 0.0$.
- **Final Score**: 0.
- **Verdict**: `clean` (Risk score 0/100, Confidence 1.0).
