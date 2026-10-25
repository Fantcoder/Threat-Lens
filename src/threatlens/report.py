"""Multi-format threat intelligence report generator.

Generates structured reports in JSON, CSV (flattened), GitHub-flavored Markdown,
and self-contained HTML cybersecurity dashboards.
"""

from __future__ import annotations

import csv
import html
import io
import json
from collections.abc import Sequence
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from threatlens.models import AggregatedReport, Verdict


class ReportFormat(StrEnum):
    """Supported output formats for ThreatLens reports."""

    JSON = "json"
    CSV = "csv"
    MARKDOWN = "markdown"
    MD = "md"
    HTML = "html"


def get_report_tags(r: AggregatedReport) -> list[str]:
    """Extract distinct tags across all providers."""
    seen: set[str] = set()
    result: list[str] = []
    for p in r.providers:
        for t in p.tags:
            if t not in seen:
                seen.add(t)
                result.append(t)
    return result


def get_report_malware_families(r: AggregatedReport) -> list[str]:
    """Extract distinct malware families across all providers."""
    seen: set[str] = set()
    result: list[str] = []
    for p in r.providers:
        for m in p.malware_families:
            if m not in seen:
                seen.add(m)
                result.append(m)
    return result


def get_report_first_seen(r: AggregatedReport) -> datetime | None:
    """Find earliest first-seen timestamp across providers."""
    dates = [p.first_seen for p in r.providers if p.first_seen is not None]
    return min(dates) if dates else None


def get_report_last_seen(r: AggregatedReport) -> datetime | None:
    """Find latest last-seen timestamp across providers."""
    dates = [p.last_seen for p in r.providers if p.last_seen is not None]
    return max(dates) if dates else None


def get_succeeded_providers(r: AggregatedReport) -> list[str]:
    """List provider names that returned successful responses."""
    return [p.provider for p in r.providers if p.status == "ok"]


def get_failed_providers(r: AggregatedReport) -> list[str]:
    """List provider names that returned error or rate limited responses."""
    return [p.provider for p in r.providers if p.status in ("error", "rate_limited")]


def _ensure_report_list(
    reports: Sequence[AggregatedReport] | AggregatedReport,
) -> list[AggregatedReport]:
    if isinstance(reports, AggregatedReport):
        return [reports]
    return list(reports)


def render_json(
    reports: Sequence[AggregatedReport] | AggregatedReport,
    *,
    indent: int = 2,
) -> str:
    """Renders one or more AggregatedReport objects as formatted JSON."""
    if isinstance(reports, AggregatedReport):
        return json.dumps(reports.model_dump(mode="json"), indent=indent)
    items = [r.model_dump(mode="json") for r in reports]
    return json.dumps(items, indent=indent)


def render_csv(reports: Sequence[AggregatedReport] | AggregatedReport) -> str:
    """Renders one or more AggregatedReport objects into a flattened CSV format."""
    report_list = _ensure_report_list(reports)
    output = io.StringIO()

    fieldnames = [
        "ioc",
        "ioc_type",
        "normalized_value",
        "verdict",
        "risk_score",
        "confidence",
        "cached",
        "providers_succeeded",
        "providers_failed",
        "tags",
        "malware_families",
        "first_seen",
        "last_seen",
        "virustotal_score",
        "otx_score",
        "abuseipdb_score",
        "generated_at",
    ]

    writer = csv.DictWriter(output, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()

    for r in report_list:
        subscores: dict[str, Any] = {}
        for item in r.score_breakdown:
            subscores[f"{item.provider.lower()}_score"] = item.subscore

        f_seen = get_report_first_seen(r)
        l_seen = get_report_last_seen(r)

        writer.writerow(
            {
                "ioc": r.ioc,
                "ioc_type": r.ioc_type.value,
                "normalized_value": r.normalized_value,
                "verdict": r.verdict.value,
                "risk_score": r.risk_score,
                "confidence": r.score_confidence,
                "cached": r.cached,
                "providers_succeeded": ";".join(get_succeeded_providers(r)),
                "providers_failed": ";".join(get_failed_providers(r)),
                "tags": ";".join(get_report_tags(r)),
                "malware_families": ";".join(get_report_malware_families(r)),
                "first_seen": f_seen.isoformat() if f_seen else "",
                "last_seen": l_seen.isoformat() if l_seen else "",
                "virustotal_score": subscores.get("virustotal_score", ""),
                "otx_score": subscores.get("otx_score", ""),
                "abuseipdb_score": subscores.get("abuseipdb_score", ""),
                "generated_at": r.generated_at.isoformat(),
            }
        )

    return output.getvalue()


def render_markdown(reports: Sequence[AggregatedReport] | AggregatedReport) -> str:
    """Renders one or more AggregatedReport objects as GitHub-flavored Markdown."""
    report_list = _ensure_report_list(reports)
    now_str = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Aggregate metrics
    total = len(report_list)
    malicious_count = sum(1 for r in report_list if r.verdict == Verdict.MALICIOUS)
    suspicious_count = sum(1 for r in report_list if r.verdict == Verdict.SUSPICIOUS)
    low_risk_count = sum(1 for r in report_list if r.verdict == Verdict.LOW_RISK)
    clean_count = sum(1 for r in report_list if r.verdict == Verdict.CLEAN)

    lines: list[str] = [
        "# ThreatLens Threat Intelligence Report",
        "",
        f"**Generated:** {now_str}  ",
        f"**Total Indicators:** {total} | "
        f"🔴 **Malicious:** {malicious_count} | "
        f"🟠 **Suspicious:** {suspicious_count} | "
        f"🟡 **Low Risk:** {low_risk_count} | "
        f"🟢 **Clean:** {clean_count}",
        "",
        "---",
        "",
        "## Summary Overview",
        "",
        "| Indicator | Type | Verdict | Risk Score | Confidence | Succeeded | Failed |",
        "| :--- | :--- | :--- | :---: | :---: | :--- | :--- |",
    ]

    for r in report_list:
        verdict_badge = {
            Verdict.MALICIOUS: "🔴 `MALICIOUS`",
            Verdict.SUSPICIOUS: "🟠 `SUSPICIOUS`",
            Verdict.LOW_RISK: "🟡 `LOW_RISK`",
            Verdict.CLEAN: "🟢 `CLEAN`",
            Verdict.UNKNOWN: "⚪ `UNKNOWN`",
        }.get(r.verdict, f"`{r.verdict.value.upper()}`")

        succeeded = ", ".join(get_succeeded_providers(r)) or "-"
        failed = ", ".join(get_failed_providers(r)) or "-"

        lines.append(
            f"| `{r.normalized_value}` | {r.ioc_type.value} | {verdict_badge} | "
            f"**{r.risk_score}**/100 | {r.score_confidence:.2f} | {succeeded} | {failed} |"
        )

    lines.extend(["", "---", "", "## Detailed Indicator Analysis", ""])

    for r in report_list:
        tags = get_report_tags(r)
        malware = get_report_malware_families(r)

        lines.append(f"### Indicator: `{r.normalized_value}` ({r.ioc_type.value})")
        lines.append(f"- **Verdict:** `{r.verdict.value.upper()}` (Risk Score: {r.risk_score}/100)")
        lines.append(f"- **Confidence:** {r.score_confidence:.2f}")
        lines.append(f"- **Cache State:** {'Cached' if r.cached else 'Fresh Query'}")

        if tags:
            lines.append(f"- **Tags:** {', '.join(f'`{t}`' for t in tags)}")
        if malware:
            lines.append(f"- **Malware Families:** {', '.join(f'`{m}`' for m in malware)}")

        if r.score_breakdown:
            lines.append("")
            lines.append("#### Provider Score Breakdown")
            lines.append("| Provider | Subscore | Weight | Reason |")
            lines.append("| :--- | :---: | :---: | :--- |")
            for item in r.score_breakdown:
                lines.append(
                    f"| {item.provider} | {item.subscore:.1f} | {item.weight:.2f} | {item.reason} |"
                )

        lines.append("")

    return "\n".join(lines)


def render_html(reports: Sequence[AggregatedReport] | AggregatedReport) -> str:
    """Renders a self-contained, responsive, modern cybersecurity dashboard HTML report.

    Features dark theme, zero CDN dependencies, inline styles, responsive KPI cards,
    and vanilla JavaScript for client-side column sorting and instant search filtering.
    """
    report_list = _ensure_report_list(reports)
    now_str = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")

    total = len(report_list)
    malicious_count = sum(1 for r in report_list if r.verdict == Verdict.MALICIOUS)
    suspicious_count = sum(1 for r in report_list if r.verdict == Verdict.SUSPICIOUS)
    low_risk_count = sum(1 for r in report_list if r.verdict == Verdict.LOW_RISK)
    clean_count = sum(1 for r in report_list if r.verdict == Verdict.CLEAN)

    rows_html: list[str] = []
    for idx, r in enumerate(report_list, start=1):
        verdict_class = f"badge-{r.verdict.value}"
        score_class = f"score-{r.verdict.value}"

        tags = get_report_tags(r)
        malware = get_report_malware_families(r)
        f_seen_dt = get_report_first_seen(r)
        l_seen_dt = get_report_last_seen(r)

        tags_html = "".join(f'<span class="chip">{html.escape(t)}</span>' for t in tags[:5])
        if len(tags) > 5:
            tags_html += f'<span class="chip chip-more">+{len(tags) - 5}</span>'
        if not tags_html:
            tags_html = '<span class="text-muted">-</span>'

        malware_html = "".join(
            f'<span class="chip chip-malware">{html.escape(m)}</span>' for m in malware[:3]
        )
        if len(malware) > 3:
            malware_html += f'<span class="chip chip-more">+{len(malware) - 3}</span>'
        if not malware_html:
            malware_html = '<span class="text-muted">-</span>'

        # Providers list
        prov_items = []
        for p in r.providers:
            p_class = "prov-ok" if p.status == "ok" else "prov-err"
            prov_items.append(
                f'<span class="prov-badge {p_class}" title="{html.escape(p.status)}">'
                f"{html.escape(p.provider)}</span>"
            )
        prov_html = " ".join(prov_items) if prov_items else '<span class="text-muted">-</span>'

        # Score breakdown summary
        breakdown_items = []
        for b in r.score_breakdown:
            breakdown_items.append(
                f"<li><strong>{html.escape(b.provider)}</strong>: {b.subscore:.1f}/100 "
                f"(w={b.weight:.2f}) &mdash; {html.escape(b.reason)}</li>"
            )
        breakdown_html = f"<ul>{''.join(breakdown_items)}</ul>" if breakdown_items else "None"

        f_seen = html.escape(f_seen_dt.isoformat()) if f_seen_dt else "N/A"
        l_seen = html.escape(l_seen_dt.isoformat()) if l_seen_dt else "N/A"
        c_status = "Cached" if r.cached else "Fresh"
        norm_val = html.escape(r.normalized_value)
        val_type = html.escape(r.ioc_type.value)
        v_upper = html.escape(r.verdict.value.upper())
        fill_pct = min(100.0, float(r.risk_score))

        row = f"""
        <tr class="ioc-row" id="row-{idx}">
            <td class="font-mono">{norm_val}</td>
            <td><span class="type-pill">{val_type}</span></td>
            <td><span class="badge {verdict_class}">{v_upper}</span></td>
            <td>
                <div class="score-container">
                    <span class="score-num {score_class}">{r.risk_score}</span>
                    <div class="progress-bar">
                        <div class="progress-fill {verdict_class}"
                             style="width: {fill_pct}%;"></div>
                    </div>
                </div>
            </td>
            <td>{r.score_confidence:.2f}</td>
            <td>{tags_html}</td>
            <td>{malware_html}</td>
            <td>{prov_html}</td>
            <td><button class="btn-toggle" onclick="toggleDetails({idx})">Details</button></td>
        </tr>
        <tr class="details-row" id="details-{idx}" style="display: none;">
            <td colspan="9">
                <div class="details-pane">
                    <h4>Breakdown & Metadata for <code>{norm_val}</code></h4>
                    <p><strong>First Seen:</strong> {f_seen} |
                       <strong>Last Seen:</strong> {l_seen} |
                       <strong>Cache Status:</strong> {c_status}</p>
                    <h5>Provider Score Reasons</h5>
                    {breakdown_html}
                </div>
            </td>
        </tr>
        """
        rows_html.append(row)

    table_body = "\n".join(rows_html)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ThreatLens Intelligence Report</title>
    <style>
        :root {{
            --bg-body: #0a0e17;
            --bg-card: #131b2e;
            --bg-hover: #1e293b;
            --border: #334155;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --accent: #38bdf8;
            --malicious: #ef4444;
            --suspicious: #f97316;
            --low-risk: #eab308;
            --clean: #10b981;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background-color: var(--bg-body);
            color: var(--text-main);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            padding: 2rem;
            line-height: 1.5;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border);
            padding-bottom: 1.5rem;
            margin-bottom: 2rem;
        }}
        .brand h1 {{
            font-size: 1.8rem;
            font-weight: 700;
            letter-spacing: -0.5px;
            color: var(--accent);
        }}
        .brand p {{ color: var(--text-muted); font-size: 0.9rem; margin-top: 0.25rem; }}
        .meta-timestamp {{ color: var(--text-muted); font-size: 0.85rem; font-family: monospace; }}

        /* KPI Cards Grid */
        .kpi-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .kpi-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.25rem;
            position: relative;
            overflow: hidden;
        }}
        .kpi-card::before {{
            content: "";
            position: absolute;
            top: 0; left: 0; right: 0;
            height: 3px;
        }}
        .kpi-card.total::before {{ background: var(--accent); }}
        .kpi-card.malicious::before {{ background: var(--malicious); }}
        .kpi-card.suspicious::before {{ background: var(--suspicious); }}
        .kpi-card.low_risk::before {{ background: var(--low-risk); }}
        .kpi-card.clean::before {{ background: var(--clean); }}
        .kpi-title {{
            font-size: 0.8rem;
            text-transform: uppercase;
            color: var(--text-muted);
            font-weight: 600;
            letter-spacing: 0.5px;
        }}
        .kpi-val {{ font-size: 2rem; font-weight: 700; margin-top: 0.25rem; }}

        /* Controls */
        .controls {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
            gap: 1rem;
        }}
        .search-box {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 0.6rem 1rem;
            color: var(--text-main);
            width: 100%;
            max-width: 350px;
            font-size: 0.9rem;
        }}
        .search-box:focus {{ outline: 1px solid var(--accent); border-color: var(--accent); }}

        /* Table */
        .table-wrap {{
            overflow-x: auto;
            border: 1px solid var(--border);
            border-radius: 8px;
            background: var(--bg-card);
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            text-align: left;
            font-size: 0.9rem;
        }}
        th, td {{
            padding: 0.85rem 1rem;
            border-bottom: 1px solid var(--border);
        }}
        th {{
            background: #111827;
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-muted);
            cursor: pointer;
            user-select: none;
        }}
        th:hover {{ color: var(--accent); }}
        tr.ioc-row:hover {{ background: var(--bg-hover); }}
        .font-mono {{
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 0.85rem;
        }}

        /* Badges & Chips */
        .badge {{
            display: inline-block;
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .badge-malicious {{
            background: rgba(239, 68, 68, 0.15);
            color: var(--malicious);
            border: 1px solid var(--malicious);
        }}
        .badge-suspicious {{
            background: rgba(249, 115, 22, 0.15);
            color: var(--suspicious);
            border: 1px solid var(--suspicious);
        }}
        .badge-low_risk {{
            background: rgba(234, 179, 8, 0.15);
            color: var(--low-risk);
            border: 1px solid var(--low-risk);
        }}
        .badge-clean {{
            background: rgba(16, 185, 129, 0.15);
            color: var(--clean);
            border: 1px solid var(--clean);
        }}
        .badge-unknown {{
            background: rgba(148, 163, 184, 0.15);
            color: var(--text-muted);
            border: 1px solid var(--border);
        }}

        .type-pill {{
            background: #1e293b;
            color: #cbd5e1;
            padding: 0.15rem 0.4rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-family: monospace;
        }}
        .chip {{
            background: #1e293b;
            border: 1px solid #334155;
            color: #94a3b8;
            padding: 0.1rem 0.35rem;
            border-radius: 3px;
            font-size: 0.75rem;
            margin-right: 0.2rem;
            display: inline-block;
        }}
        .chip-malware {{ border-color: var(--malicious); color: #fca5a5; }}
        .chip-more {{ background: #334155; color: #f1f5f9; }}

        .prov-badge {{
            font-size: 0.7rem;
            padding: 0.15rem 0.35rem;
            border-radius: 3px;
            font-family: monospace;
            text-transform: uppercase;
        }}
        .prov-ok {{ background: rgba(16, 185, 129, 0.2); color: #6ee7b7; }}
        .prov-err {{ background: rgba(239, 68, 68, 0.2); color: #fca5a5; }}

        /* Score Bars */
        .score-container {{ display: flex; align-items: center; gap: 0.5rem; }}
        .score-num {{ font-weight: 700; width: 35px; text-align: right; font-family: monospace; }}
        .score-malicious {{ color: var(--malicious); }}
        .score-suspicious {{ color: var(--suspicious); }}
        .score-low_risk {{ color: var(--low-risk); }}
        .score-clean {{ color: var(--clean); }}

        .progress-bar {{
            flex: 1;
            min-width: 60px;
            height: 6px;
            background: #1e293b;
            border-radius: 3px;
            overflow: hidden;
        }}
        .progress-fill {{ height: 100%; border-radius: 3px; }}
        .progress-fill.badge-malicious {{ background: var(--malicious); }}
        .progress-fill.badge-suspicious {{ background: var(--suspicious); }}
        .progress-fill.badge-low_risk {{ background: var(--low-risk); }}
        .progress-fill.badge-clean {{ background: var(--clean); }}

        .btn-toggle {{
            background: #334155;
            color: #f8fafc;
            border: none;
            border-radius: 4px;
            padding: 0.25rem 0.6rem;
            font-size: 0.75rem;
            cursor: pointer;
        }}
        .btn-toggle:hover {{ background: #475569; }}

        .details-pane {{
            background: #0f172a;
            padding: 1.25rem;
            border-radius: 6px;
            margin: 0.5rem 0;
            border: 1px dashed var(--border);
        }}
        .details-pane h4 {{ margin-bottom: 0.5rem; color: var(--accent); }}
        .details-pane h5 {{ margin: 0.75rem 0 0.25rem 0; color: #cbd5e1; }}
        .details-pane ul {{ margin-left: 1.5rem; color: var(--text-muted); font-size: 0.85rem; }}
    </style>
</head>
<body>

    <div class="header">
        <div class="brand">
            <h1>ThreatLens Intelligence Report</h1>
            <p>Aggregated multi-provider indicator scoring and normalization</p>
        </div>
        <div class="meta-timestamp">Report Time: {now_str}</div>
    </div>

    <div class="kpi-grid">
        <div class="kpi-card total">
            <div class="kpi-title">Total Analyzed</div>
            <div class="kpi-val">{total}</div>
        </div>
        <div class="kpi-card malicious">
            <div class="kpi-title">Malicious</div>
            <div class="kpi-val" style="color: var(--malicious);">{malicious_count}</div>
        </div>
        <div class="kpi-card suspicious">
            <div class="kpi-title">Suspicious</div>
            <div class="kpi-val" style="color: var(--suspicious);">{suspicious_count}</div>
        </div>
        <div class="kpi-card low_risk">
            <div class="kpi-title">Low Risk</div>
            <div class="kpi-val" style="color: var(--low-risk);">{low_risk_count}</div>
        </div>
        <div class="kpi-card clean">
            <div class="kpi-title">Clean</div>
            <div class="kpi-val" style="color: var(--clean);">{clean_count}</div>
        </div>
    </div>

    <div class="controls">
        <input type="text"
               id="searchInput"
               class="search-box"
               placeholder="Filter by indicator, type, verdict, tag..."
               onkeyup="filterRows()">
        <span id="matchCount" style="color: var(--text-muted); font-size: 0.85rem;">
            Showing {total} entries
        </span>
    </div>

    <div class="table-wrap">
        <table id="iocTable">
            <thead>
                <tr>
                    <th onclick="sortTable(0)">Indicator &#x25B4;&#x25BE;</th>
                    <th onclick="sortTable(1)">Type &#x25B4;&#x25BE;</th>
                    <th onclick="sortTable(2)">Verdict &#x25B4;&#x25BE;</th>
                    <th onclick="sortTable(3)">Risk Score &#x25B4;&#x25BE;</th>
                    <th onclick="sortTable(4)">Confidence &#x25B4;&#x25BE;</th>
                    <th>Tags</th>
                    <th>Malware</th>
                    <th>Providers</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                {table_body}
            </tbody>
        </table>
    </div>

    <script>
        function toggleDetails(id) {{
            const row = document.getElementById('details-' + id);
            if (row) {{
                row.style.display = row.style.display === 'none' ? 'table-row' : 'none';
            }}
        }}

        function filterRows() {{
            const input = document.getElementById('searchInput');
            const filter = input.value.toLowerCase();
            const table = document.getElementById('iocTable');
            const rows = table.getElementsByClassName('ioc-row');
            let visible = 0;

            for (let i = 0; i < rows.length; i++) {{
                const text = rows[i].textContent || rows[i].innerText;
                const detailsRow = document.getElementById('details-' + (i + 1));
                if (text.toLowerCase().indexOf(filter) > -1) {{
                    rows[i].style.display = '';
                    visible++;
                }} else {{
                    rows[i].style.display = 'none';
                    if (detailsRow) detailsRow.style.display = 'none';
                }}
            }}
            document.getElementById('matchCount').innerText = 'Showing ' + visible + ' entries';
        }}

        let sortDirections = {{}};
        function sortTable(n) {{
            const table = document.getElementById("iocTable");
            const tbody = table.tBodies[0];
            const rows = Array.from(tbody.querySelectorAll("tr.ioc-row"));
            const isAsc = !sortDirections[n];
            sortDirections[n] = isAsc;

            rows.sort((rowA, rowB) => {{
                const cellA = rowA.getElementsByTagName("TD")[n].innerText.trim();
                const cellB = rowB.getElementsByTagName("TD")[n].innerText.trim();

                const numA = parseFloat(cellA);
                const numB = parseFloat(cellB);
                if (!isNaN(numA) && !isNaN(numB)) {{
                    return isAsc ? numA - numB : numB - numA;
                }}
                return isAsc ? cellA.localeCompare(cellB) : cellB.localeCompare(cellA);
            }});

            rows.forEach((row, idx) => {{
                tbody.appendChild(row);
                const detailsId = row.id.replace('row-', 'details-');
                const detailsRow = document.getElementById(detailsId);
                if (detailsRow) tbody.appendChild(detailsRow);
            }});
        }}
    </script>
</body>
</html>
"""


def generate_report(
    reports: Sequence[AggregatedReport] | AggregatedReport,
    fmt: ReportFormat | str,
) -> str:
    """Dispatches generation to the appropriate renderer based on specified format."""
    normalized_format = fmt.value if isinstance(fmt, ReportFormat) else str(fmt).lower()
    if normalized_format in ("json",):
        return render_json(reports)
    if normalized_format in ("csv",):
        return render_csv(reports)
    if normalized_format in ("markdown", "md"):
        return render_markdown(reports)
    if normalized_format in ("html",):
        return render_html(reports)
    msg = f"Unsupported report format: {fmt}. Choose from json, csv, markdown, or html."
    raise ValueError(msg)
