"""ThreatLens Command Line Interface (CLI).

Provides commands to lookup single IoCs, execute batch analysis with multi-format reports,
inspect provider quotas and circuit breakers, and run the FastAPI server.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Annotated

import typer
import uvicorn
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from threatlens.aggregator import Aggregator
from threatlens.config import Settings
from threatlens.errors import InvalidIoCError
from threatlens.models import AggregatedReport, Verdict
from threatlens.ratelimit import CircuitState
from threatlens.report import (
    ReportFormat,
    generate_report,
    get_failed_providers,
    get_report_malware_families,
    get_report_tags,
    get_succeeded_providers,
)

app = typer.Typer(
    name="threatlens",
    help="ThreatLens: Multi-provider Threat Intelligence Aggregator & CLI.",
    no_args_is_help=True,
    add_completion=False,
)

console = Console()
err_console = Console(stderr=True)


def _verdict_color(verdict: Verdict) -> str:
    if verdict == Verdict.MALICIOUS:
        return "bold red"
    if verdict == Verdict.SUSPICIOUS:
        return "bold dark_orange"
    if verdict == Verdict.LOW_RISK:
        return "bold yellow"
    if verdict == Verdict.CLEAN:
        return "bold green"
    return "dim white"


def _circuit_color(state: CircuitState) -> str:
    if state == CircuitState.CLOSED:
        return "green"
    if state == CircuitState.HALF_OPEN:
        return "yellow"
    return "bold red"


@app.command(name="lookup", help="Analyze an indicator (IP, domain, URL, or hash).")
def lookup_command(
    ioc: Annotated[str, typer.Argument(help="Indicator to analyze (IP, domain, URL, or hash)")],
    json_output: Annotated[
        bool, typer.Option("--json", "-j", help="Output results as JSON")
    ] = False,
    refresh: Annotated[
        bool, typer.Option("--refresh", "-r", help="Bypass cache and force fresh query")
    ] = False,
    include_raw: Annotated[
        bool, typer.Option("--raw", help="Include raw provider JSON payloads")
    ] = False,
) -> None:
    """Analyze an IoC across configured threat intelligence providers."""

    async def _run() -> AggregatedReport:
        settings = Settings()
        aggregator = await Aggregator.create(settings=settings)
        try:
            return await aggregator.lookup(ioc, refresh=refresh, include_raw=include_raw)
        finally:
            await aggregator.close()

    try:
        report = asyncio.run(_run())
    except InvalidIoCError as exc:
        err_console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc
    except Exception as exc:
        err_console.print(f"[bold red]Unexpected Error:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    if json_output:
        console.print(generate_report(report, ReportFormat.JSON))
    else:
        color = _verdict_color(report.verdict)
        verdict_text = f"[{color}]{report.verdict.value.upper()}[/{color}]"

        summary_table = Table(show_header=False, box=None, padding=(0, 2))
        summary_table.add_column("Key", style="bold cyan")
        summary_table.add_column("Value")

        tags = get_report_tags(report)
        malware = get_report_malware_families(report)
        succeeded = get_succeeded_providers(report)
        failed = get_failed_providers(report)

        summary_table.add_row("Indicator", report.normalized_value)
        summary_table.add_row("Type", report.ioc_type.value)
        summary_table.add_row("Verdict", verdict_text)
        summary_table.add_row("Risk Score", f"[{color}]{report.risk_score}[/{color}] / 100")
        summary_table.add_row("Confidence", f"{report.score_confidence:.2f}")
        summary_table.add_row("Cached", "Yes" if report.cached else "No")
        summary_table.add_row("Succeeded", ", ".join(succeeded) or "None")
        summary_table.add_row("Failed", ", ".join(failed) or "None")

        if tags:
            summary_table.add_row("Tags", ", ".join(tags))
        if malware:
            summary_table.add_row(
                "Malware Families",
                f"[bold red]{', '.join(malware)}[/bold red]",
            )

        console.print(
            Panel(
                summary_table,
                title=f"[bold]ThreatLens Intelligence &mdash; {report.normalized_value}[/bold]",
                border_style=color,
            )
        )

        # Provider breakdown table
        if report.score_breakdown:
            bd_table = Table(
                title="Provider Score Breakdown",
                header_style="bold magenta",
                show_lines=True,
            )
            bd_table.add_column("Provider", style="cyan")
            bd_table.add_column("Subscore", justify="right")
            bd_table.add_column("Weight", justify="right")
            bd_table.add_column("Reason")

            for item in report.score_breakdown:
                bd_table.add_row(
                    item.provider,
                    f"{item.subscore:.1f}",
                    f"{item.weight:.2f}",
                    item.reason,
                )
            console.print(bd_table)

    # Security pipeline / CI exit code: 2 if malicious or suspicious, 0 if clean/low_risk
    if report.verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS):
        raise typer.Exit(code=2)
    raise typer.Exit(code=0)


@app.command(name="batch", help="Batch analyze indicators from a file or stdin.")
def batch_command(
    target: Annotated[
        str,
        typer.Argument(
            help="Path to line-delimited IoC text file, or '-' to read from standard input"
        ),
    ],
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Destination file path to save the report"),
    ] = None,
    concurrency: Annotated[
        int, typer.Option("--concurrency", "-c", min=1, max=20, help="Max concurrent lookups")
    ] = 5,
    fmt: Annotated[
        ReportFormat,
        typer.Option("--format", "-f", case_sensitive=False, help="Report output format"),
    ] = ReportFormat.JSON,
    refresh: Annotated[
        bool, typer.Option("--refresh", "-r", help="Bypass cache for all indicators")
    ] = False,
) -> None:
    """Analyze multiple indicators in parallel with bounded concurrency and export reports."""
    # 1. Read input lines
    raw_lines: list[str] = []
    if target == "-":
        raw_lines = sys.stdin.read().splitlines()
    else:
        target_path = Path(target)
        if not target_path.exists():
            err_console.print(f"[bold red]Error:[/bold red] Input file not found: {target}")
            raise typer.Exit(code=1)
        raw_lines = target_path.read_text(encoding="utf-8").splitlines()

    iocs = [line.strip() for line in raw_lines if line.strip() and not line.strip().startswith("#")]
    if not iocs:
        err_console.print(
            "[bold yellow]Warning:[/bold yellow] No valid indicators found to process."
        )
        raise typer.Exit(code=0)

    # 2. Async concurrent processing with Rich progress
    async def _process_all() -> list[AggregatedReport]:
        settings = Settings()
        aggregator = await Aggregator.create(settings=settings)
        semaphore = asyncio.Semaphore(concurrency)
        results: list[AggregatedReport] = []

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=err_console,
        ) as progress:
            task = progress.add_task("Analyzing indicators...", total=len(iocs))

            async def _worker(item: str) -> None:
                async with semaphore:
                    try:
                        rep = await aggregator.lookup(item, refresh=refresh)
                        results.append(rep)
                    except Exception as exc:
                        err_console.print(
                            f"[dim yellow]Warning:[/] Failed to analyze '{item}': {exc}"
                        )
                    finally:
                        progress.advance(task)

            workers = [_worker(item) for item in iocs]
            await asyncio.gather(*workers)

        await aggregator.close()
        return results

    reports = asyncio.run(_process_all())

    # 3. Generate report
    rendered = generate_report(reports, fmt)

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
        err_console.print(f"[bold green]Success:[/bold green] Report written to {output}")
    else:
        console.print(rendered)

    # Exit code: 2 if any malicious or suspicious indicator found, 0 otherwise
    has_threats = any(r.verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS) for r in reports)
    if has_threats:
        raise typer.Exit(code=2)
    raise typer.Exit(code=0)


@app.command(name="providers", help="Display status, daily quota usage, and circuit breakers.")
def providers_command() -> None:
    """Inspect configured providers, remaining quota, and circuit breaker operational status."""

    async def _fetch() -> list[dict[str, object]]:
        settings = Settings()
        aggregator = await Aggregator.create(settings=settings)
        data: list[dict[str, object]] = []
        try:
            for p in aggregator.providers:
                used, daily_limit = await aggregator.quota_tracker.get_usage(
                    p.name, p.rate_limit_daily
                )
                cb = aggregator.circuit_breakers.get(p.name)
                state = cb.state if cb else CircuitState.CLOSED
                failures = cb.failure_count if cb else 0
                has_key = getattr(p, "api_key", None) is not None

                data.append(
                    {
                        "name": p.name,
                        "enabled": has_key,
                        "used": used,
                        "limit": daily_limit,
                        "remaining": max(0, daily_limit - used),
                        "state": state,
                        "failures": failures,
                    }
                )
            return data
        finally:
            await aggregator.close()

    items = asyncio.run(_fetch())

    table = Table(
        title="ThreatLens Provider Telemetry & Circuit Status",
        header_style="bold cyan",
        show_lines=True,
    )
    table.add_column("Provider", style="bold")
    table.add_column("Status", justify="center")
    table.add_column("Daily Quota (Used / Limit)", justify="right")
    table.add_column("Quota Remaining", justify="right")
    table.add_column("Circuit State", justify="center")
    table.add_column("Consecutive Failures", justify="right")

    for item in items:
        status_text = "[green]Active[/green]" if item["enabled"] else "[dim]Disabled[/dim]"
        c_state: CircuitState = item["state"]  # type: ignore[assignment]
        c_color = _circuit_color(c_state)
        circuit_text = f"[{c_color}]{c_state.value.upper()}[/{c_color}]"

        table.add_row(
            str(item["name"]).upper(),
            status_text,
            f"{item['used']} / {item['limit']}",
            str(item["remaining"]),
            circuit_text,
            str(item["failures"]),
        )

    console.print(table)


@app.command(name="serve", help="Run the ThreatLens FastAPI REST service.")
def serve_command(
    host: Annotated[str, typer.Option("--host", "-h", help="Bind network host")] = "0.0.0.0",  # noqa: S104
    port: Annotated[int, typer.Option("--port", "-p", min=1, max=65535, help="Bind port")] = 8000,
    reload: Annotated[
        bool, typer.Option("--reload", help="Enable auto-reload for development")
    ] = False,
) -> None:
    """Start the FastAPI HTTP application using Uvicorn."""
    console.print(
        f"[bold green]Starting ThreatLens REST service on http://{host}:{port}...[/bold green]"
    )
    uvicorn.run(
        "threatlens.api.app:create_app",
        factory=True,
        host=host,
        port=port,
        reload=reload,
    )


if __name__ == "__main__":
    app()
