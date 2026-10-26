"""Reproducible batch performance benchmark for ThreatLens.

Measures wall time, upstream HTTP calls made, and calls saved via local caching
and single-flight request coalescing across different concurrency levels (1, 5, 20).
"""

from __future__ import annotations

import asyncio
import tempfile
import time
from pathlib import Path
from typing import Any

import httpx

from threatlens.aggregator import Aggregator
from threatlens.cache import LookupCache
from threatlens.config import Settings
from threatlens.providers.abuseipdb import AbuseIPDBProvider
from threatlens.providers.otx import OTXProvider
from threatlens.providers.virustotal import VirusTotalProvider
from threatlens.ratelimit import DailyQuotaTracker


class SimulatedLatencyTransport(httpx.AsyncBaseTransport):
    """Mock transport simulating upstream HTTP network latency without external calls."""

    def __init__(self, latency: float = 0.050) -> None:
        self.latency = latency
        self.call_count = 0

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.call_count += 1
        await asyncio.sleep(self.latency)
        url = str(request.url)
        if "virustotal" in url:
            data: dict[str, Any] = {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 0,
                            "suspicious": 0,
                            "harmless": 70,
                            "undetected": 0,
                        },
                        "reputation": 0,
                        "tags": [],
                    }
                }
            }
        elif "alienvault" in url or "otx" in url:
            data = {"pulse_info": {"count": 0, "pulses": []}}
        elif "abuseipdb" in url:
            data = {
                "data": {
                    "abuseConfidenceScore": 0,
                    "totalReports": 0,
                    "countryCode": "US",
                    "isp": "Simulated ISP",
                }
            }
        else:
            data = {}
        return httpx.Response(200, json=data, request=request)


def generate_benchmark_iocs() -> list[str]:
    """Generate a fixed list of 100 routable public IPv4 indicators with 40% duplicates."""
    unique_iocs = [f"93.184.216.{i}" for i in range(1, 61)]
    duplicates = unique_iocs[:40]
    iocs: list[str] = []
    for i in range(40):
        iocs.append(unique_iocs[i])
        iocs.append(duplicates[i])
    iocs.extend(unique_iocs[40:])
    return iocs


async def run_benchmark(
    concurrency: int, iocs: list[str], simulated_latency: float = 0.050
) -> dict[str, Any]:
    """Run a benchmark trial with a given concurrency level."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        cache = LookupCache(tmp_path / "cache.sqlite")
        await cache.initialize()
        quota = DailyQuotaTracker(tmp_path / "quotas.sqlite")
        await quota.initialize()

        transport = SimulatedLatencyTransport(latency=simulated_latency)
        async with httpx.AsyncClient(transport=transport) as client:
            settings = Settings(
                virustotal_rpm=10_000,
                otx_rpm=10_000,
                abuseipdb_rpm=10_000,
            )
            providers = [
                VirusTotalProvider(api_key="bench_vt", rpm=10_000, daily=1_000_000),
                OTXProvider(api_key="bench_otx", rpm=10_000, daily=1_000_000),
                AbuseIPDBProvider(api_key="bench_abuse", rpm=10_000, daily=1_000_000),
            ]
            aggregator = Aggregator(providers, cache, quota, settings, client)

            sem = asyncio.Semaphore(concurrency)

            async def worker(ioc: str) -> Any:
                async with sem:
                    return await aggregator.lookup(ioc)

            t_start = time.perf_counter()
            results = await asyncio.gather(*[worker(ioc) for ioc in iocs])
            wall_time = time.perf_counter() - t_start

        theoretical_calls = len(iocs) * len(providers)
        calls_made = transport.call_count
        calls_saved = theoretical_calls - calls_made
        pct_saved = (calls_saved / theoretical_calls) * 100.0

        return {
            "concurrency": concurrency,
            "total_lookups": len(results),
            "upstream_calls_made": calls_made,
            "theoretical_calls": theoretical_calls,
            "calls_saved": calls_saved,
            "pct_saved": pct_saved,
            "wall_time_s": wall_time,
        }


async def main() -> None:
    iocs = generate_benchmark_iocs()
    total = len(iocs)
    unique = len(set(iocs))
    dup_pct = ((total - unique) / total) * 100.0

    print("===================================================================")
    print(" ThreatLens Batch Performance Benchmark")
    print("===================================================================")
    print(f"Dataset: {total} IoCs ({unique} unique, {dup_pct:.0f}% duplicates)")
    print("Simulated Provider Latency: 50ms per upstream HTTP request")
    print("Configured Providers: VirusTotal, AlienVault OTX, AbuseIPDB (3 calls/IoC)\n")

    concurrency_levels = [1, 5, 20]
    rows: list[dict[str, Any]] = []

    for c in concurrency_levels:
        row = await run_benchmark(c, iocs)
        rows.append(row)

    header = (
        f"{'Concurrency':<12} | {'Total Lookups':<14} | "
        f"{'HTTP Calls Made':<16} | {'Calls Saved':<20} | {'Wall Time':<10}"
    )
    divider = f"{'-' * 12}-|-{'-' * 14}-|-{'-' * 16}-|-{'-' * 20}-|-{'-' * 10}"
    print(header)
    print(divider)
    for r in rows:
        saved_str = f"{r['calls_saved']} ({r['pct_saved']:.1f}%)"
        line = (
            f"{r['concurrency']:<12} | {r['total_lookups']:<14} | "
            f"{r['upstream_calls_made']:<16} | {saved_str:<20} | {r['wall_time_s']:.2f}s"
        )
        print(line)
    print("===================================================================\n")


if __name__ == "__main__":
    asyncio.run(main())
