# Developer Guide: Adding a New Intelligence Provider

ThreatLens is designed with a pluggable provider architecture. Adding a new threat intelligence source (e.g., GreyNoise, URLhaus, Shodan, or Pulsedive) requires implementing a single class, registering its configuration, and defining its scoring subscore.

---

## Architecture Overview for Providers

All providers inherit from `BaseProvider` (`src/threatlens/providers/base.py`). 

### Core Guarantees Every Provider Must Fulfill:
1. **Never raise uncaught exceptions** for expected network and upstream API conditions (404, 429, 500, timeouts, malformed JSON). Always translate these into normalized `ProviderResult` objects.
2. **Missing API Keys:** If `api_key` is `None` or empty, immediately return `status="skipped"`.
3. **Unsupported Types:** If the indicator type is not supported by this provider, immediately return `status="unsupported"` without making HTTP calls.
4. **Latency Measurement:** Always measure and populate `latency_ms` on the returned `ProviderResult`.

---

## Step-by-Step Implementation: Worked Example (URLhaus)

In this walkthrough, we will implement **URLhaus** (abuse.ch), an open threat intel database tracking malicious URLs and payload delivery.

### Step 1: Create the Provider Adapter

Create `src/threatlens/providers/urlhaus.py`:

```python
"""URLhaus (abuse.ch) threat intelligence provider adapter."""

from __future__ import annotations

import time
from typing import Any

import httpx

from threatlens.models import IoCType, ProviderResult
from threatlens.providers.base import BaseProvider


class URLhausProvider(BaseProvider):
    """Queries abuse.ch URLhaus API for malicious URL intelligence."""

    name = "urlhaus"
    supported_types = frozenset([IoCType.URL, IoCType.DOMAIN])
    rate_limit_rpm = 60
    rate_limit_daily = 5000
    timeout_seconds = 10.0

    def __init__(
        self,
        api_key: str | None = None,
        rpm: int | None = None,
        daily: int | None = None,
        timeout: float | None = None,
    ) -> None:
        self.api_key = api_key
        if rpm is not None:
            self.rate_limit_rpm = rpm
        if daily is not None:
            self.rate_limit_daily = daily
        if timeout is not None:
            self.timeout_seconds = timeout

    async def lookup(
        self,
        ioc: str,
        ioc_type: IoCType,
        client: httpx.AsyncClient,
        include_raw: bool = False,
    ) -> ProviderResult:
        """Query URLhaus for intelligence on URL or domain."""
        start_time = time.perf_counter()

        # 1. Type validation
        if not self.supports(ioc_type):
            return self._create_result(status="unsupported")

        # 2. Key check (URLhaus allows unauthenticated queries, but keys permit higher quotas)
        headers: dict[str, str] = {}
        if self.api_key:
            headers["Auth-Key"] = self.api_key

        endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
        data = {"url": ioc} if ioc_type == IoCType.URL else {"host": ioc}

        try:
            response = await client.post(
                endpoint,
                data=data,
                headers=headers,
                timeout=self.timeout_seconds,
            )
        except httpx.TimeoutException:
            latency = int((time.perf_counter() - start_time) * 1000)
            return self._create_result(
                status="error",
                latency_ms=latency,
                error_message="Connection timed out while contacting URLhaus API",
            )
        except httpx.RequestError as exc:
            latency = int((time.perf_counter() - start_time) * 1000)
            return self._create_result(
                status="error",
                latency_ms=latency,
                error_message=f"Network error: {exc}",
            )

        latency = int((time.perf_counter() - start_time) * 1000)

        # 3. HTTP status handling
        if response.status_code == 429:
            return self._create_result(status="rate_limited", latency_ms=latency)
        if response.status_code >= 500:
            return self._create_result(
                status="error",
                latency_ms=latency,
                error_message=f"URLhaus server error: HTTP {response.status_code}",
            )

        # 4. Parse JSON payload
        try:
            payload = response.json()
        except ValueError:
            return self._create_result(
                status="error",
                latency_ms=latency,
                error_message="Malformed JSON response from URLhaus",
            )

        query_status = payload.get("query_status")
        if query_status in ("no_results", "not_found"):
            return self._create_result(status="not_found", latency_ms=latency)

        # 5. Normalize attributes into standard schema
        threat_tags = payload.get("tags") or []
        malware = [payload.get("threat")] if payload.get("threat") else []
        is_online = payload.get("url_status") == "online"

        return ProviderResult(
            provider=self.name,
            status="ok",
            malicious_votes=1 if is_online else 0,
            confidence=0.9 if is_online else 0.5,
            tags=threat_tags,
            malware_families=malware,
            latency_ms=latency,
            raw=payload if include_raw else None,
        )
```

---

### Step 2: Add Provider Configuration

In `src/threatlens/config.py`, add the provider's environment variables and settings:

```python
# In Settings class:
urlhaus_api_key: SecretStr | None = Field(
    default=None,
    description="URLhaus Auth-Key (optional)",
)
urlhaus_rpm: int = Field(default=60, ge=1)
urlhaus_daily: int = Field(default=5000, ge=1)
urlhaus_timeout: float = Field(default=10.0, ge=1.0)
```

Update `.env.example`:
```bash
THREATLENS_URLHAUS_API_KEY=your_urlhaus_api_key_here
THREATLENS_URLHAUS_RPM=60
THREATLENS_URLHAUS_DAILY=5000
THREATLENS_URLHAUS_TIMEOUT=10.0
```

---

### Step 3: Register in Scoring Engine

In `src/threatlens/scoring.py`:

1. Define the subscore calculation:
```python
def _score_urlhaus(result: ProviderResult) -> tuple[float, str]:
    """Compute URLhaus subscore based on online status and malware threat tag."""
    if result.status == "not_found":
        return 0.0, "Not cataloged in URLhaus active database"

    score = 60.0
    reasons = ["Identified in URLhaus malicious repository"]

    if result.malware_families:
        score += 30.0
        reasons.append(f"Associated malware family: {', '.join(result.malware_families)}")

    score = min(100.0, score)
    return score, "; ".join(reasons)
```

2. Add to dispatch table in `_calculate_subscore()`:
```python
if provider_name == "urlhaus":
    return _score_urlhaus(result)
```

3. Update default weights in `DEFAULT_WEIGHTS`:
```python
DEFAULT_WEIGHTS: dict[str, float] = {
    "virustotal": 0.40,
    "otx": 0.25,
    "abuseipdb": 0.20,
    "urlhaus": 0.15,
}
```

---

### Step 4: Register in Aggregator Factory

In `src/threatlens/aggregator.py`, add the provider to the default list in `Aggregator.create`:

```python
from threatlens.providers.urlhaus import URLhausProvider

# Inside Aggregator.create:
urlhaus_key = (
    active_settings.urlhaus_api_key.get_secret_value()
    if active_settings.urlhaus_api_key
    else None
)

providers.append(
    URLhausProvider(
        api_key=urlhaus_key,
        rpm=active_settings.urlhaus_rpm,
        daily=active_settings.urlhaus_daily,
        timeout=active_settings.urlhaus_timeout,
    )
)
```

---

### Step 5: Write Respx Tests

Create `tests/unit/test_urlhaus.py` using recorded JSON fixtures and `respx`:

```python
import respx
import pytest
from threatlens.models import IoCType
from threatlens.providers.urlhaus import URLhausProvider

@pytest.mark.asyncio
@respx.mock
async def test_urlhaus_success(httpx_client):
    provider = URLhausProvider()
    respx.post("https://urlhaus-api.abuse.ch/v1/url/").respond(
        status_code=200,
        json={
            "query_status": "ok",
            "url_status": "online",
            "threat": "Mozi",
            "tags": ["elf", "mozi"],
        },
    )
    result = await provider.lookup("http://bad.com/payload.sh", IoCType.URL, httpx_client)
    assert result.status == "ok"
    assert result.malware_families == ["Mozi"]
    assert "mozi" in result.tags
```

Run test suite and verification:
```bash
.\tasks.ps1 test
.\tasks.ps1 lint
.\tasks.ps1 type-check
```
