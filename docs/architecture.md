# ThreatLens Architecture & Design Decisions

This document outlines the system architecture, component boundaries, execution flows, and engineering trade-offs underpinning ThreatLens.

---

## 1. High-Level Component Architecture

ThreatLens is designed around clean hexagonal/ports-and-adapters architecture principles. The core business logic (IoC detection, provider aggregation, and explainable scoring) is completely decoupled from delivery mechanisms (FastAPI HTTP endpoints, Typer CLI) and persistence mechanisms (aiosqlite cache and quota storage).

```mermaid
graph TD
    subgraph Clients ["Delivery Layer (Clients & Gating)"]
        CLI["Typer CLI<br/>(lookup / batch / providers / serve)"]
        API["FastAPI REST API<br/>(/api/v1/lookup, /batch, /history)"]
        CI["CI/CD Pipeline Security Gate<br/>(Exit code 2 on threats)"]
    end

    subgraph Middleware ["Cross-Cutting Middleware"]
        Auth["Timing-Safe API Key Auth<br/>(hmac.compare_digest)"]
        ClientRateLimit["Client IP Token Bucket<br/>(429 Problem Details)"]
        LogFilter["Secret Redaction & JSON Logger<br/>(Correlated X-Request-ID)"]
    end

    subgraph Core ["Orchestration & Business Logic"]
        Detector["IoC Detector & Refanger<br/>(RFC compliance, tldextract, private filter)"]
        Aggregator["Aggregator Orchestrator<br/>(Async fan-out, request coalescing)"]
        ScoringEngine["Explainable Scoring Engine<br/>(Nonlinear curves, dynamic renormalization)"]
    end

    subgraph Resilience ["Resilience & Flow Control"]
        TokenBuckets["Token Buckets<br/>(Per-provider RPM smoothing)"]
        QuotaTrackers["Daily Quota Tracker<br/>(SQLite persistence & UTC rollover)"]
        CircuitBreakers["Circuit Breakers<br/>(CLOSED / OPEN / HALF-OPEN)"]
        RetryPolicies["Exponential Retries<br/>(Tenacity jitter + Retry-After parsing)"]
    end

    subgraph Providers ["Provider Adapters"]
        VT["VirusTotal v3 Provider"]
        OTX["AlienVault OTX Provider"]
        Abuse["AbuseIPDB Provider"]
    end

    subgraph Storage ["Local High-Performance Storage"]
        CacheDB[("SQLite Cache<br/>(TTL by verdict, JSON telemetry)")]
        QuotaDB[("SQLite Quotas<br/>(Daily counters)")]
    end

    CLI --> Aggregator
    API --> Middleware
    Middleware --> Aggregator
    CI --> CLI

    Aggregator --> Detector
    Aggregator --> CacheDB
    Aggregator --> Resilience
    Resilience --> Providers
    Providers --> ScoringEngine
    Resilience --> QuotaDB
    ScoringEngine --> Aggregator
```

---

## 2. Request Lifecycle & IoC Query Sequence

When an indicator is analyzed through either the REST API or the CLI, the following end-to-end flow executes:

```mermaid
sequenceDiagram
    autonumber
    actor User as Client / CLI
    participant API as FastAPI / CLI
    participant Agg as Aggregator
    participant Det as Detector & Refanger
    participant Cache as SQLite LookupCache
    participant Guard as Resilience Guard<br/>(Bucket, Quota, Breaker)
    participant Upstream as External Provider APIs<br/>(VT, OTX, AbuseIPDB)
    participant Score as Scoring Engine

    User->>API: Query IoC (e.g., hxxps://bad[.]com or 8.8.8.8)
    API->>Agg: lookup(raw_ioc, refresh=False)
    Agg->>Det: detect_ioc(raw_ioc)
    Det-->>Agg: IoCDetails(normalized_value, type, is_defanged)
    
    alt Private / Reserved IP
        Agg-->>API: Raise InvalidIoCError (RFC 1918 / 6890 rejection)
        API-->>User: HTTP 400 Problem Details / CLI Exit 1
    end

    alt Cache Hit (and not refresh)
        Agg->>Cache: get(normalized_value)
        Cache-->>Agg: AggregatedReport (cached=True)
        Agg-->>API: Return cached report
        API-->>User: HTTP 200 / Rich Table
    else Cache Miss or Refresh
        Agg->>Agg: Check in-flight coalescing map
        alt Identical query in flight
            Agg->>Agg: Await shared Future
        else New query
            Agg->>Guard: Evaluate circuit state & daily quota
            par Query Providers Concurrently
                Guard->>Upstream: Query VirusTotal (TokenBucket RPM)
                Upstream-->>Guard: ProviderResult (or mapped fallback)
            and
                Guard->>Upstream: Query AlienVault OTX
                Upstream-->>Guard: ProviderResult
            and
                Guard->>Upstream: Query AbuseIPDB
                Upstream-->>Guard: ProviderResult
            end
            Agg->>Score: score_report(normalized_value, results)
            Score-->>Agg: AggregatedReport(verdict, score, breakdown)
            Agg->>Cache: put(report, ttl_seconds)
            Agg->>Cache: log_history(entry)
            Agg-->>API: Return fresh AggregatedReport
            API-->>User: HTTP 200 / Rich Table
        end
    end
```

---

## 3. Engineering Decisions & Architecture Trade-offs

### 3.1 Async I/O & Bounded Concurrency
- **Decision:** Use Python 3.11+ `asyncio` with `httpx.AsyncClient` rather than thread pools or synchronous requests.
- **Why:** Threat intelligence queries are fundamentally I/O bound. Concurrently querying 3-5 external HTTP APIs with latencies between 200ms and 1500ms would result in linear latency buildup ($O(N)$) in synchronous systems ($200ms + 500ms + 800ms = 1500ms$). Under async fan-out (`asyncio.gather`), total latency equals the slowest provider ($\max(200, 500, 800) = 800ms$).
- **Isolation:** Batch queries use `asyncio.Semaphore(concurrency)` to bound parallel in-flight connections (default 5, configurable up to 20), preventing descriptor exhaustion or self-inflicted network saturation.

### 3.2 Request Coalescing (Single-Flight Pattern)
- **Decision:** Implement in-flight deduplication via `_inflight: dict[str, asyncio.Future[AggregatedReport]]`.
- **Why:** Under sudden surges or batch ingestion (e.g., SIEM alerts alerting on the same IP 50 times across 10 seconds), without request coalescing, all 50 concurrent requests would experience a cache miss simultaneously (the "thundering herd" or "cache stampede" problem), exhausting free-tier provider quotas.
- **How:** The first request creates an uncompleted `asyncio.Future` in the in-flight dictionary. All subsequent concurrent requests for the exact same normalized IoC await that single Future. When the upstream call completes, the result is set on the Future, instantly satisfying all callers with zero redundant API calls.

### 3.3 SQLite with WAL Mode vs. Redis
- **Decision:** Built-in zero-dependency persistence using `aiosqlite` with SQLite Write-Ahead Logging (`PRAGMA journal_mode=WAL`).
- **Why:** ThreatLens is designed to be instantly runnable by hiring managers and security analysts without mandating external infrastructure services (Docker, Redis, PostgreSQL).
- **Performance:** SQLite in WAL mode permits concurrent readers without locking the writer. By using parameterized queries and indexes on `(ioc_hash)`, lookups achieve sub-millisecond latency.
- **TTL by Verdict:** Malicious indicators are cached for shorter durations (e.g. 2 hours) so remediations or sinkholing are promptly detected, while clean indicators are cached longer (24 hours) to preserve upstream quota.

### 3.4 Dual-Tier Rate Limiting & Flow Control
1. **Per-Minute Smoothing (Token Bucket):** Enforces upstream provider RPM (e.g. VirusTotal free tier: 4 requests/min) using an algorithmic token bucket with lazy fractional refill (`now - last_refill * rate`). If tokens are exhausted, the worker pauses (`asyncio.sleep`) up to a bounded maximum wait time.
2. **Daily Quotas (DailyQuotaTracker):** External APIs often have strict daily caps (e.g. VirusTotal: 500/day, AbuseIPDB: 1,000/day). In-memory counters would reset whenever the application restarts or reloads. Daily usage is tracked persistently in SQLite, keyed by `(provider, YYYY-MM-DD UTC)`. When the daily ceiling is reached, queries to that provider are gracefully skipped without crashing the pipeline.

### 3.5 Circuit Breaker Resilience
- **Decision:** Implement per-provider three-state circuit breakers (`CLOSED`, `OPEN`, `HALF_OPEN`).
- **Why:** If an external intelligence service experiences downtime, 5xx server errors, or persistent connection timeouts, continuing to flood it wastes local sockets and inflates user response times.
- **Behavior:** 5 consecutive failures trip the breaker to `OPEN`. For the next 60 seconds (recovery timeout), all requests to that provider are fast-failed without network calls. After the timeout, a probe request transitions the state to `HALF_OPEN`. A single success resets the circuit to `CLOSED`; a failure trips it back to `OPEN`.

### 3.6 Explainable Scoring with Dynamic Renormalization
- **Decision:** Transparent mathematical formulation instead of opaque machine-learning black boxes.
- **Mathematical Principle:**
  $$\text{Score} = \sum_{i \in \text{Available}} \left( \frac{w_i}{\sum_{j \in \text{Available}} w_j} \cdot \text{Subscore}_i \right)$$
- **Dynamic Renormalization:** If a provider is skipped due to lack of API key or circuit trip, its weight is not treated as zero score (which would artificially depress risk). Instead, the remaining available provider weights are dynamically renormalized to sum to 1.0, preserving score fidelity.
- **Explainability:** Every score calculation outputs a human-readable and machine-actionable `ScoreComponent` detailing the subscore, effective weight, mathematical contribution, and explicit rationale.
