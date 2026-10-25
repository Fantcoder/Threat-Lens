"""Async SQLite Cache and Lookup History Repository.

Tables:
- lookups: Caches serialized AggregatedReport objects with TTLs varying by verdict.
- history: Persistent audit trail of all evaluated indicators.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import aiosqlite
from pydantic import BaseModel

from threatlens.config import Settings
from threatlens.models import AggregatedReport, IoCType, Verdict


class HistoryEntry(BaseModel):
    """Audit log entry of a threat intelligence evaluation."""

    id: int
    timestamp: datetime
    ioc: str
    ioc_type: IoCType
    verdict: Verdict
    risk_score: int


class LookupCache:
    """Thread-safe, coroutine-safe SQLite cache and audit repository."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self._lock = asyncio.Lock()

    @staticmethod
    def compute_hash(ioc: str, ioc_type: IoCType) -> str:
        """Deterministic sha256 hash key for caching."""
        key = f"{ioc_type.value}:{ioc.strip().lower()}"
        return hashlib.sha256(key.encode("utf-8")).hexdigest()

    async def initialize(self) -> None:
        """Create database tables and performance indexes."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS lookups (
                    ioc_hash TEXT PRIMARY KEY,
                    ioc_type TEXT NOT NULL,
                    normalized_value TEXT NOT NULL,
                    report_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                )
                """
            )
            await db.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_lookups_expires_at
                ON lookups(expires_at)
                """
            )
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    ioc TEXT NOT NULL,
                    ioc_type TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    risk_score INTEGER NOT NULL
                )
                """
            )
            await db.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_history_timestamp
                ON history(timestamp DESC)
                """
            )
            await db.commit()

    @staticmethod
    def get_ttl_for_verdict(verdict: Verdict, settings: Settings) -> int:
        """Return TTL in seconds based on verdict severity."""
        if verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS):
            return settings.ttl_malicious
        if verdict in (Verdict.CLEAN, Verdict.LOW_RISK):
            return settings.ttl_clean
        return settings.ttl_unknown

    async def get(self, ioc_hash: str) -> AggregatedReport | None:
        """Retrieve a cached report if it exists and has not expired."""
        now_iso = datetime.now(UTC).isoformat()
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute(
                """
                SELECT report_json, expires_at FROM lookups
                WHERE ioc_hash = ? AND expires_at > ?
                """,
                (ioc_hash, now_iso),
            )
            row = await cursor.fetchone()
            if not row:
                return None

            report_dict: dict[str, Any] = json.loads(row[0])
            report = AggregatedReport.model_validate(report_dict)

            # Calculate remaining TTL
            expires_at = datetime.fromisoformat(row[1])
            remaining = int((expires_at - datetime.now(UTC)).total_seconds())
            report.ttl_remaining = max(0, remaining)
            report.cached = True
            return report

    async def put(self, report: AggregatedReport, ttl_seconds: int) -> None:
        """Store an aggregated report in cache with specified TTL."""
        ioc_hash = self.compute_hash(report.normalized_value, report.ioc_type)
        now = datetime.now(UTC)
        expires_at = datetime.fromtimestamp(now.timestamp() + ttl_seconds, tz=UTC)

        # Store with cached=True flag stripped in storage
        storable = report.model_dump(mode="json")
        storable["cached"] = False
        report_json = json.dumps(storable)

        async with self._lock, aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO lookups (
                    ioc_hash, ioc_type, normalized_value, report_json, created_at, expires_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(ioc_hash) DO UPDATE SET
                    report_json = excluded.report_json,
                    created_at = excluded.created_at,
                    expires_at = excluded.expires_at
                """,
                (
                    ioc_hash,
                    report.ioc_type.value,
                    report.normalized_value,
                    report_json,
                    now.isoformat(),
                    expires_at.isoformat(),
                ),
            )
            await db.commit()

    async def add_history(self, report: AggregatedReport) -> None:
        """Insert an audit log entry into the history table."""
        now_iso = datetime.now(UTC).isoformat()
        async with self._lock, aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO history (timestamp, ioc, ioc_type, verdict, risk_score)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    now_iso,
                    report.normalized_value,
                    report.ioc_type.value,
                    report.verdict.value,
                    report.risk_score,
                ),
            )
            await db.commit()

    async def get_history(self, limit: int = 50) -> list[HistoryEntry]:
        """Fetch recent audit log history in reverse chronological order."""
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute(
                """
                SELECT id, timestamp, ioc, ioc_type, verdict, risk_score
                FROM history
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            )
            rows = await cursor.fetchall()
            return [
                HistoryEntry(
                    id=row[0],
                    timestamp=datetime.fromisoformat(row[1]),
                    ioc=row[2],
                    ioc_type=IoCType(row[3]),
                    verdict=Verdict(row[4]),
                    risk_score=row[5],
                )
                for row in rows
            ]

    async def cleanup_expired(self) -> int:
        """Delete all expired cache entries. Returns count of deleted rows."""
        now_iso = datetime.now(UTC).isoformat()
        async with self._lock, aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute("DELETE FROM lookups WHERE expires_at <= ?", (now_iso,))
            deleted = cursor.rowcount
            await db.commit()
            return max(0, deleted)
