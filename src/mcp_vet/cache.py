"""Local verdict cache (SQLite). TTL-based; invalidated on version bump.

A trust tool stays local-first: no telemetry, no cloud round-trips.
"""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

CACHE_DIR = Path.home() / ".cache" / "mcp-vet"
DEFAULT_TTL_S = 24 * 3600


class VerdictCache:
    def __init__(self, path: Path | None = None, ttl_s: int = DEFAULT_TTL_S):
        self.path = path or (CACHE_DIR / "verdicts.sqlite")
        self.ttl_s = ttl_s
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path))
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS verdicts ("
            " target TEXT PRIMARY KEY, version TEXT, verdict TEXT, ts REAL)"
        )

    def get(self, target: str, version: str) -> dict | None:
        row = self._conn.execute(
            "SELECT verdict, ts FROM verdicts WHERE target=? AND version=?",
            (target, version),
        ).fetchone()
        if not row:
            return None
        verdict_json, ts = row
        if time.time() - ts > self.ttl_s:
            return None
        return json.loads(verdict_json)

    def put(self, target: str, version: str, verdict: dict) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO verdicts (target, version, verdict, ts) VALUES (?,?,?,?)",
            (target, version, json.dumps(verdict), time.time()),
        )
        self._conn.commit()
