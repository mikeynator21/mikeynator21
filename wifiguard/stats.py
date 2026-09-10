"""Query logging and statistics.

Writes go through a queue and land in SQLite in batches from one background
thread. A DNS server answers in single-digit milliseconds and a synchronous
insert per query would dominate that, so the resolver path never touches the
database directly.

Logging what a household looks up is sensitive by nature, so retention is
bounded by default and `log_queries = false` keeps the counters while recording
no names at all.
"""

from __future__ import annotations

import logging
import queue
import sqlite3
import threading
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

log = logging.getLogger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS queries (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          REAL    NOT NULL,
    client      TEXT    NOT NULL,
    name        TEXT    NOT NULL,
    qtype       TEXT    NOT NULL,
    action      TEXT    NOT NULL,
    reason      TEXT    NOT NULL DEFAULT '',
    rule        TEXT    NOT NULL DEFAULT '',
    elapsed_ms  REAL    NOT NULL DEFAULT 0,
    cached      INTEGER NOT NULL DEFAULT 0,
    group_name  TEXT    NOT NULL DEFAULT 'default'
);
CREATE INDEX IF NOT EXISTS queries_ts    ON queries (ts);
CREATE INDEX IF NOT EXISTS queries_name  ON queries (name);
CREATE INDEX IF NOT EXISTS queries_client ON queries (client);
CREATE INDEX IF NOT EXISTS queries_action ON queries (action);
"""


@dataclass
class QueryRecord:
    ts: float
    client: str
    name: str
    qtype: str
    action: str
    reason: str = ""
    rule: str = ""
    elapsed_ms: float = 0.0
    cached: bool = False
    group_name: str = "default"

    def as_row(self) -> tuple:
        return (
            self.ts,
            self.client,
            self.name,
            self.qtype,
            self.action,
            self.reason,
            self.rule,
            self.elapsed_ms,
            int(self.cached),
            self.group_name,
        )

    def as_dict(self) -> dict[str, object]:
        return {
            "ts": self.ts,
            "client": self.client,
            "name": self.name,
            "type": self.qtype,
            "action": self.action,
            "reason": self.reason,
            "rule": self.rule,
            "elapsed_ms": round(self.elapsed_ms, 2),
            "cached": self.cached,
            "group": self.group_name,
        }


@dataclass
class Counters:
    """Live totals, kept in memory so the dashboard never waits on a query."""

    total: int = 0
    blocked: int = 0
    cached: int = 0
    forwarded: int = 0
    errors: int = 0
    rewritten: int = 0
    started_at: float = field(default_factory=time.time)
    #: Bytes we did not send upstream because a query never left the house.
    upstream_queries_avoided: int = 0

    @property
    def block_rate(self) -> float:
        return self.blocked / self.total if self.total else 0.0

    @property
    def cache_rate(self) -> float:
        return self.cached / self.total if self.total else 0.0

    def as_dict(self) -> dict[str, object]:
        return {
            "total": self.total,
            "blocked": self.blocked,
            "cached": self.cached,
            "forwarded": self.forwarded,
            "rewritten": self.rewritten,
            "errors": self.errors,
            "block_rate": round(self.block_rate, 4),
            "cache_rate": round(self.cache_rate, 4),
            "uptime_seconds": int(time.time() - self.started_at),
            "upstream_queries_avoided": self.upstream_queries_avoided,
        }


class QueryLog:
    """Batching writer and query interface over the SQLite log."""

    def __init__(
        self,
        path: Path | str | None,
        *,
        retention_days: int = 7,
        log_queries: bool = True,
        recent_size: int = 500,
        flush_interval: float = 2.0,
        batch_size: int = 200,
    ) -> None:
        self.path = Path(path) if path else None
        self.retention_days = retention_days
        self.log_queries = log_queries
        self.flush_interval = flush_interval
        self.batch_size = batch_size

        self.counters = Counters()
        self.recent: deque[QueryRecord] = deque(maxlen=recent_size)
        #: In-memory top-N counters, so the dashboard is instant even when
        #: persistent logging is switched off entirely.
        self.top_blocked: Counter[str] = Counter()
        self.top_allowed: Counter[str] = Counter()
        self.by_client: Counter[str] = Counter()

        self._queue: queue.Queue[QueryRecord | None] = queue.Queue(maxsize=10_000)
        self._lock = threading.Lock()
        self._writer: threading.Thread | None = None
        self._stop = threading.Event()
        self._connection: sqlite3.Connection | None = None
        self._dropped = 0

    # -- lifecycle --------------------------------------------------------

    def start(self) -> None:
        if self.path is not None and self.log_queries:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._connection = sqlite3.connect(self.path, check_same_thread=False)
            # WAL keeps the dashboard's reads from blocking the writer.
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute("PRAGMA synchronous=NORMAL")
            self._connection.executescript(SCHEMA)
            self._connection.commit()
            self.prune()

        self._stop.clear()
        self._writer = threading.Thread(target=self._drain, name="querylog", daemon=True)
        self._writer.start()

    def stop(self) -> None:
        self._stop.set()
        try:
            self._queue.put_nowait(None)
        except queue.Full:
            pass
        if self._writer is not None:
            self._writer.join(timeout=5)
        with self._lock:
            if self._connection is not None:
                self._connection.commit()
                self._connection.close()
                self._connection = None

    # -- recording --------------------------------------------------------

    def record(self, record: QueryRecord) -> None:
        """Note one answered query. Never blocks the resolver."""
        counters = self.counters
        counters.total += 1
        if record.action == "block":
            counters.blocked += 1
            counters.upstream_queries_avoided += 1
            self.top_blocked[record.name] += 1
        elif record.action == "rewrite":
            counters.rewritten += 1
        elif record.action == "error":
            counters.errors += 1
        else:
            self.top_allowed[record.name] += 1

        if record.cached:
            counters.cached += 1
            counters.upstream_queries_avoided += 1
        elif record.action not in ("block", "error"):
            counters.forwarded += 1

        if record.client:
            self.by_client[record.client] += 1

        # Keep the in-memory top-N tables from growing without bound on a busy
        # network; trimming to the top few thousand keeps the ranking intact.
        if len(self.top_blocked) > 5000:
            self._trim(self.top_blocked)
        if len(self.top_allowed) > 5000:
            self._trim(self.top_allowed)

        self.recent.append(record)

        if self._connection is not None:
            try:
                self._queue.put_nowait(record)
            except queue.Full:
                # Under sustained overload, dropping log entries is the right
                # thing to sacrifice -- answers matter more than records of them.
                self._dropped += 1
                if self._dropped % 1000 == 1:
                    log.warning("query log is falling behind; %d entries dropped", self._dropped)

    @staticmethod
    def _trim(counter: Counter[str], keep: int = 2000) -> None:
        for name, _ in counter.most_common()[keep:]:
            del counter[name]

    def _drain(self) -> None:
        batch: list[QueryRecord] = []
        last_flush = time.monotonic()

        while not (self._stop.is_set() and self._queue.empty()):
            timeout = max(0.05, self.flush_interval - (time.monotonic() - last_flush))
            try:
                record = self._queue.get(timeout=timeout)
            except queue.Empty:
                record = None
            if record is not None:
                batch.append(record)

            due = (time.monotonic() - last_flush) >= self.flush_interval
            if batch and (len(batch) >= self.batch_size or due or self._stop.is_set()):
                self._flush(batch)
                batch = []
                last_flush = time.monotonic()

        if batch:
            self._flush(batch)

    def _flush(self, batch: Iterable[QueryRecord]) -> None:
        with self._lock:
            if self._connection is None:
                return
            try:
                self._connection.executemany(
                    "INSERT INTO queries "
                    "(ts, client, name, qtype, action, reason, rule, elapsed_ms, cached, group_name) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    [record.as_row() for record in batch],
                )
                self._connection.commit()
            except sqlite3.Error as exc:
                log.error("could not write to the query log: %s", exc)

    # -- reading ----------------------------------------------------------

    def prune(self) -> int:
        """Delete entries older than the retention window."""
        if self._connection is None or self.retention_days <= 0:
            return 0
        cutoff = time.time() - self.retention_days * 86_400
        with self._lock:
            try:
                cursor = self._connection.execute("DELETE FROM queries WHERE ts < ?", (cutoff,))
                self._connection.commit()
                return cursor.rowcount
            except sqlite3.Error as exc:
                log.error("could not prune the query log: %s", exc)
                return 0

    def recent_queries(self, limit: int = 100, client: str = "", action: str = "") -> list[dict]:
        """The most recent queries, newest first, from the in-memory ring."""
        rows = list(self.recent)[::-1]
        if client:
            rows = [row for row in rows if row.client == client]
        if action:
            rows = [row for row in rows if row.action == action]
        return [row.as_dict() for row in rows[:limit]]

    def history(self, hours: int = 24, buckets: int = 48) -> list[dict[str, object]]:
        """Query volume over time, split into allowed and blocked."""
        if self._connection is None:
            return []
        now = time.time()
        window = hours * 3600
        start = now - window
        size = window / buckets

        with self._lock:
            try:
                rows = self._connection.execute(
                    "SELECT CAST((ts - ?) / ? AS INTEGER) AS bucket, action, COUNT(*) "
                    "FROM queries WHERE ts >= ? GROUP BY bucket, action",
                    (start, size, start),
                ).fetchall()
            except sqlite3.Error as exc:
                log.error("could not read query history: %s", exc)
                return []

        series = [{"ts": start + index * size, "allowed": 0, "blocked": 0} for index in range(buckets)]
        for bucket, action, count in rows:
            if 0 <= bucket < buckets:
                key = "blocked" if action == "block" else "allowed"
                series[bucket][key] += count
        return series

    def top(self, action: str = "block", limit: int = 20) -> list[dict[str, object]]:
        counter = self.top_blocked if action == "block" else self.top_allowed
        return [{"name": name, "count": count} for name, count in counter.most_common(limit)]

    def clients(self, limit: int = 50) -> list[dict[str, object]]:
        return [{"client": client, "count": count} for client, count in self.by_client.most_common(limit)]

    def search(self, term: str, limit: int = 100) -> list[dict[str, object]]:
        """Search the persistent log for a name."""
        if self._connection is None:
            return [row for row in self.recent_queries(limit=limit) if term in str(row["name"])]
        with self._lock:
            try:
                rows = self._connection.execute(
                    "SELECT ts, client, name, qtype, action, reason, rule, elapsed_ms, cached, group_name "
                    "FROM queries WHERE name LIKE ? ORDER BY ts DESC LIMIT ?",
                    (f"%{term}%", limit),
                ).fetchall()
            except sqlite3.Error as exc:
                log.error("could not search the query log: %s", exc)
                return []
        return [
            QueryRecord(
                ts=row[0], client=row[1], name=row[2], qtype=row[3], action=row[4],
                reason=row[5], rule=row[6], elapsed_ms=row[7], cached=bool(row[8]),
                group_name=row[9],
            ).as_dict()
            for row in rows
        ]
