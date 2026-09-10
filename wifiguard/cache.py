"""TTL-aware DNS cache built to keep upstream traffic as low as possible.

Four things do the heavy lifting:

* **TTL flooring.** Ad and CDN records ship absurdly short TTLs (often 30s) to
  steer load balancing. Holding them for a configurable minimum collapses
  repeated lookups for the same name into one upstream query.
* **Prefetch.** A name that keeps being asked for is refreshed shortly *before*
  it expires, so the expiry never turns into a client-visible miss.
* **Serve-stale** (RFC 8767). If upstream is unreachable, an expired answer is
  still better than a failure, and the network stays usable when the uplink
  does not.
* **Persistence.** The cache is written to disk on shutdown and read back on
  start, so a reboot does not re-query everything a household looks up.
"""

from __future__ import annotations

import gzip
import logging
import struct
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, NamedTuple

from . import dnsmsg

log = logging.getLogger(__name__)

_MAGIC = b"WGDC3"


class CacheKey(NamedTuple):
    name: str
    qtype: int
    qclass: int
    #: Whether the stored answer carries DNSSEC records. A validating client
    #: that is handed an unsigned answer treats it as an attack, so signed and
    #: unsigned answers for the same name are different cache entries.
    dnssec: bool = False


@dataclass
class CacheEntry:
    wire: bytes
    stored_at: float
    expires_at: float
    ttl: int
    rcode: int
    hits: int = 0
    # Set while a prefetch for this key is already running, so a burst of
    # queries schedules exactly one refresh.
    refreshing: bool = False


class Lookup(NamedTuple):
    """The outcome of a cache read."""

    wire: bytes
    stale: bool
    age: int


@dataclass
class CacheStats:
    hits: int = 0
    misses: int = 0
    stale_hits: int = 0
    evictions: int = 0
    expired: int = 0
    prefetches: int = 0
    inserts: int = 0

    @property
    def hit_rate(self) -> float:
        total = self.hits + self.misses
        return self.hits / total if total else 0.0

    def as_dict(self) -> dict[str, float | int]:
        return {**self.__dict__, "hit_rate": round(self.hit_rate, 4)}


@dataclass
class CacheConfig:
    max_entries: int = 100_000
    # Hold every answer at least this long. The single biggest lever on upstream
    # query volume; 300s is invisible to users and cuts traffic hard.
    min_ttl: int = 300
    max_ttl: int = 86_400
    # Failures and NXDOMAIN are cached too, but briefly, so a typo storm or a
    # chatty offline device cannot hammer upstream.
    min_negative_ttl: int = 60
    max_negative_ttl: int = 3_600
    # Serve an expired answer for up to this long while a refresh is attempted.
    serve_stale_for: int = 86_400
    # Refresh an entry once it is this far into its life (0.9 = last 10%).
    prefetch_after: float = 0.9
    # Only prefetch names that have actually been asked for repeatedly.
    prefetch_min_hits: int = 2
    persist_path: Path | None = None


class DNSCache:
    """Thread-safe LRU cache of raw DNS responses."""

    def __init__(
        self,
        config: CacheConfig | None = None,
        *,
        prefetch: Callable[[CacheKey], None] | None = None,
    ) -> None:
        self.config = config or CacheConfig()
        self._entries: OrderedDict[CacheKey, CacheEntry] = OrderedDict()
        self._lock = threading.RLock()
        self.stats = CacheStats()
        self._prefetch = prefetch

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    def get(self, key: CacheKey, *, allow_stale: bool = False) -> Lookup | None:
        """Look up a key, returning a response with TTLs already aged down.

        `allow_stale` is set by the caller once upstream has failed: it turns an
        expired-but-retained entry into a usable answer instead of a SERVFAIL.
        """
        now = time.time()
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                self.stats.misses += 1
                return None

            age = int(now - entry.stored_at)
            fresh = now < entry.expires_at

            if not fresh:
                keep_until = entry.expires_at + self.config.serve_stale_for
                if now >= keep_until:
                    del self._entries[key]
                    self.stats.expired += 1
                    self.stats.misses += 1
                    return None
                if not allow_stale:
                    self.stats.misses += 1
                    # Retained, not returned: a live lookup is preferred while
                    # upstream is believed healthy.
                    return None

            self._entries.move_to_end(key)
            entry.hits += 1
            if fresh:
                self.stats.hits += 1
            else:
                self.stats.stale_hits += 1

            should_prefetch = (
                fresh
                and self._prefetch is not None
                and not entry.refreshing
                and entry.hits >= self.config.prefetch_min_hits
                and entry.ttl > 0
                and (now - entry.stored_at) >= entry.ttl * self.config.prefetch_after
            )
            if should_prefetch:
                entry.refreshing = True
                self.stats.prefetches += 1

            # A stale answer is handed out with a short TTL so the client comes
            # back soon rather than pinning an out-of-date record.
            wire = (
                dnsmsg.with_ttls_reduced(entry.wire, age)
                if fresh
                else _rewrite_all_ttls(entry.wire, 30)
            )
            result = Lookup(wire=wire, stale=not fresh, age=age)

        if should_prefetch:
            self._prefetch(key)  # type: ignore[misc]  # guarded above
        return result

    def put(self, key: CacheKey, wire: bytes, *, rcode: int | None = None) -> int:
        """Store a response. Returns the TTL it was cached for (0 = not cached)."""
        try:
            header = dnsmsg.parse_header(wire)
        except dnsmsg.DNSFormatError:
            return 0

        if rcode is None:
            rcode = header.rcode

        # Truncated answers are an instruction to retry over TCP, not data.
        if header.truncated:
            return 0

        negative = rcode != dnsmsg.RCODE_NOERROR or header.ancount == 0
        try:
            upstream_ttl = dnsmsg.message_ttl(wire, default=0)
        except dnsmsg.DNSFormatError:
            return 0

        if negative:
            ttl = _clamp(upstream_ttl, self.config.min_negative_ttl, self.config.max_negative_ttl)
        else:
            ttl = _clamp(upstream_ttl, self.config.min_ttl, self.config.max_ttl)

        if ttl <= 0:
            return 0

        now = time.time()
        with self._lock:
            self._entries[key] = CacheEntry(
                wire=wire,
                stored_at=now,
                expires_at=now + ttl,
                ttl=ttl,
                rcode=rcode,
            )
            self._entries.move_to_end(key)
            self.stats.inserts += 1
            self._evict_if_needed()
        return ttl

    def finish_refresh(self, key: CacheKey) -> None:
        """Clear the in-progress flag after a prefetch attempt, success or not."""
        with self._lock:
            entry = self._entries.get(key)
            if entry is not None:
                entry.refreshing = False

    def invalidate(self, name: str | None = None) -> int:
        """Drop entries for one name, or the whole cache when name is None."""
        with self._lock:
            if name is None:
                dropped = len(self._entries)
                self._entries.clear()
                return dropped
            target = name.strip(".").lower()
            doomed = [key for key in self._entries if key.name == target]
            for key in doomed:
                del self._entries[key]
            return len(doomed)

    def _evict_if_needed(self) -> None:
        while len(self._entries) > self.config.max_entries:
            self._entries.popitem(last=False)
            self.stats.evictions += 1

    def snapshot(self) -> list[dict[str, object]]:
        """Cache contents for the dashboard, most recently used first."""
        now = time.time()
        with self._lock:
            return [
                {
                    "name": key.name,
                    "type": dnsmsg.type_name(key.qtype),
                    "dnssec": key.dnssec,
                    "hits": entry.hits,
                    "expires_in": max(0, int(entry.expires_at - now)),
                    "stale": now >= entry.expires_at,
                }
                for key, entry in reversed(self._entries.items())
            ]

    # -- persistence ------------------------------------------------------

    def save(self, path: Path | None = None) -> int:
        """Write unexpired entries to disk. Returns the number saved."""
        path = path or self.config.persist_path
        if path is None:
            return 0

        now = time.time()
        out = bytearray(_MAGIC)
        saved = 0
        body = bytearray()
        with self._lock:
            for key, entry in self._entries.items():
                if now >= entry.expires_at:
                    continue
                name = key.name.encode("utf-8")
                if len(name) > 0xFFFF or len(entry.wire) > 0xFFFF:
                    continue
                body += struct.pack("!H", len(name)) + name
                body += struct.pack("!HHB", key.qtype, key.qclass, int(key.dnssec))
                body += struct.pack("!ddIIH", entry.stored_at, entry.expires_at, entry.ttl, entry.hits, len(entry.wire))
                body += entry.wire
                saved += 1

        out += struct.pack("!I", saved) + body
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(path.suffix + ".tmp")
            tmp.write_bytes(gzip.compress(bytes(out), compresslevel=6))
            tmp.replace(path)
        except OSError as exc:
            log.warning("could not persist DNS cache: %s", exc)
            return 0
        log.info("persisted %d cache entries to %s", saved, path)
        return saved

    def load(self, path: Path | None = None) -> int:
        """Restore entries written by `save`, discarding any that expired."""
        path = path or self.config.persist_path
        if path is None or not path.exists():
            return 0

        try:
            raw = gzip.decompress(path.read_bytes())
        except (OSError, gzip.BadGzipFile) as exc:
            log.warning("could not read persisted DNS cache: %s", exc)
            return 0

        if not raw.startswith(_MAGIC):
            log.warning("ignoring cache file %s: unrecognised format", path)
            return 0

        now = time.time()
        offset = len(_MAGIC)
        # Bound before the try, not inside it: a file truncated to just the
        # magic makes the very first unpack raise, and the handler whose whole
        # job is to shrug off a corrupt file would itself fail on an unbound
        # name.
        restored = 0
        try:
            (count,) = struct.unpack_from("!I", raw, offset)
            offset += 4
            with self._lock:
                for _ in range(count):
                    (name_len,) = struct.unpack_from("!H", raw, offset)
                    offset += 2
                    if offset + name_len > len(raw):
                        raise IndexError("name runs past the end of the file")
                    name = raw[offset : offset + name_len].decode("utf-8")
                    offset += name_len
                    qtype, qclass, dnssec = struct.unpack_from("!HHB", raw, offset)
                    offset += 5
                    stored_at, expires_at, ttl, hits, wire_len = struct.unpack_from("!ddIIH", raw, offset)
                    offset += struct.calcsize("!ddIIH")
                    # Slicing past the end yields a short read rather than an
                    # error, and a truncated message that still has a readable
                    # header would be cached and served to a client.
                    if offset + wire_len > len(raw):
                        raise IndexError("response runs past the end of the file")
                    wire = raw[offset : offset + wire_len]
                    offset += wire_len

                    if now >= expires_at:
                        continue
                    # Walked in full, so a message that survives cannot raise
                    # later when its TTLs are rewritten on the way out.
                    dnsmsg.message_ttl(wire)
                    self._entries[CacheKey(name, qtype, qclass, bool(dnssec))] = CacheEntry(
                        wire=wire,
                        stored_at=stored_at,
                        expires_at=expires_at,
                        ttl=ttl,
                        rcode=dnsmsg.parse_header(wire).rcode,
                        hits=hits,
                    )
                    restored += 1
                self._evict_if_needed()
        except (struct.error, IndexError, UnicodeDecodeError, dnsmsg.DNSFormatError) as exc:
            log.warning("persisted DNS cache is corrupt, ignoring the rest: %s", exc)

        log.info("restored %d cache entries from %s", restored, path)
        return restored


def _clamp(value: int, low: int, high: int) -> int:
    return max(low, min(value, high))


def _rewrite_all_ttls(wire: bytes, ttl: int) -> bytes:
    """Force every TTL in a message to `ttl`, used when serving stale data."""
    try:
        out = bytearray(wire)
        for rr in dnsmsg.iter_records(wire):
            if rr.rtype != dnsmsg.TYPE_OPT:
                struct.pack_into("!I", out, rr.ttl_offset, ttl)
        return bytes(out)
    except dnsmsg.DNSFormatError:
        return wire


class SingleFlight:
    """Collapses concurrent identical lookups into one upstream query.

    Twelve devices waking up and asking for the same name at once is the normal
    pattern on a home network; without this, that is twelve upstream queries for
    one answer.
    """

    #: A published answer stays readable for this long. Setting an event wakes a
    #: follower but does not run it: it still has to be scheduled and reacquire
    #: the lock. Dropping the answer the moment the leader returns means the
    #: follower almost always arrives to find it gone, and the collapse quietly
    #: degrades into a second cache lookup -- which fails outright for an answer
    #: that was not cacheable. A short window makes the handover reliable.
    RESULT_GRACE = 2.0
    #: Hard ceiling on retained answers, so a flood of distinct names inside one
    #: grace window cannot grow this without bound.
    MAX_RESULTS = 512

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._waiters: dict[CacheKey, threading.Event] = {}
        self._results: dict[CacheKey, tuple[bytes | None, float]] = {}

    def leader(self, key: CacheKey) -> tuple[bool, threading.Event]:
        """Claim a key. Returns (is_leader, event) -- followers wait on it."""
        with self._lock:
            event = self._waiters.get(key)
            if event is not None:
                return False, event
            event = threading.Event()
            self._waiters[key] = event
            return True, event

    def publish(self, key: CacheKey, result: bytes | None) -> None:
        """Hand the leader's result to any followers and release them."""
        now = time.monotonic()
        with self._lock:
            self._results[key] = (result, now)
            event = self._waiters.pop(key, None)
            self._prune(now)
        if event is not None:
            event.set()

    def collect(self, key: CacheKey, event: threading.Event, timeout: float) -> bytes | None:
        """Wait for the leader's result. Returns None on timeout or failure."""
        if not event.wait(timeout):
            return None
        with self._lock:
            found = self._results.get(key)
        return found[0] if found is not None else None

    def done(self, key: CacheKey) -> None:
        """End a leader's turn, whether or not it managed to publish.

        A leader that dies on an unexpected error would otherwise leave its
        event in the map with nothing left to set it, and every later query for
        that name would become a follower waiting the full timeout on a leader
        that no longer exists -- for the life of the process.
        """
        with self._lock:
            event = self._waiters.pop(key, None)
        if event is not None:
            event.set()

    def _prune(self, now: float) -> None:
        """Drop answers nobody can still be waiting for. Caller holds the lock."""
        if len(self._results) <= self.MAX_RESULTS // 2:
            return
        cutoff = now - self.RESULT_GRACE
        self._results = {
            key: value for key, value in self._results.items() if value[1] > cutoff
        }
        if len(self._results) > self.MAX_RESULTS:
            # Still oversized: every entry is inside its grace window, so shed
            # the oldest half rather than let a flood pin memory.
            ordered = sorted(self._results.items(), key=lambda item: item[1][1])
            self._results = dict(ordered[len(ordered) // 2 :])
