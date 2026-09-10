"""Blocklist loading, parsing and matching.

Handles the three formats community lists ship in -- hosts files, plain domain
lists and Adblock-style ``||domain^`` rules -- plus wildcards and regexes, and
folds them into one structure that answers "is this name blocked?" in time
proportional to the number of labels in the name.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import logging
import os
import re
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, NamedTuple

log = logging.getLogger(__name__)

USER_AGENT = "WiFiGuard/1.0 (+https://github.com/mikeynator21/wifiguard)"
FETCH_TIMEOUT = 30

# Addresses a hosts file uses to mean "nowhere".  A line pointing at any other
# address is a real host mapping, not a block rule, and is ignored.
SINKHOLE_ADDRESSES = frozenset({"0.0.0.0", "127.0.0.1", "::", "::1", "0.0.0.0.0.0"})

# Names that appear in hosts files as part of normal system configuration and
# must never be treated as block rules.
HOSTS_NOISE = frozenset({"localhost", "localhost.localdomain", "local", "broadcasthost", "ip6-localhost", "ip6-loopback", "ip6-localnet", "ip6-mcastprefix", "ip6-allnodes", "ip6-allrouters", "ip6-allhosts", "0.0.0.0"})

_ADBLOCK_BLOCK = re.compile(r"^\|\|([^\^/\*]+)\^?(\$[^\s]*)?$")
_ADBLOCK_ALLOW = re.compile(r"^@@\|\|([^\^/\*]+)\^?(\$[^\s]*)?$")
_VALID_DOMAIN = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)(\.(?!-)[a-z0-9_-]{1,63}(?<!-))*$")


class Match(NamedTuple):
    """Why a name was blocked (or allowed)."""

    matched: bool
    rule: str = ""
    source: str = ""

    def __bool__(self) -> bool:  # pragma: no cover - trivial
        return self.matched


NO_MATCH = Match(False)


def parent_domains(name: str) -> Iterable[str]:
    """Yield `name` and each of its parent domains, longest first.

    ``a.b.example.com`` yields itself, ``b.example.com``, ``example.com`` and
    ``com``.  Walking this is how a suffix rule matches every name beneath it
    without storing them.
    """
    name = name.strip(".").lower()
    while name:
        yield name
        dot = name.find(".")
        if dot < 0:
            return
        name = name[dot + 1 :]


class DomainSet:
    """A set of domain rules that can be matched against a query name.

    Rules come in three flavours, each stored separately because they match
    differently: exact names, suffix rules (the name and everything under it)
    and regexes.
    """

    def __init__(self) -> None:
        self.exact: dict[str, str] = {}
        self.suffix: dict[str, str] = {}
        self.regex: list[tuple[re.Pattern[str], str]] = []

    def __len__(self) -> int:
        return len(self.exact) + len(self.suffix) + len(self.regex)

    def clear(self) -> None:
        self.exact.clear()
        self.suffix.clear()
        self.regex.clear()

    def add_exact(self, domain: str, source: str = "") -> None:
        self.exact.setdefault(domain, source)

    def add_suffix(self, domain: str, source: str = "") -> None:
        # A suffix rule subsumes the exact rule for the same name.
        self.exact.pop(domain, None)
        self.suffix[domain] = source

    def add_regex(self, pattern: str, source: str = "") -> None:
        try:
            self.regex.append((re.compile(pattern, re.IGNORECASE), source))
        except re.error as exc:
            log.warning("skipping invalid regex %r from %s: %s", pattern, source or "config", exc)

    def match(self, name: str) -> Match:
        name = name.strip(".").lower()
        if not name:
            return NO_MATCH

        source = self.exact.get(name)
        if source is not None:
            return Match(True, name, source)

        if self.suffix:
            for candidate in parent_domains(name):
                source = self.suffix.get(candidate)
                if source is not None:
                    return Match(True, f"*.{candidate}", source)

        for pattern, source in self.regex:
            if pattern.search(name):
                return Match(True, f"/{pattern.pattern}/", source)

        return NO_MATCH


@dataclass
class SourceStats:
    """What one blocklist source contributed on its last load."""

    url: str
    rules: int = 0
    updated_at: float = 0.0
    error: str = ""
    from_cache: bool = False


@dataclass
class ParseResult:
    block: DomainSet = field(default_factory=DomainSet)
    allow: DomainSet = field(default_factory=DomainSet)
    lines_read: int = 0
    lines_skipped: int = 0


def parse_rules(
    text: str,
    source: str,
    *,
    hosts_match_subdomains: bool = True,
    into: ParseResult | None = None,
) -> ParseResult:
    """Parse any supported list format into block/allow rules.

    `hosts_match_subdomains` decides whether a bare domain (from a hosts file or
    a plain list) also blocks everything beneath it.  Curated lists name base
    tracker domains and expect subdomains to fall with them, so this defaults to
    on; turning it off makes such entries match the exact name only.
    """
    result = into if into is not None else ParseResult()

    for raw in text.splitlines():
        result.lines_read += 1
        line = raw.strip()
        if not line or line[0] in "#!;[":
            continue

        # Strip trailing comments, but not from regex rules where # is literal.
        if not line.startswith("/"):
            for marker in (" #", "\t#"):
                index = line.find(marker)
                if index >= 0:
                    line = line[:index].strip()
            if not line:
                continue

        if _consume_rule(line, source, result, hosts_match_subdomains):
            continue
        result.lines_skipped += 1

    return result


def _consume_rule(
    line: str, source: str, result: ParseResult, hosts_match_subdomains: bool
) -> bool:
    """Apply one already-trimmed line. Returns False if it isn't a usable rule."""
    allow_match = _ADBLOCK_ALLOW.match(line)
    if allow_match:
        domain = _normalise(allow_match.group(1))
        if domain:
            result.allow.add_suffix(domain, source)
            return True
        return False

    block_match = _ADBLOCK_BLOCK.match(line)
    if block_match:
        domain = _normalise(block_match.group(1))
        if domain:
            result.block.add_suffix(domain, source)
            return True
        return False

    # An Adblock rule we do not support (element hiding, path matching, options
    # that need HTTP context).  Recognised so it is not counted as garbage.
    if line.startswith(("@@", "||", "|", "/", "##", "#@#", "#?#")) and not line.startswith("/*"):
        if line.startswith("/") and line.endswith("/") and len(line) > 2:
            result.block.add_regex(line[1:-1], source)
            return True
        return False

    fields = line.split()

    # Hosts format: an address followed by one or more names.
    if len(fields) >= 2 and _looks_like_address(fields[0]):
        if fields[0] not in SINKHOLE_ADDRESSES:
            return False
        added = False
        for candidate in fields[1:]:
            if candidate.startswith("#"):
                break
            domain = _normalise(candidate)
            if domain and domain not in HOSTS_NOISE:
                _add_domain(result.block, domain, source, hosts_match_subdomains)
                added = True
        return added

    if len(fields) != 1:
        return False

    entry = fields[0]

    if entry.startswith("*."):
        domain = _normalise(entry[2:])
        if domain:
            result.block.add_suffix(domain, source)
            return True
        return False

    domain = _normalise(entry)
    if domain and domain not in HOSTS_NOISE:
        _add_domain(result.block, domain, source, hosts_match_subdomains)
        return True
    return False


def _add_domain(target: DomainSet, domain: str, source: str, as_suffix: bool) -> None:
    if as_suffix:
        target.add_suffix(domain, source)
    else:
        target.add_exact(domain, source)


def _looks_like_address(text: str) -> bool:
    return bool(re.match(r"^[0-9]{1,3}(\.[0-9]{1,3}){3}$", text) or ":" in text)


def _normalise(domain: str) -> str:
    """Lowercase and validate a domain, returning "" if it isn't usable."""
    domain = domain.strip().strip(".").lower()
    if not domain or len(domain) > 253:
        return ""
    if domain.startswith(("http://", "https://")):
        domain = domain.split("://", 1)[1].split("/", 1)[0]
    if "/" in domain or " " in domain:
        return ""
    if not domain.isascii():
        try:
            domain = domain.encode("idna").decode("ascii")
        except UnicodeError:
            return ""
    if not _VALID_DOMAIN.match(domain):
        return ""
    return domain


class BlocklistManager:
    """Fetches, caches and compiles the configured blocklists.

    Sources are downloaded to a cache directory so a restart -- or a boot with
    no internet yet, which is the normal case for a home gateway -- still comes
    up filtering.
    """

    def __init__(
        self,
        cache_dir: str | os.PathLike[str],
        *,
        hosts_match_subdomains: bool = True,
    ) -> None:
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.hosts_match_subdomains = hosts_match_subdomains

        self.block = DomainSet()
        self.allow = DomainSet()
        self.sources: dict[str, SourceStats] = {}
        self.last_update: float = 0.0
        self._validator_cache: dict[str, dict[str, str]] | None = None

    @property
    def rule_count(self) -> int:
        return len(self.block)

    def is_allowed(self, name: str) -> Match:
        return self.allow.match(name)

    def is_blocked(self, name: str) -> Match:
        return self.block.match(name)

    def load(
        self,
        urls: Iterable[str],
        *,
        extra_block: Iterable[str] = (),
        extra_allow: Iterable[str] = (),
        extra_regex: Iterable[str] = (),
        refresh: bool = False,
        max_age: float = 24 * 3600,
    ) -> None:
        """Build the rule sets from `urls` plus the locally configured rules.

        With `refresh` false, a cached copy younger than `max_age` is used
        without touching the network.
        """
        result = ParseResult()
        sources: dict[str, SourceStats] = {}

        for url in urls:
            stats = SourceStats(url=url)
            try:
                text, from_cache, fetched_at = self._read_source(url, refresh=refresh, max_age=max_age)
            except Exception as exc:  # noqa: BLE001 - one bad source must not stop the rest
                stats.error = str(exc)
                log.error("blocklist %s could not be loaded: %s", url, exc)
                sources[url] = stats
                continue

            before = len(result.block) + len(result.allow)
            parse_rules(
                text,
                source=url,
                hosts_match_subdomains=self.hosts_match_subdomains,
                into=result,
            )
            stats.rules = len(result.block) + len(result.allow) - before
            stats.from_cache = from_cache
            stats.updated_at = fetched_at
            sources[url] = stats
            log.info("blocklist %s: %d rules%s", url, stats.rules, " (cached)" if from_cache else "")

        for entry in extra_block:
            domain = _normalise(entry[2:] if entry.startswith("*.") else entry)
            if domain:
                result.block.add_suffix(domain, "config")
        for entry in extra_allow:
            domain = _normalise(entry[2:] if entry.startswith("*.") else entry)
            if domain:
                result.allow.add_suffix(domain, "config")
        for pattern in extra_regex:
            result.block.add_regex(pattern, "config")

        self.block = result.block
        self.allow = result.allow
        self.sources = sources
        self.last_update = time.time()
        log.info(
            "blocklists compiled: %d block rules, %d allow rules from %d sources",
            len(self.block),
            len(self.allow),
            len(sources),
        )

    def _cache_path(self, url: str) -> Path:
        digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]
        return self.cache_dir / f"{digest}.list.gz"

    def _read_source(
        self, url: str, *, refresh: bool, max_age: float
    ) -> tuple[str, bool, float]:
        """Return (text, came_from_cache, fetched_at) for one source.

        Bandwidth is the scarce resource here: a fresh-enough cache is used
        without any request at all, and when a refresh is due the stored
        validators turn it into a conditional GET that usually comes back as an
        empty 304 rather than a multi-megabyte body.
        """
        # A local path or file:// URL is read directly; there is nothing to cache.
        if not url.startswith(("http://", "https://")):
            path = Path(url[7:] if url.startswith("file://") else url)
            return path.read_text(encoding="utf-8", errors="replace"), False, path.stat().st_mtime

        cache = self._cache_path(url)
        cached_text: str | None = None
        cached_at = 0.0
        if cache.exists():
            try:
                cached_text = gzip.decompress(cache.read_bytes()).decode("utf-8", errors="replace")
                cached_at = cache.stat().st_mtime
            except (OSError, gzip.BadGzipFile) as exc:
                log.warning("discarding unreadable cache for %s: %s", url, exc)
                cached_text = None

        if cached_text is not None and not refresh and (time.time() - cached_at) < max_age:
            return cached_text, True, cached_at

        validators = self._validators.get(url, {}) if cached_text is not None else {}
        try:
            payload, new_validators = self._download(url, validators)
        except Exception:
            if cached_text is not None:
                log.warning("using cached copy of %s after download failure", url)
                return cached_text, True, cached_at
            raise

        if payload is None:
            # 304 Not Modified: the cached body is still current, and the only
            # bytes that crossed the network were the request and its headers.
            log.info("blocklist %s unchanged (304)", url)
            cache.touch()
            self._save_validators()
            return cached_text or "", True, time.time()

        self._validators[url] = new_validators
        self._save_validators()
        tmp = cache.with_suffix(".tmp")
        tmp.write_bytes(gzip.compress(payload.encode("utf-8"), compresslevel=6))
        tmp.replace(cache)
        return payload, False, time.time()

    @property
    def _validators(self) -> dict[str, dict[str, str]]:
        if self._validator_cache is None:
            path = self.cache_dir / "validators.json"
            try:
                self._validator_cache = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                self._validator_cache = {}
        return self._validator_cache

    def _save_validators(self) -> None:
        path = self.cache_dir / "validators.json"
        try:
            path.write_text(json.dumps(self._validators), encoding="utf-8")
        except OSError as exc:  # pragma: no cover - disk full, read-only fs
            log.warning("could not persist blocklist validators: %s", exc)

    @staticmethod
    def _download(
        url: str, validators: dict[str, str]
    ) -> tuple[str | None, dict[str, str]]:
        """Fetch a list, returning (text, validators) or (None, ...) on a 304."""
        headers = {"User-Agent": USER_AGENT, "Accept-Encoding": "gzip"}
        if etag := validators.get("etag"):
            headers["If-None-Match"] = etag
        if modified := validators.get("last_modified"):
            headers["If-Modified-Since"] = modified

        request = urllib.request.Request(url, headers=headers)
        context = ssl.create_default_context()
        try:
            with urllib.request.urlopen(request, timeout=FETCH_TIMEOUT, context=context) as response:
                payload = response.read()
                if response.headers.get("Content-Encoding", "").lower() == "gzip":
                    payload = gzip.decompress(payload)
                fresh = {}
                if tag := response.headers.get("ETag"):
                    fresh["etag"] = tag
                if modified := response.headers.get("Last-Modified"):
                    fresh["last_modified"] = modified
                return payload.decode("utf-8", errors="replace"), fresh
        except urllib.error.HTTPError as exc:
            if exc.code == 304:
                return None, validators
            raise


# Curated defaults: broad ad/tracker coverage that is safe on a family network.
# Kept deliberately short -- these lists overlap heavily, and each extra source
# costs a download on every refresh for rules the others already carry.
DEFAULT_BLOCKLISTS = [
    # Ads, trackers and malware, consolidated and deduplicated.
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    # CNAME-disguised trackers, which resolve inside first-party subdomains and
    # so are invisible to the lists above.
    "https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_trackers_justdomains.txt",
    # Smart-TV and set-top-box telemetry.
    "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV.txt",
]

# Opt-in hardening beyond ads: phishing, malware C2 and newly registered domains
# used in short-lived campaigns.  Enabled by the "strict" protection level.
SECURITY_BLOCKLISTS = [
    "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt",
    "https://phishing.army/download/phishing_army_blocklist_extended.txt",
    "https://urlhaus.abuse.ch/downloads/hostfile/",
]

# Public DNS-over-HTTPS and DNS-over-TLS endpoints.
#
# Browsers and phone operating systems increasingly resolve names through their
# own encrypted resolver, which silently bypasses a network-level filter: the
# device never sends us a query at all.  Blocking the *bootstrap* hostnames of
# those resolvers makes the client fail its DoH probe and fall back to the
# network's DNS, which is us.  This is what makes filtering hold for every
# device on the WiFi rather than only the cooperative ones.
DOH_BOOTSTRAP_DOMAINS = [
    "dns.google",
    "dns64.dns.google",
    "cloudflare-dns.com",
    "one.one.one.one",
    "mozilla.cloudflare-dns.com",
    "security.cloudflare-dns.com",
    "family.cloudflare-dns.com",
    "chrome.cloudflare-dns.com",
    "dns.quad9.net",
    "dns9.quad9.net",
    "dns10.quad9.net",
    "dns11.quad9.net",
    "doh.opendns.com",
    "doh.familyshield.opendns.com",
    "dns.nextdns.io",
    "dns.adguard.com",
    "dns.adguard-dns.com",
    "unfiltered.adguard-dns.com",
    "family.adguard-dns.com",
    "doh.cleanbrowsing.org",
    "doh.mullvad.net",
    "dns.mullvad.net",
    "doh.libredns.gr",
    "dns.controld.com",
    "freedns.controld.com",
    "doh.dnslify.com",
    "dns.rubyfish.cn",
    "doh.42l.fr",
    "doh.tiar.app",
    "dnsforge.de",
    "dns.digitale-gesellschaft.ch",
    "doh.ffmuc.net",
    "odvr.nic.cz",
    "dns.switch.ch",
    "resolver.dnscrypt.info",
    "dns.oszx.co",
    "doh.centraleu.pi-dns.com",
    "doh.applied-privacy.net",
    "dns.aa.net.uk",
    "dns.brahma.world",
    "basic.rethinkdns.com",
    "sky.rethinkdns.com",
    "use-application-dns.net",
]

# Domains that break common services when blocked; shipped as a default
# allowlist so a first-time install does not look broken.
DEFAULT_ALLOWLIST = [
    "s.youtube.com",
    "clients2.google.com",
    "clients4.google.com",
    "app-measurement.com",
    "graph.facebook.com",
    "mesu.apple.com",
    "gspe1-ssl.ls.apple.com",
    "captive.apple.com",
    "connectivitycheck.gstatic.com",
    "msftconnecttest.com",
    "msftncsi.com",
]
