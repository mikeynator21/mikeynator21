"""Per-device policy: groups, schedules, category filters and safe search.

Not every device on a network deserves the same rules. A child's tablet, a smart
TV that phones home constantly, and a guest's laptop each want different
treatment, and the thing they have in common is that none of them will install
any software to get it. Everything here keys off the client's address, which is
all a DNS server ever knows about who is asking.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, time as clock_time
from typing import Iterable, NamedTuple

from .blocklist import DomainSet, Match, NO_MATCH, parent_domains

log = logging.getLogger(__name__)

#: Small curated category lists, used for scheduling and parental controls
#: rather than ad blocking. Kept short and obvious: these are levers a person
#: pulls deliberately, not lists that need to be exhaustive.
CATEGORIES: dict[str, list[str]] = {
    "social": [
        "facebook.com", "fb.com", "fbcdn.net", "messenger.com",
        "instagram.com", "cdninstagram.com",
        "tiktok.com", "tiktokv.com", "tiktokcdn.com", "musical.ly",
        "snapchat.com", "sc-cdn.net",
        "twitter.com", "x.com", "t.co", "twimg.com",
        "reddit.com", "redd.it", "redditmedia.com",
        "discord.com", "discordapp.com", "discord.gg",
        "tumblr.com", "pinterest.com", "threads.net",
    ],
    "video": [
        "youtube.com", "youtu.be", "ytimg.com", "googlevideo.com",
        "netflix.com", "nflxvideo.net", "nflximg.net",
        "twitch.tv", "ttvnw.net",
        "hulu.com", "disneyplus.com", "primevideo.com",
    ],
    "gaming": [
        "roblox.com", "rbxcdn.com",
        "epicgames.com", "fortnite.com",
        "steampowered.com", "steamcommunity.com",
        "minecraft.net", "mojang.com",
        "playstation.com", "xboxlive.com", "nintendo.net",
    ],
    "adult": [
        "pornhub.com", "xvideos.com", "xhamster.com", "redtube.com",
        "youporn.com", "onlyfans.com", "stripchat.com", "chaturbate.com",
    ],
    "gambling": [
        "bet365.com", "draftkings.com", "fanduel.com", "pokerstars.com",
        "bovada.lv", "stake.com",
    ],
    "news": [
        "cnn.com", "bbc.co.uk", "nytimes.com", "foxnews.com",
        "theguardian.com", "reuters.com",
    ],
    "shopping": [
        "amazon.com", "ebay.com", "aliexpress.com", "temu.com",
        "shein.com", "etsy.com", "walmart.com",
    ],
    "telemetry": [
        "telemetry.microsoft.com", "vortex.data.microsoft.com",
        "settings-win.data.microsoft.com", "watson.telemetry.microsoft.com",
        "metrics.apple.com", "smoot.apple.com",
        "app-measurement.com", "firebase-settings.crashlytics.com",
        "device-metrics-us.amazon.com",
    ],
}

#: Domains rewritten to a provider's filtered endpoint when safe search is on.
#: The providers publish these specifically for network-level enforcement.
SAFE_SEARCH_REWRITES: dict[str, str] = {
    "www.google.com": "forcesafesearch.google.com",
    "google.com": "forcesafesearch.google.com",
    "www.bing.com": "strict.bing.com",
    "bing.com": "strict.bing.com",
    "duckduckgo.com": "safe.duckduckgo.com",
    "www.duckduckgo.com": "safe.duckduckgo.com",
    "www.youtube.com": "restrictmoderate.youtube.com",
    "youtube.com": "restrictmoderate.youtube.com",
    "m.youtube.com": "restrictmoderate.youtube.com",
    "youtubei.googleapis.com": "restrictmoderate.youtube.com",
    "www.pixiv.net": "safe.pixiv.net",
}

#: The stricter YouTube endpoint, selected by `youtube_restrict = "strict"`.
YOUTUBE_STRICT = "restrict.youtube.com"


class Decision(NamedTuple):
    """What to do with one query."""

    action: str  # "allow", "block", or "rewrite"
    reason: str = ""
    rule: str = ""
    #: Set when action is "rewrite": the name to answer with instead.
    target: str = ""

    @property
    def blocked(self) -> bool:
        return self.action == "block"


ALLOW = Decision("allow")


@dataclass
class Schedule:
    """A recurring window during which a group's extra restrictions apply."""

    name: str
    start: clock_time
    end: clock_time
    #: 0 = Monday. Empty means every day.
    days: list[int] = field(default_factory=list)
    #: Categories blocked while the window is open.
    block_categories: list[str] = field(default_factory=list)
    #: Block everything except the group's allowlist while the window is open.
    block_all: bool = False

    def active_at(self, moment: datetime) -> bool:
        if self.days and moment.weekday() not in self.days:
            return False
        now = moment.time()
        if self.start <= self.end:
            return self.start <= now < self.end
        # A window that wraps past midnight, e.g. 22:00 to 07:00.
        return now >= self.start or now < self.end

    @classmethod
    def parse(cls, name: str, spec: dict) -> "Schedule":
        return cls(
            name=name,
            start=_parse_clock(spec.get("start", "00:00")),
            end=_parse_clock(spec.get("end", "00:00")),
            days=[_parse_day(day) for day in spec.get("days", [])],
            block_categories=list(spec.get("block_categories", [])),
            block_all=bool(spec.get("block_all", False)),
        )


def _parse_clock(value: str) -> clock_time:
    try:
        hour, _, minute = value.partition(":")
        return clock_time(int(hour), int(minute or 0))
    except (ValueError, TypeError) as exc:
        raise ValueError(f"{value!r} is not a valid time of day (use HH:MM)") from exc


_DAY_NAMES = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]


def _parse_day(value: str | int) -> int:
    if isinstance(value, int):
        return value % 7
    key = str(value).strip().lower()[:3]
    if key not in _DAY_NAMES:
        raise ValueError(f"{value!r} is not a day name (use mon, tue, ... sun)")
    return _DAY_NAMES.index(key)


@dataclass
class Group:
    """A named set of rules that devices are assigned to."""

    name: str
    #: Ad and tracker filtering. Off makes the group's devices unfiltered.
    filtering: bool = True
    block_categories: list[str] = field(default_factory=list)
    allow: list[str] = field(default_factory=list)
    block: list[str] = field(default_factory=list)
    schedules: list[Schedule] = field(default_factory=list)
    safe_search: bool = False
    youtube_restrict: str = ""  # "", "moderate" or "strict"
    #: Refuse queries for anything not explicitly allowed. For IoT devices that
    #: should only ever reach their vendor.
    default_deny: bool = False

    def __post_init__(self) -> None:
        self._allow_set = _domain_set(self.allow, f"group:{self.name}")
        self._block_set = _domain_set(self.block, f"group:{self.name}")
        self._category_set = _category_set(self.block_categories, f"group:{self.name}")

    def refresh(self) -> None:
        """Rebuild the compiled rule sets after the lists are edited."""
        self.__post_init__()


def _domain_set(entries: Iterable[str], source: str) -> DomainSet:
    compiled = DomainSet()
    for entry in entries:
        entry = entry.strip().lower()
        if not entry:
            continue
        if entry.startswith("/") and entry.endswith("/") and len(entry) > 2:
            compiled.add_regex(entry[1:-1], source)
        elif entry.startswith("*."):
            compiled.add_suffix(entry[2:], source)
        else:
            compiled.add_suffix(entry, source)
    return compiled


def _category_set(categories: Iterable[str], source: str) -> DomainSet:
    compiled = DomainSet()
    for category in categories:
        domains = CATEGORIES.get(category)
        if domains is None:
            log.warning("unknown category %r in %s", category, source)
            continue
        for domain in domains:
            compiled.add_suffix(domain, f"category:{category}")
    return compiled


@dataclass
class Device:
    """A known client, addressed by IP and identified however we can manage."""

    identifier: str  # An IP address, a CIDR range, a MAC, or a hostname glob.
    group: str = "default"
    label: str = ""


class PolicyEngine:
    """Maps a client address to a group, then a query to a decision."""

    def __init__(
        self,
        groups: dict[str, Group] | None = None,
        devices: Iterable[Device] = (),
        *,
        default_group: str = "default",
    ) -> None:
        self.groups: dict[str, Group] = groups or {"default": Group("default")}
        if default_group not in self.groups:
            self.groups[default_group] = Group(default_group)
        self.default_group = default_group
        self.devices = list(devices)
        #: Populated by the DHCP server so hostname and MAC rules can match.
        self.address_hints: dict[str, tuple[str, str]] = {}

        self._networks: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str]] = []
        self._exact: dict[str, str] = {}
        self._mac: dict[str, str] = {}
        self._hostname_globs: list[tuple[str, str]] = []
        self._compile_devices()

    def _compile_devices(self) -> None:
        self._networks.clear()
        self._exact.clear()
        self._mac.clear()
        self._hostname_globs.clear()

        for device in self.devices:
            identifier = device.identifier.strip().lower()
            if not identifier:
                continue
            if re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", identifier):
                self._mac[identifier] = device.group
                continue
            if "/" in identifier:
                try:
                    self._networks.append((ipaddress.ip_network(identifier, strict=False), device.group))
                    continue
                except ValueError:
                    pass
            try:
                ipaddress.ip_address(identifier)
                self._exact[identifier] = device.group
                continue
            except ValueError:
                pass
            self._hostname_globs.append((identifier, device.group))

    def set_devices(self, devices: Iterable[Device]) -> None:
        self.devices = list(devices)
        self._compile_devices()

    def note_client(self, address: str, mac: str = "", hostname: str = "") -> None:
        """Record what the DHCP server learned about an address."""
        if address:
            self.address_hints[address] = (mac.lower(), hostname.lower())

    def group_for(self, client_address: str) -> Group:
        """Which group a client belongs to."""
        address = (client_address or "").lower()

        group_name = self._exact.get(address)
        if group_name is None:
            mac, hostname = self.address_hints.get(address, ("", ""))
            if mac:
                group_name = self._mac.get(mac)
            if group_name is None and hostname:
                for pattern, candidate in self._hostname_globs:
                    if fnmatch.fnmatch(hostname, pattern):
                        group_name = candidate
                        break
        if group_name is None and self._networks:
            try:
                parsed = ipaddress.ip_address(address)
                # Most specific match wins, so a /32 override beats a /24 rule.
                matches = [
                    (network.prefixlen, name)
                    for network, name in self._networks
                    if parsed.version == network.version and parsed in network
                ]
                if matches:
                    group_name = max(matches)[1]
            except ValueError:
                pass

        return self.groups.get(group_name or self.default_group) or self.groups[self.default_group]

    def evaluate(
        self,
        name: str,
        client_address: str,
        *,
        now: datetime | None = None,
    ) -> tuple[Decision, Group]:
        """Decide what to do with `name` for this client, before blocklists.

        Returns the decision and the group it was made for; the caller applies
        the shared ad and tracker lists only when this returns "allow" and the
        group has filtering enabled.
        """
        group = self.group_for(client_address)
        name = name.strip(".").lower()
        moment = now or datetime.now()

        # An explicit per-group allow wins over everything, including schedules.
        allowed = group._allow_set.match(name)
        if allowed:
            return Decision("allow", "group allowlist", allowed.rule), group

        blocked = group._block_set.match(name)
        if blocked:
            return Decision("block", "group blocklist", blocked.rule), group

        category = group._category_set.match(name)
        if category:
            return Decision("block", "category", category.rule), group

        for schedule in group.schedules:
            if not schedule.active_at(moment):
                continue
            if schedule.block_all:
                return Decision("block", f"schedule:{schedule.name}", "all traffic"), group
            hit = _category_set(schedule.block_categories, f"schedule:{schedule.name}").match(name)
            if hit:
                return Decision("block", f"schedule:{schedule.name}", hit.rule), group

        if group.default_deny:
            return Decision("block", "default deny", "not in the group allowlist"), group

        rewrite = self._safe_search_target(name, group)
        if rewrite:
            return Decision("rewrite", "safe search", name, rewrite), group

        return ALLOW, group

    @staticmethod
    def _safe_search_target(name: str, group: Group) -> str:
        if not group.safe_search and not group.youtube_restrict:
            return ""

        if group.youtube_restrict and ("youtube.com" in name or "youtubei" in name):
            target = YOUTUBE_STRICT if group.youtube_restrict == "strict" else "restrictmoderate.youtube.com"
            # Never rewrite the target itself, or the answer would loop.
            return "" if name in (YOUTUBE_STRICT, "restrictmoderate.youtube.com") else target

        if not group.safe_search:
            return ""

        target = SAFE_SEARCH_REWRITES.get(name)
        if target and target != name:
            return target

        # Country domains: google.co.uk, google.de and the rest all redirect to
        # the same enforcement host.
        if re.fullmatch(r"(www\.)?google\.[a-z.]{2,6}", name):
            return "forcesafesearch.google.com"
        return ""


def build_groups(spec: dict) -> dict[str, Group]:
    """Construct groups from the parsed configuration file."""
    groups: dict[str, Group] = {}
    for name, entry in (spec or {}).items():
        schedules = [
            Schedule.parse(schedule_name, schedule_spec)
            for schedule_name, schedule_spec in (entry.get("schedules") or {}).items()
        ]
        groups[name] = Group(
            name=name,
            filtering=entry.get("filtering", True),
            block_categories=list(entry.get("block_categories", [])),
            allow=list(entry.get("allow", [])),
            block=list(entry.get("block", [])),
            schedules=schedules,
            safe_search=bool(entry.get("safe_search", False)),
            youtube_restrict=entry.get("youtube_restrict", ""),
            default_deny=bool(entry.get("default_deny", False)),
        )
    if "default" not in groups:
        groups["default"] = Group("default")
    return groups
