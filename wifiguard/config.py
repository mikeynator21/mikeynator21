"""Configuration loading and validation.

Config is TOML, read with the standard library's `tomllib`. Every setting has a
working default, so an empty file is a valid configuration and the shipped
example is documentation rather than a requirement.

Validation is strict and the errors name the fix: a gateway that fails to start
at 11pm because a value was misspelled should say which value.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import tomllib
from dataclasses import dataclass, field, fields, is_dataclass
from pathlib import Path
from typing import Any

from . import blocklist as blocklist_module
from . import resolver as resolver_module
from .cache import CacheConfig
from .cluster import ClusterConfig
from .engine import EngineConfig
from .policy import CATEGORIES, Device, Group, build_groups
from .server import ServerConfig
from .tlsutil import TLSPolicy

log = logging.getLogger(__name__)

DEFAULT_CONFIG_PATHS = [
    Path("/etc/wifiguard/wifiguard.toml"),
    Path.home() / ".config/wifiguard/wifiguard.toml",
    Path("wifiguard.toml"),
]

DEFAULT_STATE_DIR = Path(os.environ.get("WIFIGUARD_STATE", "/var/lib/wifiguard"))

PROTECTION_LEVELS = ("standard", "strict", "paranoid")


class ConfigError(ValueError):
    """The configuration file is invalid."""


@dataclass
class NetworkSettings:
    """How WiFiGuard finds the other networks on the same router."""

    #: Widen `server.allowed_networks` to cover every private subnet this host
    #: is attached to. A modem with a 2.4GHz, a 5GHz and a guest SSID often
    #: means several subnets, and all of them should be filtered.
    discover_local: bool = True
    #: Route every discovered local network to VPN peers, so a phone on the
    #: tunnel can reach devices on any of them.
    route_to_vpn_peers: bool = True
    #: Extra subnets to serve that are not directly attached -- a VLAN behind
    #: the router, or a second access point on its own range.
    extra_networks: list[str] = field(default_factory=list)
    #: Map a subnet to a policy group, so the guest SSID can be filtered harder
    #: than the main one.
    group_by_network: dict[str, str] = field(default_factory=dict)


@dataclass
class UpstreamSettings:
    servers: list[str] = field(default_factory=lambda: list(resolver_module.DEFAULT_UPSTREAMS))
    timeout: float = 5.0
    require_encrypted: bool = True
    use_0x20: bool = True
    #: "compatible", "strict" or "paranoid" -- see tlsutil.TLSPolicy.
    tls_profile: str = "strict"
    #: hostname -> list of base64 SHA-256 SPKI pins.
    pins: dict[str, list[str]] = field(default_factory=dict)


@dataclass
class BlocklistSettings:
    sources: list[str] = field(default_factory=lambda: list(blocklist_module.DEFAULT_BLOCKLISTS))
    security_sources: list[str] = field(default_factory=list)
    allow: list[str] = field(default_factory=lambda: list(blocklist_module.DEFAULT_ALLOWLIST))
    block: list[str] = field(default_factory=list)
    regex: list[str] = field(default_factory=list)
    #: Block the bootstrap names of public DoH resolvers so clients cannot
    #: bypass filtering with their own encrypted DNS.
    block_doh_bypass: bool = True
    #: A bare domain in a hosts-format list also blocks everything beneath it.
    hosts_match_subdomains: bool = True
    #: Refresh interval in hours. Refreshes are conditional requests, so a
    #: frequent schedule is cheap; the default is still weekly.
    refresh_hours: int = 168
    update_on_start: bool = False


@dataclass
class VPNSettings:
    enabled: bool = False
    endpoint: str = ""
    subnet: str = "10.9.0.0/24"
    listen_port: int = 51820
    interface: str = "wg0"
    config_path: str = "/etc/wireguard/wg0.conf"


@dataclass
class HotspotSettings:
    enabled: bool = False
    ssid: str = "WiFiGuard"
    passphrase: str = ""
    #: Wireless interface to run the access point on. Empty means autodetect.
    interface: str = ""
    #: Uplink interface. Empty means "whatever holds the default route", which
    #: is what makes the gateway follow the laptop from network to network.
    uplink: str = ""
    subnet: str = ""  # Empty means pick one that does not clash with the uplink.
    channel: int = 0  # 0 means pick the least crowded.
    band: str = "auto"  # "2.4", "5" or "auto".
    #: Regulatory domain. Getting this wrong is illegal in some places and
    #: stops 5GHz from working in most.
    country_code: str = "US"
    hidden: bool = False
    #: WPA3-only. Stronger, but older devices cannot join at all; the default
    #: accepts WPA3 and WPA2 on the same SSID.
    wpa3_only: bool = False
    #: Stop hotspot clients from reaching each other.
    client_isolation: bool = False
    #: Route client traffic through the VPN, and drop it when the tunnel is down.
    route_through_vpn: bool = False
    #: Stop clients from reaching the network the laptop joined.
    isolate_from_uplink: bool = True
    allow_ipv6: bool = False
    lease_seconds: int = 3600


@dataclass
class DashboardSettings:
    enabled: bool = True
    address: str = "127.0.0.1"
    port: int = 8080
    #: Setting this requires a password for any change; reads stay open on the
    #: local network. Empty disables authentication entirely.
    password: str = ""
    readonly: bool = False


@dataclass
class LoggingSettings:
    level: str = "INFO"
    log_queries: bool = True
    retention_days: int = 7
    database: str = ""  # Empty means <state_dir>/queries.db.


@dataclass
class Config:
    protection: str = "standard"
    state_dir: Path = field(default_factory=lambda: DEFAULT_STATE_DIR)
    server: ServerConfig = field(default_factory=ServerConfig)
    engine: EngineConfig = field(default_factory=EngineConfig)
    cache: CacheConfig = field(default_factory=CacheConfig)
    networks: NetworkSettings = field(default_factory=NetworkSettings)
    cluster: ClusterConfig = field(default_factory=ClusterConfig)
    upstream: UpstreamSettings = field(default_factory=UpstreamSettings)
    blocklists: BlocklistSettings = field(default_factory=BlocklistSettings)
    vpn: VPNSettings = field(default_factory=VPNSettings)
    hotspot: HotspotSettings = field(default_factory=HotspotSettings)
    dashboard: DashboardSettings = field(default_factory=DashboardSettings)
    logging: LoggingSettings = field(default_factory=LoggingSettings)
    groups: dict[str, Group] = field(default_factory=dict)
    devices: list[Device] = field(default_factory=list)
    source_path: Path | None = None

    # -- derived paths ----------------------------------------------------

    @property
    def blocklist_cache_dir(self) -> Path:
        return self.state_dir / "blocklists"

    @property
    def cache_file(self) -> Path:
        return self.state_dir / "dnscache.bin"

    @property
    def query_database(self) -> Path:
        return Path(self.logging.database) if self.logging.database else self.state_dir / "queries.db"

    @property
    def peer_store(self) -> Path:
        return self.state_dir / "peers.json"

    @property
    def lease_file(self) -> Path:
        return self.state_dir / "leases.json"

    @property
    def local_rules_file(self) -> Path:
        """Allow/block rules added at runtime from the dashboard or the CLI."""
        return self.state_dir / "local-rules.json"

    def resolved_listen_addresses(self) -> list[str]:
        """Concrete addresses to bind, expanding the "auto" keyword."""
        from .gateway.networks import resolve_listen_addresses

        return resolve_listen_addresses(self.server.listen_addresses, port=self.server.port)

    def resolved_allowed_networks(self) -> list[str]:
        """Client networks permitted to query us, including discovered subnets."""
        from .gateway.networks import allowed_networks

        configured = list(self.server.allowed_networks) + list(self.networks.extra_networks)
        return allowed_networks(configured, discover=self.networks.discover_local)

    def resolved_vpn_routes(self) -> list[str]:
        """Local networks advertised to VPN peers."""
        from .gateway.networks import vpn_routed_networks

        return vpn_routed_networks(
            list(self.networks.extra_networks),
            discover=self.networks.route_to_vpn_peers,
        )

    def tls_policy(self) -> TLSPolicy:
        return TLSPolicy(profile=self.upstream.tls_profile, pins=self.upstream.pins)  # type: ignore[arg-type]

    def effective_blocklists(self) -> list[str]:
        sources = list(self.blocklists.sources)
        if self.protection in ("strict", "paranoid"):
            for source in self.blocklists.security_sources or blocklist_module.SECURITY_BLOCKLISTS:
                if source not in sources:
                    sources.append(source)
        return sources

    def effective_block_rules(self) -> list[str]:
        rules = list(self.blocklists.block)
        if self.blocklists.block_doh_bypass:
            rules.extend(blocklist_module.DOH_BOOTSTRAP_DOMAINS)
        return rules


def load(path: str | os.PathLike[str] | None = None) -> Config:
    """Read a config file, or return defaults when none exists."""
    candidates = [Path(path)] if path else DEFAULT_CONFIG_PATHS
    for candidate in candidates:
        if candidate.exists():
            try:
                raw = tomllib.loads(candidate.read_text(encoding="utf-8"))
            except (OSError, tomllib.TOMLDecodeError) as exc:
                raise ConfigError(f"could not read {candidate}: {exc}") from exc
            config = from_mapping(raw)
            config.source_path = candidate
            log.info("loaded configuration from %s", candidate)
            return config

    if path:
        raise ConfigError(f"configuration file {path} does not exist")
    log.info("no configuration file found; using defaults")
    return apply_protection(Config())


def from_mapping(raw: dict[str, Any]) -> Config:
    """Build a Config from parsed TOML, validating as it goes."""
    config = Config()
    unknown_top = set(raw) - {
        "protection", "state_dir", "server", "engine", "cache", "upstream",
        "networks", "cluster", "blocklists", "vpn", "hotspot", "dashboard", "logging",
        "groups", "devices",
    }
    if unknown_top:
        raise ConfigError(
            f"unknown configuration section(s): {', '.join(sorted(unknown_top))}"
        )

    config.protection = raw.get("protection", "standard")
    if config.protection not in PROTECTION_LEVELS:
        raise ConfigError(
            f"protection must be one of {', '.join(PROTECTION_LEVELS)}, got {config.protection!r}"
        )
    if "state_dir" in raw:
        config.state_dir = Path(raw["state_dir"]).expanduser()

    _populate(config.server, raw.get("server", {}), "server")
    _populate(config.engine, raw.get("engine", {}), "engine")
    _populate(config.cache, raw.get("cache", {}), "cache")
    _populate(config.networks, raw.get("networks", {}), "networks")
    _populate(config.cluster, raw.get("cluster", {}), "cluster")
    _populate(config.upstream, raw.get("upstream", {}), "upstream")
    _populate(config.blocklists, raw.get("blocklists", {}), "blocklists")
    _populate(config.vpn, raw.get("vpn", {}), "vpn")
    _populate(config.hotspot, raw.get("hotspot", {}), "hotspot")
    _populate(config.dashboard, raw.get("dashboard", {}), "dashboard")
    _populate(config.logging, raw.get("logging", {}), "logging")

    config.groups = build_groups(raw.get("groups", {}))
    config.devices = [
        Device(
            identifier=str(entry.get("id") or entry.get("identifier") or ""),
            group=str(entry.get("group", "default")),
            label=str(entry.get("label", "")),
        )
        for entry in raw.get("devices", [])
    ]

    _validate(config)
    return apply_protection(config)


def _populate(target: Any, values: dict[str, Any], section: str) -> None:
    """Copy known keys onto a dataclass, rejecting unknown ones."""
    if not is_dataclass(target):  # pragma: no cover - programming error
        raise TypeError(f"{target!r} is not a dataclass")
    known = {entry.name for entry in fields(target)}
    unknown = set(values) - known
    if unknown:
        suggestions = ", ".join(sorted(known))
        raise ConfigError(
            f"unknown key(s) in [{section}]: {', '.join(sorted(unknown))}. "
            f"Valid keys are: {suggestions}"
        )
    for key, value in values.items():
        current = getattr(target, key)
        if isinstance(current, Path):
            value = Path(value)
        setattr(target, key, value)


def _validate(config: Config) -> None:
    if not 1 <= config.server.port <= 65_535:
        raise ConfigError(f"server.port must be 1-65535, got {config.server.port}")
    if not 1 <= config.dashboard.port <= 65_535:
        raise ConfigError(f"dashboard.port must be 1-65535, got {config.dashboard.port}")
    if config.server.port == config.dashboard.port:
        raise ConfigError("server.port and dashboard.port cannot be the same")

    if config.engine.block_mode not in ("zero", "nxdomain", "refused"):
        raise ConfigError(
            f"engine.block_mode must be zero, nxdomain or refused, got {config.engine.block_mode!r}"
        )
    if config.upstream.tls_profile not in ("compatible", "strict", "paranoid"):
        raise ConfigError(
            f"upstream.tls_profile must be compatible, strict or paranoid, "
            f"got {config.upstream.tls_profile!r}"
        )
    if not config.upstream.servers:
        raise ConfigError("upstream.servers must list at least one resolver")

    for network in list(config.networks.extra_networks) + list(config.networks.group_by_network):
        try:
            ipaddress.ip_network(network, strict=False)
        except ValueError as exc:
            raise ConfigError(f"[networks] contains {network!r}, which is not a subnet: {exc}") from exc

    for network in config.server.allowed_networks:
        try:
            ipaddress.ip_network(network, strict=False)
        except ValueError as exc:
            raise ConfigError(f"server.allowed_networks contains {network!r}: {exc}") from exc

    for name, group in config.groups.items():
        for category in group.block_categories:
            if category not in CATEGORIES:
                raise ConfigError(
                    f"group {name!r} blocks unknown category {category!r}. "
                    f"Known categories: {', '.join(sorted(CATEGORIES))}"
                )
        if group.youtube_restrict not in ("", "moderate", "strict"):
            raise ConfigError(
                f"group {name!r}: youtube_restrict must be \"moderate\" or \"strict\""
            )

    known_groups = set(config.groups) | {"default"}
    for device in config.devices:
        if not device.identifier:
            raise ConfigError("every entry in [[devices]] needs an `id`")
        if device.group not in known_groups:
            raise ConfigError(
                f"device {device.identifier!r} is assigned to unknown group "
                f"{device.group!r}; defined groups are {', '.join(sorted(known_groups))}"
            )

    if config.cluster.enabled:
        if not config.cluster.secret:
            raise ConfigError(
                "cluster.secret is required when clustering is enabled, and must be "
                "the same on every node. Generate one with: "
                'python3 -c "import secrets; print(secrets.token_hex(32))"'
            )
        if len(config.cluster.secret) < 32:
            raise ConfigError("cluster.secret must be at least 32 characters")
        if not config.cluster.peers:
            raise ConfigError("cluster.peers must list the other nodes' addresses")

    if config.vpn.enabled and not config.vpn.endpoint:
        raise ConfigError(
            "vpn.endpoint must be set to the address or hostname peers connect back to"
        )
    for key, value in (("vpn.subnet", config.vpn.subnet), ("hotspot.subnet", config.hotspot.subnet)):
        if value:
            try:
                ipaddress.ip_network(value)
            except ValueError as exc:
                raise ConfigError(f"{key} is not a valid network: {exc}") from exc

    if config.hotspot.enabled:
        if not config.hotspot.passphrase:
            raise ConfigError(
                "hotspot.passphrase is required when the hotspot is enabled; "
                "an open access point would let anyone nearby use the gateway"
            )
        if len(config.hotspot.passphrase) < 8:
            raise ConfigError("hotspot.passphrase must be at least 8 characters (WPA2 minimum)")
        if not 1 <= len(config.hotspot.ssid) <= 32:
            raise ConfigError("hotspot.ssid must be 1-32 characters")
        if config.hotspot.band not in ("2.4", "5", "auto"):
            raise ConfigError(f"hotspot.band must be 2.4, 5 or auto, got {config.hotspot.band!r}")


def apply_protection(config: Config) -> Config:
    """Fold the `protection` level into the individual settings.

    The level is a single dial for people who do not want to reason about
    fifteen options. Anything set explicitly in the file is left alone -- this
    only raises floors.
    """
    if config.protection in ("strict", "paranoid"):
        config.upstream.require_encrypted = True
        config.engine.rebinding_protection = True
        config.engine.uncloak_cnames = True
        config.blocklists.block_doh_bypass = True

    if config.protection == "paranoid":
        config.upstream.tls_profile = "paranoid"
        config.engine.refuse_any = True
        # Nothing that identifies a client should reach a third party, and a
        # shorter log retention limits what a stolen laptop reveals.
        config.logging.retention_days = min(config.logging.retention_days, 1)
    return config


EXAMPLE_CONFIG = """\
# WiFiGuard configuration.
#
# Every value below is a default; delete anything you do not want to change.
# `wifiguard check <domain>` explains what these settings do to a given name.

# "standard", "strict" or "paranoid". strict adds malware and phishing lists;
# paranoid additionally requires TLS 1.3 upstream and trims log retention.
protection = "standard"
state_dir = "/var/lib/wifiguard"

[server]
# Add the hotspot or LAN address here so other devices can use the resolver.
listen_addresses = ["127.0.0.1"]
port = 53
workers = 32
# Only these networks may query us. Do not add 0.0.0.0/0.
allowed_networks = ["127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
rate_limit = 100.0

[upstream]
# Encrypted resolvers only. Order does not matter: the fastest healthy one wins.
servers = [
    "https://dns.quad9.net/dns-query",
    "https://dns.cloudflare.com/dns-query",
    "tls://dns.quad9.net@9.9.9.9",
]
require_encrypted = true
tls_profile = "strict"

[cache]
# The main lever on how much traffic leaves the network. Raising min_ttl to 600
# roughly halves upstream queries again on a typical household.
min_ttl = 300
max_entries = 100000
serve_stale_for = 86400
prefetch_after = 0.9

[blocklists]
# Refreshes are conditional requests, so an unchanged list costs a few hundred
# bytes rather than a few megabytes.
refresh_hours = 168
block_doh_bypass = true
allow = ["captive.apple.com", "connectivitycheck.gstatic.com"]
block = []

[engine]
block_mode = "zero"       # "zero", "nxdomain" or "refused"
uncloak_cnames = true
rebinding_protection = true

[dashboard]
enabled = true
address = "127.0.0.1"
port = 8080
# password = "set-me-to-require-auth-for-changes"

[logging]
level = "INFO"
log_queries = true
retention_days = 7

# -- Turning this laptop into a portable gateway -----------------------------
# [hotspot]
# enabled = true
# ssid = "WiFiGuard"
# passphrase = "choose-something-long"
# interface = ""            # autodetected
# uplink = ""               # follows the default route as you change networks
# isolate_from_uplink = true
# route_through_vpn = false

# -- The tunnel that carries the filter to your phone ------------------------
# [vpn]
# enabled = true
# endpoint = "home.example.com"   # or a static IP
# subnet = "10.9.0.0/24"
# listen_port = 51820

# -- Per-device rules --------------------------------------------------------
# [groups.kids]
# block_categories = ["adult", "gambling", "social"]
# safe_search = true
# youtube_restrict = "moderate"
#
# [groups.kids.schedules.bedtime]
# start = "21:30"
# end = "07:00"
# block_all = true
#
# [groups.iot]
# default_deny = true
# allow = ["*.tuya.com", "*.hue.philips.com"]
#
# [[devices]]
# id = "10.42.7.31"          # an IP, a CIDR range, a MAC, or a hostname pattern
# group = "kids"
# label = "Tablet"
"""
