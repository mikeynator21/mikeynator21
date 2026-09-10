"""Assembles the components into a running service.

One place where the wiring lives, so the CLI, the dashboard and the tests all
build the same thing.
"""

from __future__ import annotations

import json
import logging
import signal
import threading
import time

from . import blocklist as blocklist_module
from .blocklist import BlocklistManager
from .cache import DNSCache
from .cluster import Cluster
from .config import Config
from .engine import FilterEngine
from .policy import Device, PolicyEngine
from .resolver import UpstreamPool
from .server import DNSServer
from .stats import QueryLog
from .vpn.wireguard import PeerStore, WireGuardManager

log = logging.getLogger(__name__)


class Application:
    """The running service: resolver, listeners, gateway, dashboard."""

    def __init__(self, config: Config) -> None:
        self.config = config
        config.state_dir.mkdir(parents=True, exist_ok=True)

        # Expand "auto" and fold in every other network on this router, so a
        # device on the guest SSID or the wired LAN is filtered exactly like one
        # on the main WiFi.
        config.server.listen_addresses = config.resolved_listen_addresses()
        config.server.allowed_networks = config.resolved_allowed_networks()

        self.blocklists = BlocklistManager(
            config.blocklist_cache_dir,
            hosts_match_subdomains=config.blocklists.hosts_match_subdomains,
        )
        # A subnet-to-group mapping is just a device rule whose identifier is a
        # CIDR range, so it goes through the same matcher.
        devices = list(config.devices) + [
            Device(identifier=network, group=group, label=f"network {network}")
            for network, group in config.networks.group_by_network.items()
        ]
        self.policy = PolicyEngine(groups=config.groups, devices=devices)
        self.upstreams = UpstreamPool(
            config.upstream.servers,
            timeout=config.upstream.timeout,
            require_encrypted=config.upstream.require_encrypted,
            use_0x20=config.upstream.use_0x20,
            tls_policy=config.tls_policy(),
        )

        config.cache.persist_path = config.cache_file
        self.cache = DNSCache(config.cache)

        self.query_log = QueryLog(
            config.query_database,
            retention_days=config.logging.retention_days,
            log_queries=config.logging.log_queries,
        )

        self.engine = FilterEngine(
            self.blocklists,
            self.policy,
            self.upstreams,
            self.cache,
            self.query_log,
            config.engine,
        )
        self.dns = DNSServer(self.engine, config.server)

        self.cluster = Cluster(config.cluster, self.cache, counters=self.query_log.counters)
        if config.cluster.enabled:
            self.engine.cluster = self.cluster
            # Peers are told about every node, so a phone keeps resolving when
            # the laptop closes.
            self.vpn.resolvers = self.cluster.resolver_order()

        self.vpn = WireGuardManager(
            PeerStore(config.peer_store), local_networks=config.resolved_vpn_routes()
        )
        self.gateway = None
        self.dashboard = None

        self._stop = threading.Event()
        self._maintenance: threading.Thread | None = None
        self.started_at = 0.0

    # -- lifecycle --------------------------------------------------------

    def load_blocklists(self, *, refresh: bool = False) -> None:
        """Compile the rule sets. Safe to call while the server is running."""
        local = self._read_local_rules()
        self.blocklists.load(
            self.config.effective_blocklists(),
            extra_block=self.config.effective_block_rules() + local["block"],
            extra_allow=self.config.blocklists.allow + local["allow"],
            extra_regex=self.config.blocklists.regex,
            refresh=refresh,
            max_age=self.config.blocklists.refresh_hours * 3600,
        )
        # A rule change invalidates cached answers for that name, so a domain
        # unblocked from the dashboard starts working immediately.
        for domain in local["allow"] + local["block"]:
            self.cache.invalidate(domain)

    def _read_local_rules(self) -> dict[str, list[str]]:
        path = self.config.local_rules_file
        if not path.exists():
            return {"allow": [], "block": []}
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            log.warning("could not read %s: %s", path, exc)
            return {"allow": [], "block": []}
        return {
            "allow": list(payload.get("allow", [])),
            "block": list(payload.get("block", [])),
        }

    def add_local_rule(self, domain: str, *, allow: bool) -> None:
        """Add an allow or block rule that survives a restart.

        Adding to one list removes from the other, so toggling a domain in the
        dashboard does what it looks like it does.
        """
        domain = domain.strip().lower().strip(".")
        if not domain:
            raise ValueError("a domain is required")

        rules = self._read_local_rules()
        target, other = ("allow", "block") if allow else ("block", "allow")
        rules[other] = [entry for entry in rules[other] if entry != domain]
        if domain not in rules[target]:
            rules[target].append(domain)

        path = self.config.local_rules_file
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(rules, indent=2), encoding="utf-8")
        tmp.replace(path)

        # Apply to the live rule sets rather than reloading every source.
        if allow:
            self.blocklists.allow.add_suffix(domain, "local")
        else:
            self.blocklists.block.add_suffix(domain, "local")
            self.blocklists.allow.exact.pop(domain, None)
            self.blocklists.allow.suffix.pop(domain, None)
        self.cache.invalidate(domain)
        log.info("%s %s (local rule)", "allowed" if allow else "blocked", domain)

    def local_rules(self) -> dict[str, list[str]]:
        return self._read_local_rules()

    def start(self, *, with_gateway: bool = True, with_dashboard: bool = True) -> None:
        self.started_at = time.time()
        self.load_blocklists(refresh=self.config.blocklists.update_on_start)

        restored = self.cache.load()
        if restored:
            log.info("resumed with %d cached answers, so nothing is re-queried", restored)

        self.query_log.start()
        self.dns.start()
        self.cluster.start()

        if with_gateway and self.config.hotspot.enabled:
            from .gateway.manager import GatewayManager

            self.gateway = GatewayManager(
                self.config,
                on_leases_changed=self._leases_changed,
                resolvers=self.client_resolvers,
            )
            self.gateway.start()

        if with_dashboard and self.config.dashboard.enabled:
            from .api import Dashboard

            self.dashboard = Dashboard(self)
            self.dashboard.start()

        self._stop.clear()
        self._maintenance = threading.Thread(
            target=self._maintain, name="maintenance", daemon=True
        )
        self._maintenance.start()

        log.info(
            "WiFiGuard is up: %d block rules, %d upstreams, listening on %s",
            self.blocklists.rule_count,
            len(self.upstreams.upstreams),
            ", ".join(self.config.server.listen_addresses),
        )

    def stop(self) -> None:
        log.info("shutting down")
        self._stop.set()
        if self._maintenance is not None:
            self._maintenance.join(timeout=5)
            self._maintenance = None
        if self.dashboard is not None:
            self.dashboard.stop()
            self.dashboard = None
        if self.gateway is not None:
            self.gateway.stop()
            self.gateway = None
        self.cluster.stop()
        self.dns.stop()
        # Saving the cache is what makes a restart cost nothing upstream.
        self.cache.save()
        self.query_log.stop()
        self.upstreams.close()
        log.info("stopped cleanly")

    def run_forever(self) -> None:
        """Run until interrupted, handling SIGTERM and SIGINT."""
        shutdown = threading.Event()

        def handle(signum, _frame):
            log.info("received %s", signal.Signals(signum).name)
            shutdown.set()

        for signame in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(signame, handle)
            except ValueError:
                # Signals can only be installed on the main thread.
                pass

        try:
            while not shutdown.is_set():
                shutdown.wait(1.0)
        finally:
            self.stop()

    # -- background work --------------------------------------------------

    def _maintain(self) -> None:
        """Refresh blocklists, prune the log and persist the cache periodically."""
        last_refresh = time.time()
        last_prune = time.time()
        last_save = time.time()
        refresh_interval = max(3600, self.config.blocklists.refresh_hours * 3600)

        while not self._stop.wait(60):
            now = time.time()

            if now - last_refresh >= refresh_interval:
                last_refresh = now
                try:
                    log.info("refreshing blocklists")
                    self.load_blocklists(refresh=True)
                except Exception:  # noqa: BLE001 - keep serving on a failed refresh
                    log.exception("blocklist refresh failed; the previous rules stay in effect")

            if now - last_prune >= 3600:
                last_prune = now
                removed = self.query_log.prune()
                if removed:
                    log.info("pruned %d expired query-log entries", removed)

            # A periodic save means an unclean shutdown still resumes with a
            # mostly-warm cache.
            if now - last_save >= 900:
                last_save = now
                self.cache.save()

    def _leases_changed(self, leases) -> None:
        """Publish DHCP-learned names to the policy engine and local zone."""
        mapping = {}
        for lease in leases:
            self.policy.note_client(lease.ip, lease.mac, lease.hostname)
            if lease.hostname:
                mapping[lease.hostname.lower()] = lease.ip
        self.engine.set_local_names(mapping)

    # -- introspection ----------------------------------------------------

    def status(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "version": __import__("wifiguard").__version__,
            "protection": self.config.protection,
            "uptime_seconds": int(time.time() - self.started_at) if self.started_at else 0,
            "counters": self.query_log.counters.as_dict(),
            "cache": {**self.cache.stats.as_dict(), "entries": len(self.cache)},
            "upstreams": self.upstreams.status(),
            "dns": self.dns.stats(),
            "blocklists": {
                "rules": self.blocklists.rule_count,
                "allow_rules": len(self.blocklists.allow),
                "last_update": self.blocklists.last_update,
                "sources": [
                    {
                        "url": stats.url,
                        "rules": stats.rules,
                        "updated_at": stats.updated_at,
                        "cached": stats.from_cache,
                        "error": stats.error,
                    }
                    for stats in self.blocklists.sources.values()
                ],
            },
            "groups": sorted(self.config.groups),
            "networks": self.network_summary(),
        }
        if self.config.cluster.enabled:
            payload["cluster"] = self.cluster.status()
        if self.gateway is not None:
            payload["gateway"] = self.gateway.status()
        if self.vpn.store.server is not None:
            payload["vpn"] = {
                "endpoint": self.vpn.store.server.endpoint,
                "interface": self.vpn.store.server.interface,
                "subnet": str(self.vpn.store.server.subnet),
                "peers": self.vpn.status(),
            }
        return payload

    def client_resolvers(self, local_address: str) -> list[str]:
        """The DNS servers to hand clients, best node first.

        With clustering off this is just us. With it on, every node is listed
        so a client fails over on its own when one goes away -- which is what
        keeps the network filtered while the laptop is asleep.
        """
        if not self.config.cluster.enabled:
            return [local_address]
        return self.cluster.resolver_order(fallback=[local_address])

    def network_summary(self) -> dict[str, object]:
        """Which local networks are being served, and on what addresses."""
        from .gateway.networks import discover_local_networks

        return {
            "listening_on": list(self.config.server.listen_addresses),
            "serving": [local.as_dict() for local in discover_local_networks(include_ipv6=True)],
            "allowed": list(self.config.server.allowed_networks),
            "group_by_network": dict(self.config.networks.group_by_network),
        }

    def savings(self) -> dict[str, object]:
        """An estimate of what the filter and the cache saved.

        Deliberately conservative and clearly labelled as an estimate: the
        numbers exist to show the cache and blocklists are working, not to be
        precise. The per-request figure is a rough average for an ad or tracker
        fetch that never happened.
        """
        counters = self.query_log.counters
        cache_stats = self.cache.stats
        avoided = counters.blocked + counters.cached
        # A blocked ad request typically saves a few tens of kilobytes once the
        # creative, the beacon and the redirect chain are counted.
        estimated_bytes = counters.blocked * 45_000
        return {
            "queries_total": counters.total,
            "queries_blocked": counters.blocked,
            "queries_from_cache": counters.cached,
            "upstream_queries_avoided": avoided,
            "upstream_query_rate": round(
                1 - (avoided / counters.total) if counters.total else 1.0, 4
            ),
            "cache_hit_rate": round(cache_stats.hit_rate, 4),
            "prefetches": cache_stats.prefetches,
            "estimated_bytes_saved": estimated_bytes,
            "estimated_mb_saved": round(estimated_bytes / 1_048_576, 1),
            "note": "Traffic figures are an estimate based on typical ad payload sizes.",
        }


def build(config: Config) -> Application:
    return Application(config)


def default_blocklist_sources(config: Config) -> list[str]:
    """The sources that would be used, for `wifiguard status` and the docs."""
    sources = config.effective_blocklists()
    if config.blocklists.block_doh_bypass:
        sources = sources + [f"(built-in) {len(blocklist_module.DOH_BOOTSTRAP_DOMAINS)} DoH bypass domains"]
    return sources
