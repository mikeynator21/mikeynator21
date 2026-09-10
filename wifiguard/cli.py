"""Command-line interface."""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
import shutil
import socket
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from . import __version__, config as config_module
from .app import Application
from .config import Config, ConfigError
from .vpn import qr
from .vpn.wireguard import PROFILE_HELP, PeerStore, WireGuardError, WireGuardManager

log = logging.getLogger(__name__)


def setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)-22s %(message)s",
        datefmt="%H:%M:%S",
    )
    # These are chatty at DEBUG and rarely what anyone is debugging.
    logging.getLogger("urllib3").setLevel(logging.WARNING)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wifiguard",
        description=(
            "A network-wide ad blocker, encrypted DNS resolver and portable VPN "
            "gateway. Protects every device on the network without installing "
            "anything on them."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Getting started:\n"
            "  sudo wifiguard setup        # answer a few questions, get a config\n"
            "  wifiguard doctor            # check this machine is ready\n"
            "  wifiguard fieldtest         # what is this network doing to my DNS?\n"
            "  sudo wifiguard run          # start filtering\n"
            "  wifiguard selftest          # prove it works, no root needed\n"
        ),
    )
    parser.add_argument("--config", "-c", help="path to wifiguard.toml")
    parser.add_argument("--log-level", default="", help="DEBUG, INFO, WARNING or ERROR")
    parser.add_argument("--version", action="version", version=f"WiFiGuard {__version__}")

    sub = parser.add_subparsers(dest="command", required=True, metavar="<command>")

    run = sub.add_parser("run", help="start the resolver (and gateway, if enabled)")
    run.add_argument("--no-gateway", action="store_true", help="skip the hotspot and firewall")
    run.add_argument("--no-dashboard", action="store_true", help="do not start the web dashboard")
    run.add_argument("--update", action="store_true", help="refresh blocklists before starting")

    check = sub.add_parser("check", help="explain what would happen to a domain")
    check.add_argument("domain")
    check.add_argument("--client", default="0.0.0.0", help="evaluate as this client address")

    sub.add_parser("status", help="show the running service's status")
    sub.add_parser("doctor", help="check this machine can run the gateway")
    sub.add_parser("init-config", help="print a commented example configuration")

    setup = sub.add_parser(
        "setup", help="answer a few questions and get a working configuration"
    )
    setup.add_argument("--out", default="", help="where to write it")
    setup.add_argument("--force", action="store_true", help="replace an existing config")

    passwd = sub.add_parser("passwd", help="hash a dashboard password for the config")
    passwd.add_argument(
        "--stdin", action="store_true", help="read the password from stdin instead of prompting"
    )

    sub.add_parser("harden", help="audit this configuration for weak settings")

    fieldtest = sub.add_parser(
        "fieldtest",
        help="assess the network this machine is on, and what WiFiGuard would change",
    )
    fieldtest.add_argument("--quick", action="store_true", help="skip the slower probes")
    fieldtest.add_argument(
        "--json", action="store_true",
        help="print a structured summary, for sharing the result somewhere",
    )

    selftest = sub.add_parser("selftest", help="run the full stack locally and verify it")
    selftest.add_argument("--port", type=int, default=15353, help="port to test on")
    selftest.add_argument("--keep", action="store_true", help="leave the test server running")

    allow = sub.add_parser("allow", help="always allow a domain")
    allow.add_argument("domain")
    block = sub.add_parser("block", help="always block a domain")
    block.add_argument("domain")

    blocklist = sub.add_parser("blocklist", help="manage the blocklists")
    blocklist_sub = blocklist.add_subparsers(dest="blocklist_command", required=True)
    blocklist_sub.add_parser("update", help="refresh every source now")
    blocklist_sub.add_parser("show", help="list the configured sources and rule counts")

    vpn = sub.add_parser("vpn", help="manage the WireGuard tunnel")
    vpn_sub = vpn.add_subparsers(dest="vpn_command", required=True)

    vpn_init = vpn_sub.add_parser("init", help="create the tunnel's server keys")
    vpn_init.add_argument("--endpoint", required=True, help="hostname or IP that peers dial")
    vpn_init.add_argument("--subnet", default="10.9.0.0/24")
    vpn_init.add_argument("--port", type=int, default=51820)
    vpn_init.add_argument("--interface", default="wg0")
    vpn_init.add_argument("--uplink", default="", help="interface that reaches the internet")
    vpn_init.add_argument(
        "--force", action="store_true",
        help="regenerate the server key, invalidating every existing peer",
    )

    add_peer = vpn_sub.add_parser("add-peer", help="add a device to the tunnel")
    add_peer.add_argument("name")
    add_peer.add_argument(
        "--profile", default="full", choices=sorted(PROFILE_HELP),
        help="; ".join(f"{key}: {value}" for key, value in PROFILE_HELP.items()),
    )
    add_peer.add_argument("--mobile", action="store_true", help="use a phone-friendly MTU")
    add_peer.add_argument("--tether-subnet", default="", help="route this range back to the peer")
    add_peer.add_argument("--no-preshared", action="store_true", help="skip the pre-shared key")
    add_peer.add_argument("--note", default="")
    add_peer.add_argument("--out", default="", help="also write the config to this directory")
    add_peer.add_argument("--no-qr", action="store_true", help="do not print a QR code")

    vpn_sub.add_parser("list", help="list peers and their connection state")
    show = vpn_sub.add_parser("show", help="print a peer's configuration")
    show.add_argument("name")
    show_qr = vpn_sub.add_parser("qr", help="print a peer's config as a QR code")
    show_qr.add_argument("name")
    remove = vpn_sub.add_parser("remove", help="remove a peer")
    remove.add_argument("name")
    vpn_sub.add_parser("config", help="print the server's wg-quick configuration")
    vpn_sub.add_parser("apply", help="write the server config and reload the interface")

    gateway = sub.add_parser("gateway", help="control the portable gateway")
    gateway_sub = gateway.add_subparsers(dest="gateway_command", required=True)
    gateway_sub.add_parser("status", help="show the gateway's state")
    gateway_sub.add_parser("rules", help="print the live firewall rules")
    gateway_sub.add_parser("down", help="remove the firewall rules")

    compat = sub.add_parser(
        "compat", help="check what might stop a device on the network working"
    )
    compat_sub = compat.add_subparsers(dest="compat_command", required=False)
    compat_sub.add_parser("status", help="what is being protected, and for which devices")
    compat_check = compat_sub.add_parser("check", help="explain one domain")
    compat_check.add_argument("domain")
    compat_sub.add_parser("devices", help="list the device profiles")
    compat_scan = compat_sub.add_parser(
        "scan", help="look through recent blocks for anything likely to break a device"
    )
    compat_scan.add_argument("--limit", type=int, default=500)

    cluster = sub.add_parser(
        "cluster", help="run WiFiGuard on several devices that cover for each other"
    )
    cluster_sub = cluster.add_subparsers(dest="cluster_command", required=True)
    cluster_sub.add_parser("status", help="show this node and its peers")
    cluster_sub.add_parser("secret", help="generate a shared secret for the nodes")

    tls = sub.add_parser("tls", help="TLS helpers for the encrypted-DNS channel")
    tls_sub = tls.add_subparsers(dest="tls_command", required=True)
    pin = tls_sub.add_parser("pin", help="print a resolver's current public-key pin")
    pin.add_argument("hostname")
    pin.add_argument("--port", type=int, default=443)

    return parser


# -- commands -----------------------------------------------------------------


def command_run(args: argparse.Namespace, cfg: Config) -> int:
    if cfg.source_path is None:
        # Defaults bind to localhost only, so a first run without a config
        # filters this machine and nothing else -- which is rarely what
        # someone starting the service intended, and gives no clue why.
        print(
            "No configuration file found, so WiFiGuard is running with defaults:\n"
            "  filtering for this machine only, on 127.0.0.1.\n\n"
            "To cover the rest of your network, stop this and run:\n"
            "  sudo wifiguard setup\n",
            file=sys.stderr,
        )

    if args.update:
        cfg.blocklists.update_on_start = True

    application = Application(cfg)
    try:
        application.start(
            with_gateway=not args.no_gateway,
            with_dashboard=not args.no_dashboard,
        )
    except PermissionError:
        print(
            f"Permission denied binding port {cfg.server.port}. Ports below 1024 need "
            f"root: try `sudo wifiguard run`, or set server.port to something above 1024 "
            f"and redirect port 53 to it.",
            file=sys.stderr,
        )
        return 1
    except OSError as exc:
        print(f"Could not start: {exc}", file=sys.stderr)
        if "Address already in use" in str(exc):
            print(
                "\nSomething else is already on port 53. On Ubuntu that is usually "
                "systemd-resolved:\n"
                "  sudo systemctl disable --now systemd-resolved\n"
                "  sudo rm -f /etc/resolv.conf && echo 'nameserver 127.0.0.1' | "
                "sudo tee /etc/resolv.conf",
                file=sys.stderr,
            )
        return 1
    except Exception as exc:  # noqa: BLE001
        print(f"Could not start: {exc}", file=sys.stderr)
        return 1

    application.run_forever()
    return 0


def command_check(args: argparse.Namespace, cfg: Config) -> int:
    application = Application(cfg)
    application.load_blocklists()
    result = application.engine.check(args.domain, args.client)

    verdict = result["action"]
    marker = {"block": "BLOCKED", "allow": "allowed", "rewrite": "rewritten"}.get(verdict, verdict)
    print(f"{result['name']}: {marker}")
    if result.get("reason"):
        print(f"  reason: {result['reason']}")
    if result.get("rule"):
        print(f"  rule:   {result['rule']}")
    if result.get("source"):
        print(f"  source: {result['source']}")
    print(f"  group:  {result['group']}")
    return 0


def command_status(args: argparse.Namespace, cfg: Config) -> int:
    try:
        status = _api(cfg, "/api/status")
    except NotRunning as exc:
        print(f"WiFiGuard does not appear to be running ({exc}).", file=sys.stderr)
        print(
            f"Tried http://{_dashboard_host(cfg)}:{cfg.dashboard.port}/api/status",
            file=sys.stderr,
        )
        return 1
    except (ApiError, Ambiguous) as exc:
        print(f"WiFiGuard is running, but {exc}", file=sys.stderr)
        return 1

    counters = status["counters"]
    print(f"WiFiGuard {status['version']} — {status['protection']} protection")
    print(f"  uptime        {_duration(status['uptime_seconds'])}")
    print(f"  queries       {counters['total']:,}")
    print(f"  blocked       {counters['blocked']:,} ({counters['block_rate'] * 100:.1f}%)")
    print(f"  from cache    {counters['cached']:,} ({counters['cache_rate'] * 100:.1f}%)")
    print(f"  avoided       {counters['upstream_queries_avoided']:,} upstream queries")
    print(f"  rules         {status['blocklists']['rules']:,}")
    print("  upstreams")
    for upstream in status["upstreams"]:
        state = "ok" if upstream["available"] else "UNAVAILABLE"
        lock = "encrypted" if upstream["encrypted"] else "PLAINTEXT"
        print(f"    {upstream['spec']}  {upstream['latency_ms']}ms  {lock}  {state}")

    gateway = status.get("gateway")
    if gateway:
        print("  gateway")
        print(f"    ssid        {gateway['ssid']}")
        print(f"    access pt   {gateway['ap_interface']} ({gateway['subnet']})")
        print(f"    uplink      {gateway['uplink_interface'] or 'not connected'}")
        print(f"    firewall    {'active' if gateway['rules_applied'] else 'NOT APPLIED'}")
        print(f"    clients     {len(gateway.get('clients', []))}")
    return 0


def command_doctor(args: argparse.Namespace, cfg: Config) -> int:
    """Check the machine can actually do what the config asks of it."""
    checks: list[tuple[str, bool, str]] = []

    root = hasattr(os, "geteuid") and os.geteuid() == 0
    checks.append((
        "running as root",
        root,
        "needed to bind port 53 and manage the firewall; re-run with sudo" if not root else "",
    ))

    checks.append((
        f"python {sys.version_info.major}.{sys.version_info.minor}",
        sys.version_info >= (3, 11),
        "WiFiGuard needs Python 3.11 or newer (it uses tomllib)",
    ))

    port_free = _port_available(cfg.server.port)
    holder = _port_holder(cfg.server.port)
    checks.append((
        f"port {cfg.server.port} available",
        port_free,
        f"in use{f' by {holder}' if holder else ''}; on Ubuntu run "
        f"`sudo systemctl disable --now systemd-resolved`" if not port_free else "",
    ))

    for tool, why, required in (
        ("nft", "firewall rules for gateway mode", cfg.hotspot.enabled),
        ("hostapd", "running the access point", cfg.hotspot.enabled),
        ("iw", "checking wireless capabilities", False),
        ("wg", "WireGuard key handling (a pure-Python fallback exists)", False),
        ("wg-quick", "bringing the tunnel up", cfg.vpn.enabled),
    ):
        present = shutil.which(tool) is not None
        checks.append((
            f"{tool} installed",
            present or not required,
            f"needed for {why}; install it with your package manager" if not present else "",
        ))

    from .gateway import interfaces

    uplink, gateway_address = interfaces.default_route_interface()
    checks.append((
        "internet uplink",
        uplink is not None,
        "no default route: connect this machine to a network first" if not uplink else "",
    ))

    if cfg.hotspot.enabled:
        ap = cfg.hotspot.interface or interfaces.pick_access_point_interface(
            exclude={uplink} if uplink else set()
        )
        checks.append((
            "wireless interface for the access point",
            ap is not None,
            "no wireless interface found; a USB WiFi adapter is the usual fix" if not ap else "",
        ))
        if ap:
            supports = interfaces.supports_ap_mode(ap)
            checks.append((
                f"{ap} supports AP mode",
                supports,
                f"`iw list` does not report AP mode for {ap}; most USB adapters do" if not supports else "",
            ))

    reachable, detail = _probe_upstream(cfg)
    checks.append(("encrypted upstream reachable", reachable, detail))

    width = max(len(label) for label, _, _ in checks)
    failures = 0
    for label, ok, hint in checks:
        mark = "ok  " if ok else "FAIL"
        print(f"  [{mark}] {label.ljust(width)}", end="")
        if not ok and hint:
            print(f"   {hint}")
            failures += 1
        else:
            print()

    print()
    if failures:
        print(f"{failures} check(s) failed. WiFiGuard may still start, but fix these first.")
        return 1
    print("Everything checks out.")
    return 0


def command_fieldtest(args: argparse.Namespace, cfg: Config) -> int:
    """Report on the network this machine is actually attached to."""
    from . import fieldtest

    if not args.json:
        print("Assessing this network. Nothing is modified.\n")

    report = fieldtest.run(quick=args.quick)

    if args.json:
        print(json.dumps(report.as_dict(), indent=2))
        return 1 if report.by_severity("problem") else 0

    print(report.render(), end="")

    problems = report.by_severity("problem")
    warnings = report.by_severity("warn")

    if problems:
        print(f"  {len(problems)} problem(s) found on this network:")
        for finding in problems:
            print(f"    - {finding.title}")
        print()
        print("  These are things the network is doing to your traffic, not faults")
        print("  in this machine. Each one above says what WiFiGuard does about it.")
        return 1

    if warnings:
        print(f"  Nothing seriously wrong. {len(warnings)} thing(s) worth knowing:")
        for finding in warnings:
            print(f"    - {finding.title}")
        return 0

    print("  This network looks clean: no interception, no rewriting, and")
    print("  encrypted DNS gets out. WiFiGuard will filter ads and trackers here")
    print("  without having to work around anything.")
    return 0


def command_selftest(args: argparse.Namespace, cfg: Config) -> int:
    """Run the whole stack against a loopback listener and verify the behaviour.

    Needs no root and touches no system configuration, so it is the honest way
    to confirm an install before pointing real devices at it.
    """
    from .selftest import run_selftest

    return run_selftest(cfg, port=args.port, keep=args.keep)


def command_allow(args: argparse.Namespace, cfg: Config) -> int:
    return _local_rule(cfg, args.domain, allow=True)


def command_block(args: argparse.Namespace, cfg: Config) -> int:
    return _local_rule(cfg, args.domain, allow=False)


def _local_rule(cfg: Config, domain: str, *, allow: bool) -> int:
    verb = "Allowed" if allow else "Blocked"
    endpoint = "/api/allow" if allow else "/api/block"

    # Prefer the running service, so the change takes effect at once.
    try:
        _api(cfg, endpoint, {"domain": domain})
        print(f"{verb} {domain} (applied immediately).")
        return 0
    except ApiError as exc:
        # It is running and refused us. Writing the rule to disk anyway would
        # leave the daemon still filtering the name while telling the caller it
        # had been allowed, which is worse than failing.
        print(f"WiFiGuard is running, but {exc}", file=sys.stderr)
        print(f"\n{domain} was NOT changed.", file=sys.stderr)
        return 1
    except Ambiguous as exc:
        # The request went out and the answer did not come back. It may well
        # have been applied, so writing it again locally and announcing "not
        # running" would be a guess dressed up as a fact.
        print(f"Lost contact with WiFiGuard partway through ({exc}).", file=sys.stderr)
        print(
            f"\n{domain} may or may not have been changed. Check with:\n"
            f"  wifiguard check {domain}",
            file=sys.stderr,
        )
        return 2
    except NotRunning:
        pass

    application = Application(cfg)
    application.add_local_rule(domain, allow=allow)
    print(
        f"{verb} {domain}. WiFiGuard is not running, so this takes effect when "
        f"it next starts."
    )
    return 0


def command_blocklist(args: argparse.Namespace, cfg: Config) -> int:
    application = Application(cfg)

    if args.blocklist_command == "update":
        started = time.time()
        application.load_blocklists(refresh=True)
        print(
            f"{application.blocklists.rule_count:,} block rules from "
            f"{len(application.blocklists.sources)} sources "
            f"in {time.time() - started:.1f}s"
        )
    else:
        application.load_blocklists()

    for stats in application.blocklists.sources.values():
        if stats.error:
            print(f"  FAILED  {stats.url}\n            {stats.error}")
        else:
            age = _duration(int(time.time() - stats.updated_at)) if stats.updated_at else "?"
            note = "cached" if stats.from_cache else "downloaded"
            print(f"  {stats.rules:>7,}  {stats.url}  ({note}, {age} old)")

    local = application.local_rules()
    if local["allow"] or local["block"]:
        print(f"  local: {len(local['block'])} blocked, {len(local['allow'])} allowed")
    print(f"  total: {application.blocklists.rule_count:,} block, {len(application.blocklists.allow):,} allow")
    return 0


def command_vpn(args: argparse.Namespace, cfg: Config) -> int:
    cfg.state_dir.mkdir(parents=True, exist_ok=True)
    manager = WireGuardManager(
        PeerStore(cfg.peer_store), local_networks=cfg.resolved_vpn_routes()
    )

    try:
        return _dispatch_vpn(args, cfg, manager)
    except WireGuardError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def _dispatch_vpn(args: argparse.Namespace, cfg: Config, manager: WireGuardManager) -> int:
    command = args.vpn_command

    if command == "init":
        server = manager.initialise_server(
            args.endpoint,
            subnet=args.subnet,
            listen_port=args.port,
            interface=args.interface,
            uplink_interface=args.uplink,
            dns_address="",
            force=args.force,
        )
        print(f"Tunnel ready on {server.endpoint}:{server.listen_port}")
        print(f"  public key   {server.public_key}")
        print(f"  subnet       {server.subnet}")
        print(f"  peer DNS     {server.resolver}")
        print()
        print("Next: add a device with")
        print(f"  wifiguard vpn add-peer phone --mobile")
        return 0

    if command == "add-peer":
        peer = manager.add_peer(
            args.name,
            profile=args.profile,
            preshared=not args.no_preshared,
            mobile=args.mobile,
            tether_subnet=args.tether_subnet,
            note=args.note,
        )
        print(f"Added {peer.name} at {peer.address} ({peer.profile})")
        print(f"  {PROFILE_HELP[peer.profile]}")
        if peer.routed_networks:
            print(f"  routed back: {', '.join(peer.routed_networks)}")
        print()

        if args.out:
            path = manager.write_peer_config(peer.name, Path(args.out))
            print(f"Config written to {path}")
        if not args.no_qr:
            print(qr.render_terminal(manager.peer_config(peer.name)))
            print("Scan this in the WireGuard app (Add tunnel -> Create from QR code).")

        try:
            manager.apply(Path(cfg.vpn.config_path))
        except WireGuardError as exc:
            print(f"\nNote: the live interface was not reloaded ({exc}).")
        return 0

    if command == "list":
        peers = manager.status()
        if not peers:
            print("No peers yet. Add one with `wifiguard vpn add-peer <name>`.")
            return 0
        for peer in peers:
            state = "connected" if peer.get("connected") else (
                "idle" if peer.get("last_handshake") else "never connected"
            )
            print(f"  {peer['name']:<16} {peer['address']:<14} {peer['profile']:<14} {state}")
            if peer.get("bytes_received"):
                print(
                    f"  {'':<16} {_bytes(peer['bytes_received'])} in, "
                    f"{_bytes(peer['bytes_sent'])} out"
                )
        return 0

    if command == "show":
        print(manager.peer_config(args.name), end="")
        return 0

    if command == "qr":
        print(qr.render_terminal(manager.peer_config(args.name)))
        return 0

    if command == "remove":
        manager.remove_peer(args.name)
        print(f"Removed {args.name}.")
        try:
            manager.apply(Path(cfg.vpn.config_path))
        except WireGuardError:
            pass
        return 0

    if command == "config":
        print(manager.server_config(), end="")
        return 0

    if command == "apply":
        manager.apply(Path(cfg.vpn.config_path))
        print(f"Wrote {cfg.vpn.config_path} and reloaded the interface.")
        return 0

    return 1


def command_gateway(args: argparse.Namespace, cfg: Config) -> int:
    from .gateway import firewall, interfaces

    if args.gateway_command == "down":
        firewall.teardown()
        print("Gateway firewall rules removed.")
        return 0

    if args.gateway_command == "rules":
        print(firewall.describe())
        return 0

    uplink, gateway_address = interfaces.default_route_interface()
    print(f"  uplink          {uplink or 'not connected'}")
    if gateway_address:
        print(f"  via             {gateway_address}")
    print(f"  ip forwarding   {'on' if firewall.forwarding_enabled() else 'off'}")
    print(f"  rules loaded    {'yes' if firewall.rules_installed() else 'no'}")
    print(f"  fingerprint     {interfaces.uplink_fingerprint()}")

    if cfg.networks.share_discovery:
        from .gateway.reflector import groups_from_names

        protocols = ", ".join(
            group.name for group in groups_from_names(cfg.networks.discovery_protocols)
        )
        print(f"  discovery       sharing {protocols} between local networks")
    else:
        print("  discovery       not shared (devices on different networks "
              "cannot find each other)")
    print()
    print("  interfaces")
    for interface in interfaces.list_interfaces():
        if interface.loopback:
            continue
        kind = "wireless" if interface.wireless else "wired"
        addresses = ", ".join(interface.addresses) or "no address"
        print(f"    {interface.name:<12} {kind:<9} {'up' if interface.up else 'down':<5} {addresses}")
    return 0


def command_compat(args: argparse.Namespace, cfg: Config) -> int:
    from .compat import DEVICE_PROFILES, ESSENTIAL_SERVICES

    guard = cfg.compatibility_guard()
    command = getattr(args, "compat_command", None) or "status"

    if command == "devices":
        print("Device profiles. Add the ones on your network to wifiguard.toml:\n")
        print('  [compatibility]')
        print('  devices = ["apple", "smart-tv", "console"]      # or ["all"]\n')
        for profile in DEVICE_PROFILES:
            active = "on " if (profile.key in guard.profiles or "all" in guard.profiles) else "   "
            print(f"  [{active}] {profile.key:<16} {profile.title}")
            print(f"         {profile.note}")
            print(f"         {len(profile.domains)} domains\n")
        return 0

    if command == "check":
        name = args.domain.strip().lower().strip(".")
        service = guard.explain(name)
        if service is not None:
            print(f"{name}: PROTECTED -- {service.title}")
            print()
            for line in _wrap(service.why, 74):
                print(f"  {line}")
            print()
            print("  It is allowed ahead of every blocklist, category and group rule.")
            print(f"  To stop protecting it: compatibility.unprotect = [\"{service.key}\"]")
            return 0

        hit = guard.match(name)
        if hit:
            print(f"{name}: allowed for compatibility ({hit.source})")
            print(f"  matched {hit.rule}")
            return 0

        print(f"{name}: not treated as essential.")
        print("  It is filtered by the normal rules -- `wifiguard check` says how.")
        return 0

    if command == "scan":
        return _compat_scan(cfg, guard, args.limit)

    # status
    summary = guard.summary()
    if not summary["enabled"]:
        print("Compatibility protection is OFF.")
        print("Blocklists can take away a device's clock or certificate checks,")
        print("which breaks it in ways that are very hard to diagnose.")
        return 0

    print(f"Protecting {summary['rules']} domains that devices break without.\n")
    print("  Essential services")
    for service in ESSENTIAL_SERVICES:
        state = "on " if service.key not in cfg.compatibility.unprotect else "OFF"
        print(f"    [{state}] {service.key:<20} {len(service.domains):>3} domains  {service.title}")

    active = [p for p in DEVICE_PROFILES if p.key in guard.profiles or "all" in guard.profiles]
    print(f"\n  Device profiles ({len(active)} of {len(DEVICE_PROFILES)} active)")
    if not active:
        print("    none -- run `wifiguard compat devices` to see what is available")
    for profile in active:
        print(f"    [on ] {profile.key:<20} {len(profile.domains):>3} domains  {profile.title}")

    print(f"\n  DNSSEC pass-through: {'on' if cfg.compatibility.dnssec_passthrough else 'OFF'}")
    if not cfg.compatibility.dnssec_passthrough:
        print("    A device that validates DNSSEC itself cannot resolve anything.")
    return 0


def _compat_scan(cfg: Config, guard, limit: int) -> int:
    """Look through recent blocks for things that look like they break a device."""
    try:
        queries = _api(cfg, f"/api/queries?limit={limit}&action=block").get("queries", [])
    except NotRunning as exc:
        print(f"WiFiGuard does not appear to be running ({exc}).", file=sys.stderr)
        print("The scan reads the live query log, so start it first.", file=sys.stderr)
        return 1
    except (ApiError, Ambiguous) as exc:
        print(f"WiFiGuard is running, but {exc}", file=sys.stderr)
        return 1

    # Words that show up in the names of services devices depend on. This is a
    # hint for a human to look at, not a rule -- which is why it prints
    # suspicions rather than allowing anything by itself.
    signals = {
        "time": ("ntp", "time.", "clock", "sntp"),
        "certificates": ("ocsp", "crl.", "pki.", "cert"),
        "connectivity": ("connectivity", "captive", "detectportal", "ncsi", "connecttest"),
        "updates": ("update", "firmware", "swcdn", "swscan"),
        "push": ("push", "mtalk", "notify", "courier"),
    }

    from collections import Counter

    suspects: dict[str, Counter] = {key: Counter() for key in signals}
    by_client: dict[str, Counter] = {}

    for entry in queries:
        name = str(entry.get("name", ""))
        if not name:
            continue
        for key, words in signals.items():
            if any(word in name for word in words):
                suspects[key][name] += 1
                by_client.setdefault(str(entry.get("client", "")), Counter())[name] += 1

    flagged = {key: counter for key, counter in suspects.items() if counter}
    if not flagged:
        print(f"Looked at {len(queries)} recent blocks. Nothing looks likely to break a device.")
        return 0

    print(f"Looked at {len(queries)} recent blocks. These may be breaking something:\n")
    for key, counter in flagged.items():
        print(f"  {key}")
        for name, count in counter.most_common(8):
            protected = " (already protected)" if guard.match(name) else ""
            print(f"    {name:<44} blocked {count}x{protected}")
        print()

    print("If a device on this network misbehaves, allow the matching name:")
    example = next(iter(next(iter(flagged.values())).most_common(1)))[0]
    print(f"  wifiguard allow {example}")
    print("\nOr add the device's profile, which covers the whole class at once:")
    print("  wifiguard compat devices")
    return 0


def _wrap(text: str, width: int) -> list[str]:
    import textwrap

    return textwrap.wrap(" ".join(text.split()), width)


def command_cluster(args: argparse.Namespace, cfg: Config) -> int:
    if args.cluster_command == "secret":
        import secrets

        value = secrets.token_hex(32)
        print(value)
        print()
        print("Put the same value in every node's config:")
        print("  [cluster]")
        print("  enabled = true")
        print(f'  secret = "{value}"')
        return 0

    # Prefer the running service, which knows about live peers.
    try:
        status = _api(cfg, "/api/status").get("cluster")
    except (NotRunning, ApiError, Ambiguous):
        status = None

    if status is None:
        if not cfg.cluster.enabled:
            print("Clustering is off. Enable it with:")
            print("  [cluster]")
            print("  enabled = true")
            print('  address = "10.9.0.1"     # this node, as peers reach it')
            print('  peers   = ["10.9.0.2"]   # the other nodes')
            print("  priority = 50            # higher wins; give the always-on device more")
            print("\nGenerate the shared secret with `wifiguard cluster secret`.")
            return 0
        print("WiFiGuard is not running, so live peer state is unavailable.", file=sys.stderr)
        print(f"Configured: {cfg.cluster.name or 'this host'} "
              f"priority {cfg.cluster.priority}, peers {', '.join(cfg.cluster.peers) or 'none'}")
        return 1

    print(f"This node: {status['name']} ({status['address'] or 'no address set'})")
    print(f"  priority     {status['priority']} (effective {status['effective_priority']})")
    print(f"  state        {status['state']}"
          + (f" -- {status['yield_reason']}" if status['yield_reason'] else ""))
    print(f"  answering    {'yes, clients ask this node first' if status['preferred'] else 'standby'}")
    print(f"  cache shared {status['cache_shared_out']} out, {status['cache_shared_in']} in")
    if status["rejected_messages"]:
        print(f"  rejected     {status['rejected_messages']} unauthenticated messages")

    print("\n  peers")
    if not status["peers"]:
        print("    none seen yet")
    for peer in status["peers"]:
        state = "up" if peer["alive"] else "DOWN"
        print(f"    {peer['name']:<16} {peer['address']:<16} priority {peer['effective_priority']:<4} "
              f"{peer['state']:<9} {state}  ({peer['seconds_since_seen']}s ago)")

    print("\n  clients are handed these resolvers, in order:")
    for index, address in enumerate(status["resolver_order"], 1):
        print(f"    {index}. {address}")
    return 0


def command_tls(args: argparse.Namespace, cfg: Config) -> int:
    from .tlsutil import fetch_pin

    try:
        pin = fetch_pin(args.hostname, args.port)
    except Exception as exc:  # noqa: BLE001
        print(f"Could not fetch a pin for {args.hostname}: {exc}", file=sys.stderr)
        return 1

    print(f"{args.hostname} public-key pin:\n  {pin}\n")
    print("Add it to wifiguard.toml as:")
    print("  [upstream.pins]")
    print(f'  "{args.hostname}" = ["{pin}"]')
    print()
    print(
        "Pinning rejects any certificate for this host that does not carry this\n"
        "public key. Capture the pin on a network you trust, and remember that a\n"
        "resolver rotating its key will break resolution until you update it."
    )
    return 0


def command_setup(args: argparse.Namespace, cfg: Config) -> int:
    from . import setupwizard

    target = Path(args.out) if args.out else setupwizard.DEFAULT_CONFIG_PATH
    return setupwizard.run(target, force=args.force)


def command_passwd(args: argparse.Namespace, cfg: Config) -> int:
    """Turn a password into something safe to keep in a config file."""
    from .auth import hash_password

    if args.stdin:
        password = sys.stdin.readline().rstrip("\n")
    else:
        import getpass

        password = getpass.getpass("  password: ")
        if password and getpass.getpass("  again: ") != password:
            print("Those did not match.", file=sys.stderr)
            return 1

    if not password:
        print("No password given.", file=sys.stderr)
        return 1
    if len(password) < 8:
        print("Use at least 8 characters.", file=sys.stderr)
        return 1

    print()
    print("Put this in wifiguard.toml:")
    print()
    print("  [dashboard]")
    print(f'  password = "{hash_password(password)}"')
    print()
    print("The password itself is not recoverable from that, so the config file")
    print("no longer carries a usable secret.")
    return 0


def command_harden(args: argparse.Namespace, cfg: Config) -> int:
    """Report settings that weaken this install, and how to fix each."""
    from .auth import is_hashed, looks_local

    findings: list[tuple[str, str, str]] = []

    def note(severity: str, what: str, fix: str) -> None:
        findings.append((severity, what, fix))

    # -- exposure ---------------------------------------------------------
    if cfg.dashboard.enabled and not looks_local(cfg.dashboard.address):
        if not cfg.dashboard.password:
            note("high", "The dashboard is on the network with no password.",
                 "Set one: wifiguard passwd")
        elif not is_hashed(cfg.dashboard.password):
            note("medium", "The dashboard password is stored in the clear.",
                 "Replace it with a hash: wifiguard passwd")
    if cfg.dashboard.enabled and cfg.dashboard.allow_insecure:
        note("high", "dashboard.allow_insecure is on, which waives the password check.",
             "Remove it and set a password instead.")

    # -- the resolver -----------------------------------------------------
    if "0.0.0.0/0" in cfg.server.allowed_networks or "::/0" in cfg.server.allowed_networks:
        note("high", "server.allowed_networks accepts the whole internet.",
             "This makes an open resolver, which will be found and abused. "
             "List only your own private ranges.")
    if cfg.server.rate_limit <= 0:
        note("medium", "Per-client rate limiting is off.",
             "Set server.rate_limit to something like 100.")

    # -- upstream ---------------------------------------------------------
    if not cfg.upstream.require_encrypted:
        note("high", "Plaintext DNS upstreams are permitted.",
             "Set upstream.require_encrypted = true and use https:// or tls:// servers.")
    plaintext = [s for s in cfg.upstream.servers if not s.startswith(("https://", "tls://"))]
    if plaintext:
        note("high", f"These upstreams are unencrypted: {', '.join(plaintext)}",
             "Everyone on the path to them sees every lookup this network makes.")
    if not cfg.upstream.pins:
        note("low", "No resolver public keys are pinned.",
             "Certificate verification alone cannot see through an interception "
             "whose CA your machine trusts. Capture pins on a network you trust: "
             "wifiguard tls pin dns.quad9.net")
    if cfg.upstream.tls_profile == "compatible":
        note("low", "TLS profile is 'compatible', which allows TLS 1.2.",
             "Use 'strict', or 'paranoid' to require TLS 1.3.")

    # -- filtering integrity ----------------------------------------------
    if cfg.blocklists.trust_remote_allow_rules:
        note("medium", "Downloaded lists are trusted to write exception rules.",
             "A hijacked list source could un-block anything. Turn "
             "blocklists.trust_remote_allow_rules off.")
    if cfg.blocklists.collapse_threshold <= 0:
        note("low", "A blocklist that collapses to nothing will be accepted.",
             "Set blocklists.collapse_threshold to 0.5.")
    if not cfg.blocklists.block_doh_bypass:
        note("medium", "Public DoH bootstrap names are not blocked.",
             "Browsers will resolve around the filter. Set "
             "blocklists.block_doh_bypass = true.")

    # -- the filter itself -------------------------------------------------
    if not cfg.engine.rebinding_protection:
        note("medium", "DNS rebinding protection is off.",
             "Set engine.rebinding_protection = true.")
    if not cfg.engine.refuse_any:
        note("low", "ANY queries are answered.",
             "That is a DNS amplification vector. Set engine.refuse_any = true.")
    if not cfg.compatibility.protect_essentials:
        note("medium", "Essential services are not protected.",
             "A blocklist can take away a device's clock or certificate checks, "
             "which breaks it with no clue why.")

    # -- gateway -----------------------------------------------------------
    if cfg.hotspot.enabled:
        if not cfg.hotspot.isolate_from_uplink:
            note("medium", "Clients are not isolated from the network you join.",
                 "On a hotel or cafe LAN that is a segment full of strangers' "
                 "machines. Set hotspot.isolate_from_uplink = true.")
        if cfg.hotspot.allow_ipv6:
            note("medium", "Client IPv6 is forwarded unfiltered.",
                 "That is a path around IPv4 filtering. Leave hotspot.allow_ipv6 off "
                 "unless you have a filtered v6 path.")
        if len(cfg.hotspot.passphrase) < 12:
            note("low", "The hotspot passphrase is short.",
                 "WPA3 makes offline cracking hard, but WPA2 clients fall back. "
                 "Twelve characters or more.")

    # -- privacy -----------------------------------------------------------
    if cfg.logging.log_queries and cfg.logging.retention_days > 30:
        note("low", f"Query logs are kept for {cfg.logging.retention_days} days.",
             "That is a detailed record of what your household reads. Shorten it, "
             "or set logging.log_queries = false.")

    # -- report -------------------------------------------------------------
    if not findings:
        print("Nothing to flag. This configuration is about as tight as it goes")
        print("without making it harder to live with.")
        print()
        print("Worth remembering anyway: DNS filtering cannot block ads served from")
        print("the same domain as the content, and a device that ships its own")
        print("resolver to an address not on the block list will get around it.")
        return 0

    order = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda item: order[item[0]])
    labels = {"high": "HIGH  ", "medium": "medium", "low": "low   "}

    print(f"{len(findings)} thing(s) worth changing:\n")
    for severity, what, fix in findings:
        print(f"  [{labels[severity]}] {what}")
        for line in _wrap(fix, 68):
            print(f"            {line}")
        print()

    high = sum(1 for severity, _, _ in findings if severity == "high")
    return 1 if high else 0


def command_init_config(args: argparse.Namespace, cfg: Config) -> int:
    print(config_module.EXAMPLE_CONFIG, end="")
    return 0


# -- helpers ------------------------------------------------------------------


class NotRunning(Exception):
    """The daemon is not listening."""


class ApiError(Exception):
    """It is listening, but the call was refused."""


class Ambiguous(Exception):
    """The call may or may not have been applied.

    A timeout or a dropped connection after the request was sent leaves no way
    to know whether the daemon acted on it, and guessing either way is worse
    than saying so.
    """


import errno as _errno

#: Errors that mean nothing is listening, as opposed to something going wrong
#: partway through a request.
_NOT_LISTENING = frozenset({
    _errno.ECONNREFUSED, _errno.ENOENT, _errno.EHOSTUNREACH, _errno.ENETUNREACH,
})


def _api(cfg: Config, path: str, payload: dict | None = None, timeout: float = 5.0):
    """Call the running daemon's API, authenticating as the local admin.

    Distinguishes "not running" from "running but refused", because reporting
    the second as the first sends people looking in the wrong place -- and, in
    the case of `allow`, quietly did the wrong thing instead.
    """
    from .auth import AdminToken

    url = f"http://{_dashboard_host(cfg)}:{cfg.dashboard.port}{path}"
    data = json.dumps(payload).encode() if payload is not None else None
    headers = {"Content-Type": "application/json"} if data is not None else {}

    token = AdminToken(cfg.state_dir).read()
    if token:
        headers["Authorization"] = f"Bearer {token}"

    request = urllib.request.Request(url, data=data, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read()
            return json.loads(body) if body else {}
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = json.loads(exc.read()).get("error", "")
        except Exception:  # noqa: BLE001 - the body is a courtesy, not a contract
            pass

        if exc.code in (401, 429):
            hint = (
                f"the daemon refused these credentials ({detail or exc.reason})."
                if token
                else "a dashboard password is set and this command could not find "
                     f"the local admin token in {cfg.state_dir}."
            )
            raise ApiError(
                f"{hint}\n"
                f"  The token is written when the service starts, and is readable "
                f"only by the user it runs as -- so run this as that user, "
                f"usually with sudo."
            ) from exc

        # 403 is not about credentials: read-only mode returns it before they
        # are even looked at. Reporting it as an auth problem sends people
        # hunting for a token that is not the issue.
        raise ApiError(detail or f"HTTP {exc.code}: {exc.reason}") from exc

    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", exc)
        # Only a refused or unreachable endpoint means "not running". A read
        # timeout is ambiguous -- the request may already have been applied --
        # and must not be reported as though nothing happened.
        if isinstance(reason, (ConnectionRefusedError, FileNotFoundError)) or (
            isinstance(reason, OSError) and reason.errno in _NOT_LISTENING
        ):
            raise NotRunning(str(reason)) from exc
        raise Ambiguous(str(reason)) from exc
    except (TimeoutError, socket.timeout) as exc:
        raise Ambiguous(f"timed out after {timeout:.0f}s") from exc
    except (OSError, ValueError) as exc:
        raise Ambiguous(str(exc)) from exc


def _dashboard_host(cfg: Config) -> str:
    address = cfg.dashboard.address
    return "127.0.0.1" if address in ("0.0.0.0", "::", "") else address


def _port_available(port: int) -> bool:
    for family, address in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET, "0.0.0.0")):
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind((address, port))
            except OSError:
                return False
    return True


def _port_holder(port: int) -> str:
    """Best-effort name of whatever already holds the port."""
    if shutil.which("ss") is None:
        return ""
    import subprocess

    try:
        result = subprocess.run(
            ["ss", "-lunp", f"sport = :{port}"],
            capture_output=True, text=True, timeout=5, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    for line in result.stdout.splitlines()[1:]:
        if "users:" in line:
            return line.split("users:", 1)[1].strip().strip('()"')
    return ""


def _probe_upstream(cfg: Config) -> tuple[bool, str]:
    """Try to resolve one name through the configured upstreams."""
    from . import dnsmsg
    from .resolver import ResolutionError, UpstreamPool

    try:
        pool = UpstreamPool(
            cfg.upstream.servers,
            timeout=min(cfg.upstream.timeout, 6.0),
            require_encrypted=cfg.upstream.require_encrypted,
            tls_policy=cfg.tls_policy(),
        )
    except ValueError as exc:
        return False, str(exc)

    try:
        started = time.monotonic()
        pool.resolve("example.com", dnsmsg.TYPE_A)
        elapsed = (time.monotonic() - started) * 1000
        return True, f"{elapsed:.0f}ms"
    except ResolutionError as exc:
        return False, f"no configured resolver answered: {exc}"
    except Exception as exc:  # noqa: BLE001 - doctor reports problems, never raises
        return False, f"{type(exc).__name__}: {exc}"
    finally:
        pool.close()


def _duration(seconds: int) -> str:
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m"
    if seconds < 86_400:
        return f"{seconds // 3600}h {(seconds % 3600) // 60}m"
    return f"{seconds // 86_400}d {(seconds % 86_400) // 3600}h"


def _bytes(count: int) -> str:
    value = float(count)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024:
            return f"{value:.1f}{unit}"
        value /= 1024
    return f"{value:.1f}TB"


COMMANDS = {
    "run": command_run,
    "check": command_check,
    "status": command_status,
    "doctor": command_doctor,
    "selftest": command_selftest,
    "fieldtest": command_fieldtest,
    "allow": command_allow,
    "block": command_block,
    "blocklist": command_blocklist,
    "vpn": command_vpn,
    "gateway": command_gateway,
    "cluster": command_cluster,
    "compat": command_compat,
    "tls": command_tls,
    "init-config": command_init_config,
    "setup": command_setup,
    "passwd": command_passwd,
    "harden": command_harden,
}


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        cfg = config_module.load(args.config)
    except ConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2

    setup_logging(args.log_level or cfg.logging.level)

    handler = COMMANDS.get(args.command)
    if handler is None:  # pragma: no cover - argparse rejects this first
        parser.error(f"unknown command {args.command!r}")
        return 2

    try:
        return handler(args, cfg)
    except KeyboardInterrupt:
        print()
        return 130
    except ConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
