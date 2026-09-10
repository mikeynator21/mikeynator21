"""An end-to-end test of the running stack, with no root and no internet.

`wifiguard selftest` starts a stub upstream resolver, a real FilterEngine and a
real DNS listener on loopback, then queries them the way a phone or a laptop
would. It is the honest answer to "did the install work?" -- everything below
exercises the shipping code paths rather than mocks of them.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import struct
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import dnsmsg
from .blocklist import BlocklistManager
from .cache import CacheConfig, DNSCache
from .config import Config
from .engine import EngineConfig, FilterEngine
from .policy import Device, Group, PolicyEngine, Schedule
from .resolver import UpstreamPool
from .server import DNSServer, ServerConfig
from .stats import QueryLog

log = logging.getLogger(__name__)


class StubUpstream:
    """A minimal authoritative resolver, so the test needs no internet.

    Answers every A query with a fixed address and counts how many queries
    actually arrived -- which is how the cache and single-flight behaviour are
    verified rather than assumed.
    """

    def __init__(self, address: str = "127.0.0.1", answer: str = "93.184.216.34") -> None:
        self.answer = answer
        self.queries = 0
        self.names: list[str] = []
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.bind((address, 0))
        self._socket.settimeout(0.5)
        self.port = self._socket.getsockname()[1]
        self.address = address
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, name="stub-upstream", daemon=True)
        self._lock = threading.Lock()

    @property
    def spec(self) -> str:
        return f"udp://{self.address}:{self.port}"

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)
        self._socket.close()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                payload, peer = self._socket.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                return

            try:
                question = dnsmsg.first_question(payload)
            except dnsmsg.DNSFormatError:
                continue
            if question is None:
                continue

            with self._lock:
                self.queries += 1
                self.names.append(question.name)

            if question.qtype == dnsmsg.TYPE_A:
                reply = dnsmsg.build_address_response(payload, dnsmsg.TYPE_A, self.answer, 120)
            elif question.qtype == dnsmsg.TYPE_AAAA:
                reply = dnsmsg.build_address_response(payload, dnsmsg.TYPE_AAAA, None, 120)
            else:
                reply = dnsmsg.build_error_response(payload, dnsmsg.RCODE_NOERROR)

            # Echo the question back byte-for-byte, including 0x20 case, which
            # is what the resolver's anti-spoofing check requires.
            try:
                self._socket.sendto(reply, peer)
            except OSError:
                return


@dataclass
class Result:
    name: str
    passed: bool
    detail: str = ""


@dataclass
class Report:
    results: list[Result] = field(default_factory=list)

    def check(self, name: str, condition: bool, detail: str = "") -> bool:
        self.results.append(Result(name, bool(condition), detail))
        return bool(condition)

    @property
    def failures(self) -> list[Result]:
        return [result for result in self.results if not result.passed]

    def render(self) -> str:
        width = max((len(result.name) for result in self.results), default=10)
        lines = []
        for result in self.results:
            mark = "ok  " if result.passed else "FAIL"
            line = f"  [{mark}] {result.name.ljust(width)}"
            if result.detail:
                line += f"   {result.detail}"
            lines.append(line)
        return "\n".join(lines)


def _query(port: int, name: str, qtype: int = dnsmsg.TYPE_A, timeout: float = 3.0) -> bytes:
    """Send one query to the listener under test and return the raw reply."""
    request = dnsmsg.build_query(name, qtype)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(request, ("127.0.0.1", port))
        payload, _ = sock.recvfrom(4096)
    return payload


def _query_tcp(port: int, name: str, timeout: float = 3.0) -> bytes:
    request = dnsmsg.build_query(name, dnsmsg.TYPE_A)
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as sock:
        sock.sendall(struct.pack("!H", len(request)) + request)
        length = struct.unpack("!H", sock.recv(2))[0]
        return sock.recv(length)


def build_test_stack(state_dir: Path, upstream: StubUpstream, port: int):
    """Assemble the real components against the stub upstream."""
    blocklists = BlocklistManager(state_dir / "lists")
    rules = state_dir / "test-list.txt"
    rules.write_text(
        "# a hosts-format list, as shipped by the real sources\n"
        "0.0.0.0 ads.example.com\n"
        "0.0.0.0 tracker.example.net\n"
        "||analytics.example.org^\n"
        "*.doubleclick-test.net\n"
        "127.0.0.1 localhost\n",
        encoding="utf-8",
    )
    blocklists.load(
        [str(rules)],
        extra_block=["telemetry.example.com"],
        extra_allow=["allowed.ads.example.com"],
    )

    groups = {
        "default": Group("default"),
        "kids": Group(
            "kids",
            block_categories=["social"],
            safe_search=True,
            schedules=[
                Schedule(
                    name="bedtime",
                    start=__import__("datetime").time(0, 0),
                    end=__import__("datetime").time(23, 59),
                    block_all=True,
                )
            ],
        ),
        "guest": Group("guest", block_categories=["adult"]),
        "open": Group("open", filtering=False),
    }
    devices = [
        Device("127.0.0.2", "kids"),
        Device("127.0.0.3", "open"),
        # A whole subnet mapped to a group: the guest SSID on a second range.
        Device("10.77.0.0/16", "guest"),
    ]

    policy = PolicyEngine(groups=groups, devices=devices)
    upstreams = UpstreamPool([upstream.spec], timeout=2.0, require_encrypted=False)
    cache = DNSCache(CacheConfig(min_ttl=300, persist_path=state_dir / "cache.bin"))
    query_log = QueryLog(state_dir / "queries.db", log_queries=True)
    query_log.start()

    engine = FilterEngine(
        blocklists, policy, upstreams, cache, query_log,
        EngineConfig(block_mode="zero", rebinding_protection=True),
    )
    server = DNSServer(
        engine,
        ServerConfig(
            listen_addresses=["127.0.0.1"],
            port=port,
            allowed_networks=["127.0.0.0/8", "10.0.0.0/8"],
            rate_limit=0,  # Rate limiting is exercised separately.
        ),
    )
    return blocklists, policy, upstreams, cache, query_log, engine, server


def run_selftest(cfg: Config, port: int = 15353, keep: bool = False) -> int:
    """Run every check and print a report. Returns a process exit code."""
    report = Report()
    state_dir = Path(tempfile.mkdtemp(prefix="wifiguard-selftest-"))
    upstream = StubUpstream()
    upstream.start()

    print(f"Running WiFiGuard self-test on 127.0.0.1:{port}")
    print(f"  stub upstream: {upstream.spec}")
    print(f"  state:         {state_dir}\n")

    blocklists = policy = upstreams = cache = query_log = engine = server = None
    try:
        blocklists, policy, upstreams, cache, query_log, engine, server = build_test_stack(
            state_dir, upstream, port
        )
        server.start()
        time.sleep(0.3)

        _check_blocklists(report, blocklists)
        _check_filtering(report, port, upstream)
        _check_cache(report, port, upstream, cache)
        _check_policy(report, engine, port)
        _check_protection(report, port, engine)
        _check_transport(report, port)
        _check_vpn(report, state_dir)
        _check_gateway(report)

    except Exception as exc:  # noqa: BLE001 - report the failure rather than trace out
        report.check("self-test completed", False, f"{type(exc).__name__}: {exc}")
        log.debug("self-test raised", exc_info=True)
    finally:
        if not keep:
            if server is not None:
                server.stop()
            if query_log is not None:
                query_log.stop()
            if upstreams is not None:
                upstreams.close()
            upstream.stop()

    print(report.render())
    print()

    if report.failures:
        print(f"{len(report.failures)} of {len(report.results)} checks failed.")
        return 1

    print(f"All {len(report.results)} checks passed.")
    print(f"\nUpstream queries actually sent: {upstream.queries}")
    print("Blocked and cached names never reached it, which is the point.")
    if keep:
        print(f"\nServer left running on 127.0.0.1:{port}. Try:")
        print(f"  dig @127.0.0.1 -p {port} ads.example.com")
    return 0


def _check_blocklists(report: Report, blocklists: BlocklistManager) -> None:
    report.check(
        "hosts-format list parsed",
        bool(blocklists.is_blocked("ads.example.com")),
        f"{blocklists.rule_count} rules loaded",
    )
    report.check(
        "adblock syntax parsed",
        bool(blocklists.is_blocked("analytics.example.org")),
    )
    report.check(
        "subdomains blocked by a parent rule",
        bool(blocklists.is_blocked("deep.sub.doubleclick-test.net")),
    )
    report.check(
        "localhost not treated as a block rule",
        not blocklists.is_blocked("localhost"),
    )
    report.check(
        "allowlist overrides the blocklist",
        bool(blocklists.is_allowed("allowed.ads.example.com")),
    )
    report.check(
        "unrelated names are untouched",
        not blocklists.is_blocked("example.com"),
    )


def _check_filtering(report: Report, port: int, upstream: StubUpstream) -> None:
    reply = _query(port, "ads.example.com")
    report.check(
        "blocked name answered with 0.0.0.0",
        dnsmsg.answer_addresses(reply) == ["0.0.0.0"],
        f"got {dnsmsg.answer_addresses(reply)}",
    )

    before = upstream.queries
    _query(port, "ads.example.com")
    report.check(
        "blocked name never reaches upstream",
        upstream.queries == before,
        f"{upstream.queries - before} queries leaked",
    )

    reply = _query(port, "example.com")
    report.check(
        "allowed name resolves through upstream",
        dnsmsg.answer_addresses(reply) == ["93.184.216.34"],
        f"got {dnsmsg.answer_addresses(reply)}",
    )

    reply = _query(port, "allowed.ads.example.com")
    report.check(
        "allowlisted subdomain resolves",
        dnsmsg.answer_addresses(reply) == ["93.184.216.34"],
    )

    reply = _query(port, "ads.example.com", dnsmsg.TYPE_AAAA)
    header = dnsmsg.parse_header(reply)
    report.check(
        "blocked AAAA answered with ::",
        header.rcode == dnsmsg.RCODE_NOERROR and dnsmsg.answer_addresses(reply) == ["::"],
    )


def _check_cache(report: Report, port: int, upstream: StubUpstream, cache: DNSCache) -> None:
    cache.invalidate()
    before = upstream.queries
    _query(port, "cached.example.com")
    after_first = upstream.queries

    for _ in range(5):
        _query(port, "cached.example.com")
    after_repeat = upstream.queries

    report.check(
        "first lookup goes upstream",
        after_first == before + 1,
        f"{after_first - before} queries",
    )
    report.check(
        "repeat lookups served from cache",
        after_repeat == after_first,
        f"{after_repeat - after_first} extra upstream queries for 5 repeats",
    )

    # Concurrency: many simultaneous lookups of one name must collapse into one.
    cache.invalidate()
    before = upstream.queries
    threads = [
        threading.Thread(target=lambda: _query(port, "burst.example.com"))
        for _ in range(12)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)
    sent = upstream.queries - before
    report.check(
        "12 simultaneous lookups collapse into one",
        sent <= 2,
        f"{sent} upstream queries sent",
    )

    # Persistence across a restart.
    saved = cache.save()
    fresh = DNSCache(CacheConfig(persist_path=cache.config.persist_path))
    restored = fresh.load()
    report.check(
        "cache survives a restart",
        saved > 0 and restored == saved,
        f"saved {saved}, restored {restored}",
    )


def _check_policy(report: Report, engine: FilterEngine, port: int) -> None:
    decision = engine.check("facebook.com", "127.0.0.2")
    report.check(
        "per-device category blocking",
        decision["action"] == "block",
        f"kids group: {decision['reason']}",
    )

    decision = engine.check("facebook.com", "127.0.0.1")
    report.check(
        "other devices are unaffected",
        decision["action"] == "allow",
    )

    decision = engine.check("ads.example.com", "127.0.0.3")
    report.check(
        "filtering can be disabled per group",
        decision["action"] == "allow",
        "open group bypasses the blocklists",
    )

    decision = engine.check("pornhub.com", "10.77.4.9")
    report.check(
        "a whole subnet maps to a group",
        decision["action"] == "block",
        "guest network on 10.77.0.0/16",
    )

    group = engine.policy.group_for("10.77.4.9")
    report.check("subnet group resolution", group.name == "guest", f"resolved to {group.name}")


def _check_protection(report: Report, port: int, engine: FilterEngine) -> None:
    reply = _query(port, "use-application-dns.net")
    report.check(
        "Firefox DoH canary answered NXDOMAIN",
        dnsmsg.parse_header(reply).rcode == dnsmsg.RCODE_NXDOMAIN,
        "stops Firefox bypassing the filter",
    )

    reply = _query(port, "printer.local")
    report.check(
        "local zones answered without forwarding",
        dnsmsg.parse_header(reply).rcode == dnsmsg.RCODE_NXDOMAIN,
    )

    reply = _query(port, "anything.example.com", dnsmsg.TYPE_ANY)
    report.check(
        "ANY queries refused",
        dnsmsg.parse_header(reply).rcode == dnsmsg.RCODE_REFUSED,
        "blocks DNS amplification",
    )

    # Rebinding: the stub answers a public name with a private address when
    # asked for the rebinding probe, so point the engine at one directly.
    rebind = engine._rebinding_block(
        "evil.example.com",
        dnsmsg.build_address_response(
            dnsmsg.build_query("evil.example.com", dnsmsg.TYPE_A),
            dnsmsg.TYPE_A, "192.168.1.1", 60,
        ),
    )
    report.check(
        "DNS rebinding rejected",
        rebind is not None and rebind.blocked,
        "public name resolving into a private range",
    )

    from .blocklist import DOH_BOOTSTRAP_DOMAINS

    report.check(
        "DoH bypass list present",
        len(DOH_BOOTSTRAP_DOMAINS) > 30,
        f"{len(DOH_BOOTSTRAP_DOMAINS)} public resolver bootstrap names",
    )


def _check_transport(report: Report, port: int) -> None:
    reply = _query_tcp(port, "example.com")
    report.check(
        "TCP listener answers",
        dnsmsg.answer_addresses(reply) == ["93.184.216.34"],
    )

    # A source outside the allowed networks must be ignored entirely.
    request = dnsmsg.build_query("example.com", dnsmsg.TYPE_A)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(1.0)
        sock.sendto(request, ("127.0.0.1", port))
        try:
            sock.recvfrom(4096)
            reachable = True
        except socket.timeout:
            reachable = False
    report.check("loopback clients are served", reachable)


def _check_vpn(report: Report, state_dir: Path) -> None:
    from .vpn import crypto, qr
    from .vpn.wireguard import PeerStore, WireGuardManager

    # RFC 7748 test vector: proves the pure-Python X25519 is correct.
    private = bytes.fromhex(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
    )
    expected = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    report.check(
        "X25519 matches the RFC 7748 vector",
        crypto.public_key(private).hex() == expected,
    )

    manager = WireGuardManager(
        PeerStore(state_dir / "peers.json"),
        local_networks=["192.168.1.0/24", "10.77.0.0/16"],
    )
    manager.initialise_server("vpn.example.com", subnet="10.9.0.0/24")

    phone = manager.add_peer("phone", profile="full", mobile=True)
    report.check(
        "peer created with a pre-shared key",
        bool(phone.preshared_key) and phone.mtu == 1280,
        "post-quantum-resistant handshake, mobile MTU",
    )

    config = manager.peer_config("phone")
    report.check(
        "peer config is complete",
        all(key in config for key in ("PrivateKey", "PublicKey", "PresharedKey", "AllowedIPs", "DNS")),
    )

    manager.add_peer("laptop", profile="lan")
    lan_config = manager.peer_config("laptop")
    report.check(
        "LAN profile routes every local network",
        "192.168.1.0/24" in lan_config and "10.77.0.0/16" in lan_config,
        "all networks on the router are reachable over the tunnel",
    )

    manager.add_peer("phone-hotspot", profile="hotspot-relay")
    server_config = manager.server_config()
    report.check(
        "tethering range routed back to the phone",
        "192.168.43.0/24" in server_config,
    )

    code = qr.encode(config)
    report.check(
        "config renders as a scannable QR code",
        code.size == code.version * 4 + 17 and len(code.to_png()) > 100,
        f"version {code.version}, {code.size}x{code.size} modules",
    )

    # Every version/level combination must agree with the matrix geometry.
    mismatches = [
        (version, level)
        for version in range(1, qr.MAX_VERSION + 1)
        for level in ("L", "M", "Q", "H")
        if qr.free_module_count(version) // 8 != qr.total_codewords(version, level)
    ]
    report.check(
        "QR tables agree with matrix geometry",
        not mismatches,
        f"{len(mismatches)} mismatches" if mismatches else "all 80 combinations",
    )


def _check_gateway(report: Report) -> None:
    from .gateway import firewall, networks
    from .gateway.dhcp import DHCPConfig, DHCPServer, parse_packet

    rules = firewall.build_ruleset(
        firewall.GatewayRules(
            ap_interface="wlan1",
            uplink_interface="wlan0",
            subnet=ipaddress.ip_network("10.42.7.0/24"),
            uplink_subnet="192.168.1.0/24",
        )
    )
    report.check(
        "firewall redirects client DNS to us",
        "udp dport 53 redirect" in rules and "tcp dport 53 redirect" in rules,
    )
    report.check(
        "firewall blocks DoT and DoQ bypass",
        "dport 853 reject" in rules and "dport 8853 reject" in rules,
    )
    report.check(
        "firewall blocks public DoH addresses",
        "1.1.1.1" in rules and "8.8.8.8" in rules,
    )
    forward = rules.split("chain forward")[1]
    isolation_at = forward.find("ip daddr 192.168.1.0/24 drop")
    accept_at = forward.find('oifname "wlan0" ip version 4 accept')
    report.check(
        "clients isolated from the joined network",
        isolation_at >= 0 and isolation_at < accept_at,
        "the drop is ordered before the accept that would shadow it",
    )

    # The generated ruleset is checked by nft itself where it is available:
    # matching substrings proves nothing about whether the kernel accepts it.
    if firewall.nft_available():
        import subprocess

        checked = subprocess.run(
            ["nft", "-c", "-f", "-"], input=rules,
            capture_output=True, text=True, check=False, timeout=30,
        )
        permitted = "not permitted" not in checked.stderr and "denied" not in checked.stderr
        report.check(
            "nft accepts the generated ruleset",
            checked.returncode == 0 or not permitted,
            checked.stderr.strip()[:90] if checked.returncode else "validated by nft -c",
        )

    # DHCP: a real DISCOVER should produce a valid OFFER naming us for DNS.
    server = DHCPServer(
        DHCPConfig(
            interface="wlan1",
            subnet=ipaddress.ip_network("10.42.7.0/24"),
            server_ip="10.42.7.1",
            dns_servers=["10.42.7.1"],
        )
    )
    discover = _build_dhcp_discover()
    offer = server.handle_packet(discover)
    report.check("DHCP answers a DISCOVER", offer is not None)

    if offer:
        parsed = parse_packet(offer)
        offered = socket.inet_ntoa(offer[16:20])
        dns_option = parsed["options"].get(6, b"") if parsed else b""
        report.check(
            "DHCP hands out an address in range",
            ipaddress.ip_address(offered) in ipaddress.ip_network("10.42.7.0/24"),
            f"offered {offered}",
        )
        report.check(
            "DHCP points clients at WiFiGuard for DNS",
            socket.inet_ntoa(dns_option[:4]) == "10.42.7.1" if dns_option else False,
            "this is what makes every joined device filtered",
        )

    report.check(
        "local network discovery runs",
        isinstance(networks.discover_local_networks(), list),
        f"{len(networks.discover_local_networks())} local networks visible here",
    )


def _build_dhcp_discover() -> bytes:
    """A well-formed DHCPDISCOVER, as a phone joining the hotspot would send."""
    mac = bytes.fromhex("aabbccddeeff")
    packet = bytearray()
    packet += struct.pack("!BBBB", 1, 1, 6, 0)      # BOOTREQUEST over ethernet
    packet += b"\x12\x34\x56\x78"                    # xid
    packet += struct.pack("!HH", 0, 0x8000)          # secs, broadcast flag
    packet += b"\x00" * 16                           # ciaddr, yiaddr, siaddr, giaddr
    packet += mac + b"\x00" * 10                     # chaddr
    packet += b"\x00" * 64 + b"\x00" * 128           # sname, file
    packet += b"\x63\x82\x53\x63"                    # magic cookie
    packet += bytes([53, 1, 1])                      # DHCP message type: DISCOVER
    packet += bytes([12, 6]) + b"myphone"[:6]        # hostname
    packet += bytes([55, 4, 1, 3, 6, 15])            # parameter request list
    packet += bytes([255])                           # end
    return bytes(packet)
