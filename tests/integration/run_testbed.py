"""End-to-end integration test against a virtual network.

Unlike the unit tests and `wifiguard selftest`, which run everything in one
process on loopback, this drives WiFiGuard from separate network stacks using
ordinary tools. The clients are real DNS resolvers that know nothing about
WiFiGuard's internals, the DHCP handshake is a real broadcast, and the firewall
is enforced by the kernel.

Run as root:  sudo python3 tests/integration/run_testbed.py
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT))

from tests.integration import topology as topo  # noqa: E402

CERT_DIR = Path("/tmp/wgt-certs")
UPSTREAM_STATE = Path("/tmp/wgt-upstream.json")


@dataclass
class Report:
    results: list[tuple[str, bool, str]] = field(default_factory=list)
    section: str = ""

    def heading(self, title: str) -> None:
        self.results.append((f"__section__{title}", True, ""))

    def check(self, name: str, ok: bool, detail: str = "") -> bool:
        self.results.append((name, bool(ok), detail))
        return bool(ok)

    @property
    def failures(self):
        return [r for r in self.results if not r[1] and not r[0].startswith("__section__")]

    @property
    def total(self):
        return len([r for r in self.results if not r[0].startswith("__section__")])

    def render(self) -> str:
        width = max(
            (len(name) for name, _, _ in self.results if not name.startswith("__section__")),
            default=10,
        )
        lines = []
        for name, ok, detail in self.results:
            if name.startswith("__section__"):
                lines.append("")
                lines.append(f"  {name[len('__section__'):]}")
                lines.append("  " + "-" * (width + 8))
                continue
            mark = "ok  " if ok else "FAIL"
            line = f"  [{mark}] {name.ljust(width)}"
            if detail:
                line += f"   {detail}"
            lines.append(line)
        return "\n".join(lines)


def sh(namespace: str, *command: str, timeout: float = 20) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["ip", "netns", "exec", namespace, *command],
        capture_output=True, text=True, timeout=timeout, check=False,
    )


def dig(namespace: str, server: str, name: str, extra: list[str] | None = None) -> str:
    """Resolve using the real dig client, returning the first answer."""
    result = sh(
        namespace, "dig", f"@{server}", name, "+short", "+timeout=3", "+tries=1",
        *(extra or []),
    )
    return result.stdout.strip().splitlines()[0] if result.stdout.strip() else ""


def dig_status(namespace: str, server: str, name: str) -> str:
    """The rcode dig reports, e.g. NOERROR or NXDOMAIN."""
    result = sh(namespace, "dig", f"@{server}", name, "+timeout=3", "+tries=1")
    for line in result.stdout.splitlines():
        if "status:" in line:
            return line.split("status:")[1].split(",")[0].strip()
    return "NO-REPLY"


def tcp_probe(namespace: str, address: str, port: int, timeout: float = 3.0):
    """Try to open a TCP connection from inside a namespace.

    Returns (connected, seconds, error). The timing matters: a firewall REJECT
    fails in milliseconds, an unroutable address times out.
    """
    script = (
        "import socket,sys,time\n"
        f"s=socket.socket();s.settimeout({timeout})\n"
        "t=time.monotonic()\n"
        "try:\n"
        f"    s.connect(('{address}',{port}))\n"
        "    print('OK', time.monotonic()-t)\n"
        "except Exception as e:\n"
        "    print('ERR', time.monotonic()-t, type(e).__name__, e)\n"
    )
    result = sh(namespace, "python3", "-c", script, timeout=timeout + 5)
    parts = result.stdout.strip().split(None, 2)
    if not parts:
        return False, timeout, "no output"
    return parts[0] == "OK", float(parts[1]), (parts[2] if len(parts) > 2 else "")


def upstream_counters() -> dict:
    try:
        return json.loads(UPSTREAM_STATE.read_text())
    except (OSError, ValueError):
        return {"udp": 0, "doh": 0, "total_dns": 0, "tcp_connections": 0, "names": []}


def write_config(path: Path, state_dir: Path, upstream: str, *, require_encrypted: bool,
                 pins: dict | None = None) -> None:
    pin_block = ""
    if pins:
        pin_block = "\n[upstream.pins]\n" + "\n".join(
            f'"{host}" = {json.dumps(values)}' for host, values in pins.items()
        )
    path.write_text(f"""
protection = "standard"
state_dir = "{state_dir}"

[server]
listen_addresses = ["127.0.0.1", "{topo.AP_ADDR}", "{topo.GUEST_GATEWAY_ADDR}"]
port = 53
allowed_networks = ["127.0.0.0/8", "{topo.AP_NET}", "{topo.GUEST_NET}"]
rate_limit = 0

[networks]
discover_local = true
group_by_network = {{ "{topo.GUEST_NET}" = "guest" }}

[upstream]
servers = ["{upstream}"]
require_encrypted = {str(require_encrypted).lower()}
timeout = 4.0
{pin_block}

[cache]
min_ttl = 300

[blocklists]
sources = []
# Deliberately blocked, to prove the compatibility guard overrides even an
# explicit block: a device with no clock and no certificate checks is dead.
block = [
    "ads.example.com", "tracker.example.net", "*.doubleclick-test.net",
    "pool.ntp.org", "ocsp.digicert.com", "connectivitycheck.gstatic.com",
]
allow = ["allowed.ads.example.com"]
block_doh_bypass = true

[engine]
block_mode = "zero"

[dashboard]
enabled = true
address = "127.0.0.1"
port = 8080

[logging]
level = "WARNING"
log_queries = true

[groups.guest]
block_categories = ["adult"]
""")


class Testbed:
    def __init__(self) -> None:
        self.state_dir = Path(tempfile.mkdtemp(prefix="wgt-state-"))
        self.config_path = self.state_dir / "wifiguard.toml"
        self.upstream_process: subprocess.Popen | None = None
        self.gateway_process: subprocess.Popen | None = None
        self.env = {**os.environ, "PYTHONPATH": str(ROOT), "TESTBED_STATE": str(UPSTREAM_STATE)}

    def start_upstream(self) -> None:
        UPSTREAM_STATE.unlink(missing_ok=True)
        self.upstream_process = subprocess.Popen(
            ["ip", "netns", "exec", topo.INTERNET, "python3",
             str(HERE / "upstream_world.py"), topo.INTERNET_ADDR,
             str(CERT_DIR / "cert.pem"), str(CERT_DIR / "key.pem")],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=self.env,
        )
        for _ in range(60):
            if UPSTREAM_STATE.exists():
                return
            time.sleep(0.25)
        raise RuntimeError("the stub internet did not start")

    def start_gateway(self, upstream: str, *, require_encrypted: bool, pins=None,
                      cold_cache: bool = False) -> None:
        self.stop_gateway()
        if cold_cache:
            # The cache is persisted across restarts by design, so a phase that
            # needs to observe a live upstream lookup has to clear it first.
            (self.state_dir / "dnscache.bin").unlink(missing_ok=True)
        write_config(self.config_path, self.state_dir, upstream,
                     require_encrypted=require_encrypted, pins=pins)
        self.gateway_process = subprocess.Popen(
            ["ip", "netns", "exec", topo.GATEWAY, "python3",
             str(HERE / "gateway_node.py"), str(self.config_path)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=self.env,
        )
        deadline = time.time() + 40
        while time.time() < deadline:
            if self.gateway_process.poll() is not None:
                output = self.gateway_process.stdout.read() if self.gateway_process.stdout else ""
                raise RuntimeError(f"the gateway exited during start-up:\n{output}")
            if sh(topo.GATEWAY, "nft", "list", "tables").stdout.count("wifiguard"):
                time.sleep(1.5)  # Let the listeners finish binding.
                return
            time.sleep(0.5)
        raise RuntimeError("the gateway did not come up")

    def stop_gateway(self) -> None:
        if self.gateway_process is not None:
            self.gateway_process.terminate()
            try:
                self.gateway_process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.gateway_process.kill()
            self.gateway_process = None
        sh(topo.GATEWAY, "nft", "delete", "table", "ip", "wifiguard")
        sh(topo.GATEWAY, "nft", "delete", "table", "inet", "wifiguard_filter")

    def stop(self) -> None:
        self.stop_gateway()
        if self.upstream_process is not None:
            self.upstream_process.terminate()
            try:
                self.upstream_process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.upstream_process.kill()
            self.upstream_process = None
        shutil.rmtree(self.state_dir, ignore_errors=True)


# =============================================================================
# Scenarios
# =============================================================================


def scenario_gateway_up(report: Report) -> None:
    report.heading("Gateway brought itself up")

    forwarding = sh(topo.GATEWAY, "cat", "/proc/sys/net/ipv4/ip_forward").stdout.strip()
    report.check("kernel IP forwarding enabled", forwarding == "1",
                 "was off before WiFiGuard started")

    tables = sh(topo.GATEWAY, "nft", "list", "tables").stdout
    report.check("nftables tables installed", "wifiguard" in tables,
                 tables.strip().replace("\n", ", "))

    rules = sh(topo.GATEWAY, "nft", "list", "table", "ip", "wifiguard").stdout
    report.check("DNS redirect rule present",
                 "dport 53" in rules and "redirect" in rules)
    report.check("NAT masquerade rule present", "masquerade" in rules)

    filter_rules = sh(topo.GATEWAY, "nft", "list", "table", "inet", "wifiguard_filter").stdout
    report.check("forward policy is drop", "policy drop" in filter_rules)
    report.check("DoT port rejected", "853" in filter_rules)


def scenario_dhcp(report: Report, testbed: Testbed) -> dict:
    report.heading("A phone joins, having been told nothing")

    result = sh(topo.PHONE, "python3", str(HERE / "dhcp_client.py"), "eth0", timeout=30)
    try:
        lease = json.loads(result.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        report.check("phone obtained a DHCP lease", False,
                     (result.stdout + result.stderr).strip()[:160])
        return {}

    if "error" in lease:
        report.check("phone obtained a DHCP lease", False, lease["error"])
        return {}

    report.check("phone obtained a DHCP lease", True, f"address {lease['address']}")

    import ipaddress
    in_range = ipaddress.ip_address(lease["address"]) in ipaddress.ip_network(topo.AP_NET)
    report.check("address is inside the client subnet", in_range, topo.AP_NET)
    report.check("lease names WiFiGuard as the DNS server",
                 lease["dns"] == [topo.AP_ADDR], f"DNS = {lease['dns']}")
    report.check("lease names WiFiGuard as the router",
                 lease["router"] == [topo.AP_ADDR], f"router = {lease['router']}")

    configured = sh(topo.PHONE, "ip", "-brief", "addr", "show", "eth0").stdout
    report.check("phone configured itself from the lease",
                 lease["address"] in configured, configured.strip())

    # The hostname the client sent should reach the policy engine.
    time.sleep(3)
    leases_file = testbed.state_dir / "leases.json"
    learned = ""
    if leases_file.exists():
        stored = json.loads(leases_file.read_text())
        learned = ", ".join(entry.get("hostname", "") for entry in stored.values())
    report.check("gateway learned the device name", "phone" in learned,
                 f"hostname {learned!r}")
    return lease


def scenario_filtering(report: Report) -> None:
    report.heading("Filtering, from a client that did nothing special")

    before = upstream_counters()

    blocked = dig(topo.PHONE, topo.AP_ADDR, "ads.example.com")
    report.check("blocked name answered 0.0.0.0", blocked == "0.0.0.0", f"got {blocked!r}")

    wildcard = dig(topo.PHONE, topo.AP_ADDR, "deep.sub.doubleclick-test.net")
    report.check("subdomain of a wildcard rule blocked", wildcard == "0.0.0.0",
                 f"got {wildcard!r}")

    allowed = dig(topo.PHONE, topo.AP_ADDR, "example.com")
    report.check("permitted name resolved through upstream", allowed == "93.184.216.34",
                 f"got {allowed!r}")

    exempt = dig(topo.PHONE, topo.AP_ADDR, "allowed.ads.example.com")
    report.check("allowlist beats the blocklist", exempt == "93.184.216.37",
                 f"got {exempt!r}")

    after = upstream_counters()
    forwarded_names = [n for n in after["names"][len(before["names"]):]]
    report.check("blocked names never reached the internet",
                 "ads.example.com" not in forwarded_names
                 and "deep.sub.doubleclick-test.net" not in forwarded_names,
                 f"upstream saw {forwarded_names}")

    canary = dig_status(topo.PHONE, topo.AP_ADDR, "use-application-dns.net")
    report.check("Firefox DoH canary answered NXDOMAIN", canary == "NXDOMAIN",
                 f"status {canary}")

    doh_bootstrap = dig(topo.PHONE, topo.AP_ADDR, "dns.google")
    report.check("public DoH bootstrap name blocked", doh_bootstrap == "0.0.0.0",
                 f"got {doh_bootstrap!r}")


def scenario_cache(report: Report) -> None:
    report.heading("Cache keeps queries off the wire")

    dig(topo.PHONE, topo.AP_ADDR, "cached.example.com")
    before = upstream_counters()["total_dns"]
    for _ in range(6):
        dig(topo.PHONE, topo.AP_ADDR, "cached.example.com")
    after = upstream_counters()["total_dns"]

    report.check("repeat lookups served from cache", after == before,
                 f"{after - before} extra upstream queries for 6 repeats")


def scenario_bypass(report: Report) -> None:
    report.heading("A device that tries not to be filtered")

    # The TV is configured with a hardcoded public resolver, as real ones are.
    hijacked = dig(topo.TV, "8.8.8.8", "ads.example.com")
    report.check("query to a hardcoded 8.8.8.8 answered by us",
                 hijacked == "0.0.0.0", f"got {hijacked!r}")

    hijacked_allowed = dig(topo.TV, "9.9.9.9", "example.com")
    report.check("the redirect does not break normal names",
                 hijacked_allowed == "93.184.216.34", f"got {hijacked_allowed!r}")

    # DNS-over-TLS must fail closed, and fail fast.
    connected, elapsed, error = tcp_probe(topo.TV, topo.INTERNET_ADDR, 853)
    report.check("DNS-over-TLS rejected", not connected,
                 f"{error or 'connected'} after {elapsed:.2f}s")
    report.check("DoT rejection is immediate, not a timeout", elapsed < 1.5,
                 f"{elapsed:.2f}s -- a client falls back to us straight away")

    # A public DoH address, which is genuinely routable here.
    connected, elapsed, error = tcp_probe(topo.TV, topo.PUBLIC_DOH_ADDR, 443)
    report.check("public DoH endpoint address rejected", not connected,
                 f"{error or 'connected'} after {elapsed:.2f}s")


def scenario_routing(report: Report) -> None:
    report.heading("Routing and isolation")

    # Reaching the internet means a host beyond the joined network...
    connected, elapsed, error = tcp_probe(topo.PHONE, topo.FAR_INTERNET_ADDR, 80)
    report.check("client reaches the internet through NAT", connected,
                 error or f"{topo.FAR_INTERNET_ADDR} in {elapsed:.2f}s")

    counters = upstream_counters()
    report.check("the connection arrived at the far side",
                 counters["tcp_connections"] > 0,
                 f"{counters['tcp_connections']} TCP connections seen")

    # ...and isolation means a host *on* it must stay out of reach. This is the
    # difference between routing through a hotel network and being on it.
    connected, elapsed, error = tcp_probe(topo.PHONE, topo.INTERNET_ADDR, 80)
    report.check("client cannot reach hosts on the joined network", not connected,
                 f"{topo.INTERNET_ADDR}: {error or 'CONNECTED'} after {elapsed:.2f}s")

    rules = sh(topo.GATEWAY, "nft", "list", "table", "inet", "wifiguard_filter").stdout
    report.check("isolation rule is against the uplink subnet",
                 "ip daddr 10.200.0.0/24 drop" in rules,
                 "written by subnet, so it is not shadowed by the accept below it")

    # Masquerade means the far side sees the gateway, never the client.
    nat = sh(topo.GATEWAY, "nft", "list", "table", "ip", "wifiguard").stdout
    report.check("client addresses are masqueraded",
                 f"ip saddr {topo.AP_NET}" in nat and "masquerade" in nat)


def scenario_multi_network(report: Report) -> None:
    report.heading("A second network on the same gateway")

    resolved = dig(topo.GUEST, topo.GUEST_GATEWAY_ADDR, "example.com")
    report.check("second network is served by the resolver",
                 resolved == "93.184.216.34", f"got {resolved!r}")

    blocked = dig(topo.GUEST, topo.GUEST_GATEWAY_ADDR, "ads.example.com")
    report.check("second network is filtered too", blocked == "0.0.0.0", f"got {blocked!r}")

    # The guest subnet maps to a stricter group.
    strict = dig(topo.GUEST, topo.GUEST_GATEWAY_ADDR, "pornhub.com")
    report.check("subnet-to-group mapping applies", strict == "0.0.0.0",
                 f"guest group blocks a category the default group does not: got {strict!r}")

    lenient = dig(topo.PHONE, topo.AP_ADDR, "pornhub.com")
    report.check("the other network keeps its own rules", lenient != "0.0.0.0",
                 f"main network got {lenient!r}")


def scenario_encrypted_upstream(report: Report, testbed: Testbed) -> None:
    report.heading("Encrypted upstream, with real certificate verification")

    doh_url = f"https://{topo.INTERNET_ADDR}/dns-query"

    # Point the trust store at the test CA. Nothing disables verification
    # anywhere: WiFiGuard has no option to, by design.
    testbed.env["SSL_CERT_FILE"] = str(CERT_DIR / "cert.pem")
    try:
        testbed.start_gateway(doh_url, require_encrypted=True, cold_cache=True)
    except RuntimeError as exc:
        report.check("gateway started with a DoH upstream", False, str(exc)[:160])
        testbed.env.pop("SSL_CERT_FILE", None)
        return
    report.check("gateway started with a DoH upstream", True, doh_url)

    before = upstream_counters()
    resolved = dig(topo.PHONE, topo.AP_ADDR, "doh-probe.example.com")
    after = upstream_counters()

    report.check("name resolved over DNS-over-HTTPS", resolved == "93.184.216.40",
                 f"got {resolved!r}")
    report.check("the query really went over the DoH endpoint",
                 after["doh"] > before["doh"] and after["udp"] == before["udp"],
                 f"{after['doh'] - before['doh']} DoH requests, "
                 f"{after['udp'] - before['udp']} plaintext")

    blocked = dig(topo.PHONE, topo.AP_ADDR, "ads.example.com")
    report.check("filtering still applies over DoH", blocked == "0.0.0.0", f"got {blocked!r}")

    # --- pinning ---------------------------------------------------------
    import ssl as ssl_module
    from wifiguard.tlsutil import spki_pin

    der = ssl_module.PEM_cert_to_DER_cert((CERT_DIR / "cert.pem").read_text())
    correct_pin = spki_pin(der)

    try:
        testbed.start_gateway(doh_url, require_encrypted=True,
                              pins={topo.INTERNET_ADDR: [correct_pin]}, cold_cache=True)
        resolved = dig(topo.PHONE, topo.AP_ADDR, "pin-ok.example.com")
        report.check("correct public-key pin accepted", resolved == "93.184.216.41",
                     f"pin {correct_pin[:16]}... -> {resolved!r}")
    except RuntimeError as exc:
        report.check("correct public-key pin accepted", False, str(exc)[:120])

    # A wrong pin must break the connection outright. This is the check that
    # matters: a pin that is silently ignored is worse than no pin at all.
    wrong_pin = "A" * 43 + "="
    try:
        testbed.start_gateway(doh_url, require_encrypted=True,
                              pins={topo.INTERNET_ADDR: [wrong_pin]}, cold_cache=True)
        before = upstream_counters()
        resolved = dig(topo.PHONE, topo.AP_ADDR, "pin-bad.example.com")
        after = upstream_counters()
        report.check("wrong public-key pin refuses to resolve", resolved == "",
                     f"got {resolved!r} -- pinning must fail closed")
        report.check("nothing was fetched under a bad pin",
                     after["doh"] == before["doh"],
                     f"{after['doh'] - before['doh']} DoH requests slipped through")
    except RuntimeError as exc:
        report.check("wrong public-key pin refuses to resolve", False, str(exc)[:120])

    testbed.env.pop("SSL_CERT_FILE", None)


def scenario_device_compatibility(report: Report, testbed: Testbed) -> None:
    report.heading("Devices that would otherwise be broken by filtering")

    # These three are in the testbed's blocklist above. A device losing any of
    # them breaks in a way that gives no clue the network is responsible.
    for name, expected, what in (
        ("pool.ntp.org", "162.159.200.1", "clock"),
        ("ocsp.digicert.com", "93.184.216.46", "certificate checks"),
        ("connectivitycheck.gstatic.com", "93.184.216.47", "connectivity probe"),
    ):
        resolved = dig(topo.PHONE, topo.AP_ADDR, name)
        report.check(
            f"blocklist cannot take away a device's {what}",
            resolved == expected,
            f"{name} -> {resolved!r} (explicitly blocked in this config)",
        )

    # ...while ordinary blocking is unaffected.
    still_blocked = dig(topo.PHONE, topo.AP_ADDR, "ads.example.com")
    report.check("ordinary names are still blocked", still_blocked == "0.0.0.0",
                 f"got {still_blocked!r}")

    # A device that validates DNSSEC itself must get the signatures, or every
    # lookup it makes fails.
    before = upstream_counters()
    sh(topo.PHONE, "dig", f"@{topo.AP_ADDR}", "signed.example.com", "+dnssec",
       "+timeout=3", "+tries=1")
    after = upstream_counters()
    report.check(
        "a client's DNSSEC request is carried upstream",
        after.get("dnssec_requests", 0) > before.get("dnssec_requests", 0),
        f"upstream saw DO set for {after.get('dnssec_names', [])[-1:]}",
    )

    # And a plain client still gets the cheap unsigned path.
    before = upstream_counters()
    dig(topo.PHONE, topo.AP_ADDR, "burst.example.com")
    after = upstream_counters()
    report.check(
        "a plain client is not charged for signatures",
        after.get("dnssec_requests", 0) == before.get("dnssec_requests", 0),
        "DNSSEC records are only fetched when a client asks for them",
    )


def scenario_clockless_device(report: Report, testbed: Testbed) -> None:
    report.heading("A device with no clock")

    # Ask for a lease again, this time reading the options a device that needs
    # a clock would act on. Runs on the client segment, which is where the DHCP
    # server listens.
    result = sh(topo.PHONE, "python3", str(HERE / "dhcp_probe.py"), timeout=30)
    try:
        lease = json.loads(result.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        report.check("device received DHCP options", False,
                     (result.stdout + result.stderr).strip()[:150])
        return
    if "error" in lease:
        report.check("device received DHCP options", False, lease["error"])
        return

    report.check("lease includes an NTP server", bool(lease.get("ntp")),
                 f"NTP = {lease.get('ntp')}")
    report.check("the NTP server is the gateway itself",
                 lease.get("ntp") == [topo.AP_ADDR],
                 "an address, because DHCP cannot carry a name like pool.ntp.org")
    report.check("lease includes an MTU", lease.get("mtu", 0) > 0,
                 f"MTU = {lease.get('mtu')}")
    report.check("lease includes a domain search list",
                 bool(lease.get("domain_search")),
                 f"search = {lease.get('domain_search')!r}")

    # Now actually ask the gateway for the time, as the device would.
    result = sh(topo.PHONE, "python3", str(HERE / "ntp_probe.py"), topo.AP_ADDR, timeout=20)
    try:
        answer = json.loads(result.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        report.check("gateway answered an NTP request", False,
                     (result.stdout + result.stderr).strip()[:150])
        return

    report.check("gateway answered an NTP request", answer.get("ok", False),
                 answer.get("error", ""))
    if answer.get("ok"):
        report.check("the time it gave is correct",
                     abs(answer["offset"]) < 5,
                     f"{answer['offset']:+.3f}s from this host's clock")
        report.check("the reply is a server-mode NTP packet", answer["mode"] == 4,
                     f"mode {answer['mode']}, stratum {answer['stratum']}")


def scenario_uplink_change(report: Report, testbed: Testbed) -> None:
    report.heading("The uplink moves (as it does on a laptop)")

    from wifiguard.gateway import interfaces

    script = (
        "import sys; sys.path.insert(0, %r)\n"
        "from wifiguard.gateway import interfaces\n"
        "print(interfaces.uplink_fingerprint())\n" % str(ROOT)
    )
    first = sh(topo.GATEWAY, "python3", "-c", script).stdout.strip()
    report.check("uplink fingerprint readable", bool(first) and first != "-|-|-", first)

    # Join a "different network": same interface, a new gateway address. That
    # is what changes when a laptop moves from home WiFi to a hotel's.
    sh(topo.INTERNET, "ip", "addr", "add", "10.200.0.3/24", "dev", "net0")
    sh(topo.GATEWAY, "ip", "route", "del", "default")
    sh(topo.GATEWAY, "ip", "route", "add", "default", "via", "10.200.0.3")
    second = sh(topo.GATEWAY, "python3", "-c", script).stdout.strip()

    report.check("a network change is detected", second != first,
                 f"{first} -> {second}")

    # And back again, as it would be on returning home.
    sh(topo.GATEWAY, "ip", "route", "del", "default")
    sh(topo.GATEWAY, "ip", "route", "add", "default", "via", topo.INTERNET_ADDR)
    third = sh(topo.GATEWAY, "python3", "-c", script).stdout.strip()
    report.check("moving back is detected too", third == first, f"{second} -> {third}")

    # Restore the plaintext upstream and confirm the gateway still resolves
    # after the network underneath it moved.
    testbed.start_gateway(f"udp://{topo.INTERNET_ADDR}", require_encrypted=False,
                          cold_cache=True)
    resolved = dig(topo.PHONE, topo.AP_ADDR, "uplink-probe.example.com")
    report.check("still resolving after the uplink changed",
                 resolved == "93.184.216.43", f"got {resolved!r}")


def main() -> int:
    if os.geteuid() != 0:
        print("This test needs root: sudo python3 tests/integration/run_testbed.py")
        return 2

    report = Report()
    testbed = Testbed()

    print("Building the virtual network...")
    topo.build()
    print(topo.describe())
    print()

    try:
        testbed.start_upstream()
        print("stub internet running")
        testbed.start_gateway(f"udp://{topo.INTERNET_ADDR}", require_encrypted=False)
        print("gateway running\n")

        scenario_gateway_up(report)
        scenario_dhcp(report, testbed)
        scenario_filtering(report)
        scenario_cache(report)
        scenario_bypass(report)
        scenario_routing(report)
        scenario_multi_network(report)
        scenario_device_compatibility(report, testbed)
        scenario_clockless_device(report, testbed)
        scenario_encrypted_upstream(report, testbed)
        scenario_uplink_change(report, testbed)

    except Exception as exc:  # noqa: BLE001 - report rather than trace out
        report.check("testbed ran to completion", False, f"{type(exc).__name__}: {exc}")
        import traceback
        traceback.print_exc()
    finally:
        testbed.stop()
        if os.environ.get("KEEP_TESTBED") != "1":
            topo.teardown()

    print(report.render())
    print()
    counters = upstream_counters()
    print(f"  Upstream saw {counters['total_dns']} DNS queries "
          f"({counters['udp']} plaintext, {counters['doh']} over HTTPS) "
          f"and {counters['tcp_connections']} TCP connections.")
    print()

    if report.failures:
        print(f"{len(report.failures)} of {report.total} checks failed.")
        return 1
    print(f"All {report.total} checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
