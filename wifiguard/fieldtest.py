"""Assess the network this machine is actually attached to.

`selftest` proves WiFiGuard works. This asks a different question: what is
*this* network doing to your DNS, and what will WiFiGuard change about it?

It runs before you install anything and answers the things worth knowing:
whether the network intercepts port 53, whether it rewrites answers, whether
encrypted DNS can get out at all, and whether TLS is being intercepted on the
way. Every check reports what it found and what WiFiGuard does about it.

Nothing here modifies the system. It sends queries and opens connections, the
same as any ordinary program would.
"""

from __future__ import annotations

import re
import socket
import ssl
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import dnsmsg
from .tlsutil import build_context, spki_pin

#: Addresses in reserved documentation ranges. Nothing can legitimately run a
#: resolver on these, so an answer from one means something on the path
#: answered on its behalf.
IMPOSSIBLE_RESOLVERS = ("203.0.113.99", "198.51.100.77", "192.0.2.123")

#: Public resolvers to compare against each other.
PUBLIC_RESOLVERS = (("Quad9", "9.9.9.9"), ("Cloudflare", "1.1.1.1"), ("Google", "8.8.8.8"))

#: DoH endpoints to try, as WiFiGuard would use them.
DOH_ENDPOINTS = (
    "https://dns.quad9.net/dns-query",
    "https://dns.cloudflare.com/dns-query",
    "https://dns.google/dns-query",
)

#: Organisations that operate CAs in the public root programmes. A certificate
#: issued by anyone else, on a public site, means something local is
#: re-signing traffic. This is a heuristic, and reported as one.
PUBLIC_CA_ORGANISATIONS = (
    "internet security research group", "let's encrypt", "digicert", "digicert inc",
    "sectigo", "sectigo limited", "comodo ca limited", "globalsign", "globalsign nv-sa",
    "google trust services", "google trust services llc", "amazon", "entrust",
    "entrust, inc.", "identrust", "godaddy.com, inc.", "starfield technologies, inc.",
    "microsoft corporation", "apple inc.", "buypass as-983163327", "certum",
    "unizeto technologies s.a.", "actalis s.p.a.", "ssl corp", "zerossl",
)

#: A name that certainly does not exist. Used to catch a resolver that invents
#: an address for typos instead of admitting the name is not there.
def _nonexistent_name() -> str:
    import secrets

    return f"wifiguard-{secrets.token_hex(8)}-should-not-exist.invalid"


SEVERITY_ORDER = {"problem": 0, "warn": 1, "ok": 2, "info": 3}


@dataclass
class Finding:
    key: str
    severity: str  # "ok", "warn", "problem", "info"
    title: str
    detail: str = ""
    remedy: str = ""


@dataclass
class FieldReport:
    findings: list[Finding] = field(default_factory=list)

    def add(self, *args, **kwargs) -> Finding:
        finding = Finding(*args, **kwargs)
        self.findings.append(finding)
        return finding

    def by_severity(self, severity: str) -> list[Finding]:
        return [f for f in self.findings if f.severity == severity]

    def render(self) -> str:
        marks = {"ok": "ok  ", "warn": "warn", "problem": "FAIL", "info": "--  "}
        lines = []
        for finding in self.findings:
            lines.append(f"  [{marks[finding.severity]}] {finding.title}")
            if finding.detail:
                for line in _wrap(finding.detail):
                    lines.append(f"           {line}")
            if finding.remedy:
                for line in _wrap(finding.remedy):
                    lines.append(f"           -> {line}")
            lines.append("")
        return "\n".join(lines)


def _wrap(text: str, width: int = 68) -> list[str]:
    import textwrap

    return textwrap.wrap(" ".join(text.split()), width) or [""]


def _query(server: str, name: str, timeout: float = 3.0, qtype: int = dnsmsg.TYPE_A):
    """Send one plain DNS query. Returns (addresses, rcode, elapsed_ms) or None."""
    query = dnsmsg.build_query(name, qtype)
    started = time.monotonic()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(query, (server, 53))
        payload, _ = sock.recvfrom(4096)
    except OSError:
        return None
    finally:
        sock.close()

    try:
        header = dnsmsg.parse_header(payload)
        return (
            dnsmsg.answer_addresses(payload),
            header.rcode,
            (time.monotonic() - started) * 1000,
        )
    except dnsmsg.DNSFormatError:
        return None


# -- checks -------------------------------------------------------------------


def check_configured_resolver(report: FieldReport) -> None:
    """What this machine has been told to use."""
    servers = []
    try:
        for line in Path("/etc/resolv.conf").read_text().splitlines():
            match = re.match(r"\s*nameserver\s+(\S+)", line)
            if match:
                servers.append(match.group(1))
    except OSError:
        pass

    if not servers:
        report.add("resolver", "info", "No resolver found in /etc/resolv.conf",
                   "This machine may use systemd-resolved or another stub.")
        return

    detail = ", ".join(servers)
    private = all(
        s.startswith(("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
                      "172.2", "172.30.", "172.31.", "127."))
        for s in servers
    )
    report.add(
        "resolver", "info",
        f"This machine currently resolves through {detail}",
        "That is a local address, so most likely your router."
        if private else
        "That is a public resolver, so your lookups leave the network in the clear "
        "unless something is encrypting them.",
    )


def check_dns_interception(report: FieldReport) -> None:
    """Does the network answer port 53 no matter who it was addressed to?"""
    responders = []
    for address in IMPOSSIBLE_RESOLVERS:
        result = _query(address, "example.com", timeout=3.0)
        if result is not None:
            responders.append(address)

    if responders:
        report.add(
            "interception", "problem",
            "This network intercepts DNS",
            f"A query addressed to {responders[0]} was answered. That address is in "
            f"a reserved documentation range where no resolver can exist, so "
            f"something on the path is answering port 53 on its behalf -- every "
            f"lookup from this network is being seen, and can be changed.",
            "WiFiGuard sends its queries over DNS-over-HTTPS on port 443 instead, "
            "which this cannot read or rewrite. Run `wifiguard doctor` to confirm "
            "encrypted DNS gets out from here.",
        )
    else:
        report.add(
            "interception", "ok",
            "Port 53 is not being intercepted",
            "Queries reach the resolver they were addressed to.",
        )


def check_answer_tampering(report: FieldReport) -> None:
    """Do independent resolvers agree, and is the answer plausible?"""
    answers = {}
    for label, address in PUBLIC_RESOLVERS:
        result = _query(address, "example.com")
        if result is not None and result[0]:
            answers[label] = sorted(result[0])

    if not answers:
        report.add("tampering", "warn", "Could not reach any public resolver on port 53",
                   "Plain DNS may be blocked outright on this network.")
        return

    # example.com is IANA's reserved domain and lives in a documented range.
    # An answer outside it did not come from the real authoritative servers.
    plausible = {
        label: any(a.startswith(("93.184.215.", "93.184.216.")) for a in addresses)
        for label, addresses in answers.items()
    }

    unique = {tuple(a) for a in answers.values()}
    if not any(plausible.values()):
        sample = next(iter(answers.values()))
        report.add(
            "tampering", "problem",
            "DNS answers on this network are being rewritten",
            f"example.com should resolve into 93.184.215.0/24, and every resolver "
            f"here returned {', '.join(sample)} instead"
            + (" -- identical across all of them, which is what an interception "
               "looks like." if len(unique) == 1 else "."),
            "Encrypted DNS is the fix: the answer is signed into a TLS session "
            "that whatever is doing this cannot open.",
        )
    elif len(unique) > 1:
        report.add(
            "tampering", "warn", "Public resolvers disagree about example.com",
            "; ".join(f"{k}: {', '.join(v)}" for k, v in answers.items()),
            "Usually harmless (CDN geography), occasionally not.",
        )
    else:
        report.add("tampering", "ok", "DNS answers look untampered",
                   f"example.com resolves to {', '.join(next(iter(answers.values())))}")


def check_nxdomain_hijack(report: FieldReport) -> None:
    """Does the network invent an address for names that do not exist?"""
    name = _nonexistent_name()
    result = _query(PUBLIC_RESOLVERS[0][1], name)
    if result is None:
        report.add("nxdomain", "info", "Could not test for NXDOMAIN hijacking")
        return

    addresses, rcode, _ = result
    if addresses:
        report.add(
            "nxdomain", "problem",
            "This network answers for names that do not exist",
            f"A random .invalid name resolved to {', '.join(addresses)}. It should "
            f"have been NXDOMAIN. Redirecting failed lookups to a search or ads "
            f"page breaks software that relies on a lookup failing.",
            "WiFiGuard passes NXDOMAIN through untouched, and encrypted upstream "
            "stops the network substituting its own answer.",
        )
    elif rcode == dnsmsg.RCODE_NXDOMAIN:
        report.add("nxdomain", "ok", "Names that do not exist correctly return NXDOMAIN")
    else:
        report.add("nxdomain", "warn",
                   f"A nonexistent name returned rcode {rcode} rather than NXDOMAIN")


def check_encrypted_dns(report: FieldReport) -> None:
    """Can DNS-over-HTTPS and DNS-over-TLS get out from here?"""
    from .resolver import DoHUpstream, ResolutionError

    working = []
    failures = []
    for url in DOH_ENDPOINTS:
        upstream = DoHUpstream(url, timeout=8.0)
        try:
            started = time.monotonic()
            response = upstream.resolve(dnsmsg.build_query("example.com", dnsmsg.TYPE_A))
            elapsed = (time.monotonic() - started) * 1000
            addresses = dnsmsg.answer_addresses(response)
            working.append((url, elapsed, addresses))
        except (ResolutionError, OSError, ssl.SSLError, dnsmsg.DNSFormatError) as exc:
            failures.append((url, str(exc)[:90]))
        finally:
            upstream.close()

    if working:
        best = min(working, key=lambda item: item[1])
        report.add(
            "doh", "ok",
            f"DNS-over-HTTPS works from this network ({len(working)} of {len(DOH_ENDPOINTS)} endpoints)",
            f"Fastest was {best[0]} at {best[1]:.0f}ms, answering "
            f"{', '.join(best[2]) if best[2] else 'no records'}.",
        )
    else:
        report.add(
            "doh", "problem",
            "DNS-over-HTTPS cannot get out from this network",
            "; ".join(f"{url.split('/')[2]}: {why}" for url, why in failures[:2]),
            "Something here is blocking or terminating encrypted DNS. WiFiGuard "
            "can fall back to plain DNS with `upstream.require_encrypted = false`, "
            "but on a network that does this, that is worth thinking about.",
        )

    # DoT is a separate port and is blocked far more often.
    reachable = []
    for _, address in PUBLIC_RESOLVERS[:2]:
        try:
            socket.create_connection((address, 853), timeout=4).close()
            reachable.append(address)
        except OSError:
            pass

    if reachable:
        report.add("dot", "ok", "DNS-over-TLS (port 853) is reachable",
                   f"Reached {', '.join(reachable)}.")
    else:
        report.add(
            "dot", "warn", "DNS-over-TLS (port 853) is blocked here",
            "No public resolver answered on 853.",
            "Not a problem by itself -- WiFiGuard prefers DoH on 443. It does mean "
            "a device using Android Private DNS on this network will fail closed.",
        )


def check_tls_interception(report: FieldReport) -> None:
    """Is something re-signing TLS on the way out?"""
    context = build_context()
    intercepted = []
    clean = []

    for url in DOH_ENDPOINTS[:2]:
        host = url.split("/")[2]
        try:
            with socket.create_connection((host, 443), timeout=6) as raw:
                with context.wrap_socket(raw, server_hostname=host) as tls:
                    certificate = tls.getpeercert()
                    der = tls.getpeercert(binary_form=True)
        except (OSError, ssl.SSLError) as exc:
            report.add("tls", "warn", f"Could not inspect TLS to {host}", str(exc)[:80])
            continue

        issuer = dict(x[0] for x in certificate.get("issuer", []))
        organisation = (issuer.get("organizationName") or "").strip()
        pin = spki_pin(der) if der else "?"

        if organisation.lower() not in PUBLIC_CA_ORGANISATIONS:
            intercepted.append((host, organisation, issuer.get("commonName", ""), pin))
        else:
            clean.append((host, organisation))

    if intercepted:
        host, organisation, common_name, pin = intercepted[0]
        report.add(
            "tls", "problem",
            "TLS on this network is being intercepted",
            f"The certificate for {host} was issued by \"{organisation}\" "
            f"({common_name}), which is not a public certificate authority. "
            f"Certificate verification still passes, because that CA is trusted by "
            f"this machine -- so nothing else would notice. The key presented is "
            f"{pin}.",
            "Pin the resolver's real key so WiFiGuard refuses to resolve rather "
            "than talking through the interception. Capture the pin from a network "
            "you trust: `wifiguard tls pin dns.quad9.net`.",
        )
    elif clean:
        report.add(
            "tls", "ok", "TLS is not being intercepted",
            f"Certificates come from public authorities ({clean[0][1]}).",
        )


def check_captive_portal(report: FieldReport) -> None:
    """Is a sign-in page standing between this machine and the internet?"""
    import http.client

    try:
        connection = http.client.HTTPConnection("captive.apple.com", 80, timeout=6)
        connection.request("GET", "/hotspot-detect.html",
                           headers={"User-Agent": "CaptiveNetworkSupport/1.0 wispr"})
        response = connection.getresponse()
        body = response.read(512).decode("utf-8", "replace")
        connection.close()
    except (OSError, http.client.HTTPException) as exc:
        report.add("portal", "warn", "Could not run the captive-portal check", str(exc)[:70])
        return

    if response.status in (301, 302, 303, 307) or "Success" not in body:
        report.add(
            "portal", "warn", "A captive portal is intercepting web traffic",
            f"The connectivity check returned HTTP {response.status} instead of the "
            f"expected success page.",
            "Sign in through a browser first. In gateway mode the laptop has to "
            "complete the portal before anything downstream of it can reach the "
            "internet.",
        )
    else:
        report.add("portal", "ok", "No captive portal in the way")


def check_existing_filtering(report: FieldReport) -> None:
    """Is anything already blocking ads on this network?"""
    probes = ("doubleclick.net", "googlesyndication.com")
    blocked = []
    for name in probes:
        result = _query(PUBLIC_RESOLVERS[0][1], name)
        if result is None:
            continue
        addresses, rcode, _ = result
        if rcode == dnsmsg.RCODE_NXDOMAIN or any(
            a in ("0.0.0.0", "127.0.0.1", "::") for a in addresses
        ):
            blocked.append(name)

    if blocked:
        report.add("existing", "info", "Something already filters ads here",
                   f"{', '.join(blocked)} did not resolve normally.")
    else:
        report.add(
            "existing", "info", "No ad filtering is in place on this network",
            f"{probes[0]} resolves normally, so ads and trackers are reaching every "
            f"device here.",
        )


def check_ipv6(report: FieldReport) -> None:
    """Is there a working IPv6 path? An unfiltered one bypasses IPv4 filtering."""
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sock.settimeout(4)
        sock.connect(("2620:fe::fe", 53))  # Quad9 over v6; connect() sends nothing.
        sock.close()
        has_v6 = True
    except OSError:
        has_v6 = False

    if has_v6:
        report.add(
            "ipv6", "warn", "This network has working IPv6",
            "A device can reach an IPv6 resolver directly, which goes around any "
            "filtering that only covers IPv4.",
            "In gateway mode WiFiGuard rejects client IPv6 by default so devices "
            "fall back to the filtered IPv4 path. Set hotspot.allow_ipv6 = true "
            "only once you have a filtered v6 path.",
        )
    else:
        report.add("ipv6", "ok", "No IPv6 path, so there is nothing to leak around")


def run(quick: bool = False) -> FieldReport:
    report = FieldReport()
    checks = [
        check_configured_resolver,
        check_dns_interception,
        check_answer_tampering,
        check_nxdomain_hijack,
        check_encrypted_dns,
        check_tls_interception,
        check_captive_portal,
        check_existing_filtering,
        check_ipv6,
    ]
    if quick:
        checks = checks[:5]

    for check in checks:
        try:
            check(report)
        except Exception as exc:  # noqa: BLE001 - a failed probe is a result too
            report.add(check.__name__, "warn", f"{check.__name__} could not complete",
                       f"{type(exc).__name__}: {exc}")
    return report
