"""The far side of the uplink: a stub internet for the testbed.

Runs inside the `internet` namespace and provides everything WiFiGuard would
reach across the wire:

* a plain DNS resolver on port 53,
* a DNS-over-HTTPS endpoint on port 443, with a real certificate that WiFiGuard
  verifies properly (no verification is disabled anywhere for this test),
* a TCP service on port 80, so NAT can be proved rather than assumed.

Every query is counted and recorded, which is how the test shows that blocked
and cached names genuinely never left the gateway.
"""

from __future__ import annotations

import json
import os
import socket
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from wifiguard import dnsmsg  # noqa: E402

STATE_PATH = Path(os.environ.get("TESTBED_STATE", "/tmp/wgt-upstream.json"))

#: Names the stub answers, and with what. Anything else gets NXDOMAIN, which
#: makes an unexpected lookup visible rather than silently succeeding.
ZONE = {
    "example.com": "93.184.216.34",
    "cached.example.com": "93.184.216.35",
    "burst.example.com": "93.184.216.36",
    "allowed.ads.example.com": "93.184.216.37",
    "forcesafesearch.google.com": "216.239.38.120",
    "www.google.com": "142.250.190.4",
    "service.example.net": "10.200.0.2",
    # Distinct names per test phase. Reusing one name would let a cached
    # answer stand in for a live lookup and hide whichever transport is
    # actually being exercised.
    "doh-probe.example.com": "93.184.216.40",
    "pin-ok.example.com": "93.184.216.41",
    "pin-bad.example.com": "93.184.216.42",
    "uplink-probe.example.com": "93.184.216.43",
    "signed.example.com": "93.184.216.44",
    # A name devices depend on, deliberately also put in the testbed's
    # blocklist so protection can be observed rather than assumed.
    "pool.ntp.org": "162.159.200.１".replace("１", "1"),
    "ocsp.digicert.com": "93.184.216.46",
    "connectivitycheck.gstatic.com": "93.184.216.47",
}


class Counters:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.udp = 0
        self.doh = 0
        self.tcp_connections = 0
        self.names: list[str] = []
        self.dnssec_requests = 0
        self.dnssec_names: list[str] = []

    def record(self, transport: str, name: str, dnssec: bool = False) -> None:
        with self.lock:
            if transport == "udp":
                self.udp += 1
            elif transport == "doh":
                self.doh += 1
            self.names.append(name)
            if dnssec:
                self.dnssec_requests += 1
                self.dnssec_names.append(name)
            self._write()

    def record_tcp(self) -> None:
        with self.lock:
            self.tcp_connections += 1
            self._write()

    def _write(self) -> None:
        STATE_PATH.write_text(
            json.dumps(
                {
                    "udp": self.udp,
                    "doh": self.doh,
                    "total_dns": self.udp + self.doh,
                    "tcp_connections": self.tcp_connections,
                    "names": self.names[-200:],
                    "dnssec_requests": self.dnssec_requests,
                    "dnssec_names": self.dnssec_names[-50:],
                }
            )
        )


COUNTERS = Counters()


def answer(query: bytes, transport: str) -> bytes | None:
    try:
        question = dnsmsg.first_question(query)
    except dnsmsg.DNSFormatError:
        return None
    if question is None:
        return None

    # Whether the resolver passed the client's DNSSEC request through.
    COUNTERS.record(transport, question.name, dnsmsg.wants_dnssec(query))

    address = ZONE.get(question.name)
    if question.qtype == dnsmsg.TYPE_A and address:
        return dnsmsg.build_address_response(query, dnsmsg.TYPE_A, address, 120)
    if question.qtype == dnsmsg.TYPE_AAAA and address:
        # The zone is IPv4-only; an empty NOERROR is the correct answer.
        return dnsmsg.build_address_response(query, dnsmsg.TYPE_AAAA, None, 120)
    return dnsmsg.build_error_response(query, dnsmsg.RCODE_NXDOMAIN)


def serve_udp(address: str) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((address, 53))
    while True:
        try:
            payload, peer = sock.recvfrom(4096)
        except OSError:
            return
        reply = answer(payload, "udp")
        if reply:
            try:
                sock.sendto(reply, peer)
            except OSError:
                pass


def serve_tcp_service(address: str) -> None:
    """A stand-in for any internet service, used to prove NAT works."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", 80))
    sock.listen(16)
    while True:
        try:
            connection, _ = sock.accept()
        except OSError:
            return
        COUNTERS.record_tcp()
        try:
            connection.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 6\r\n\r\nreally")
        except OSError:
            pass
        finally:
            connection.close()


class DoHHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # noqa: D102 - silence the default logging
        pass

    def do_POST(self):  # noqa: N802
        if not self.path.startswith("/dns-query"):
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        reply = answer(self.rfile.read(length), "doh") or b""
        self.send_response(200)
        self.send_header("Content-Type", "application/dns-message")
        self.send_header("Content-Length", str(len(reply)))
        self.end_headers()
        self.wfile.write(reply)


def serve_doh(address: str, certfile: str, keyfile: str) -> None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile, keyfile)
    server = ThreadingHTTPServer(("", 443), DoHHandler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


def main() -> None:
    address = sys.argv[1] if len(sys.argv) > 1 else "10.200.0.2"
    certfile = sys.argv[2] if len(sys.argv) > 2 else ""
    keyfile = sys.argv[3] if len(sys.argv) > 3 else ""

    threads = [
        threading.Thread(target=serve_udp, args=(address,), daemon=True),
        threading.Thread(target=serve_tcp_service, args=(address,), daemon=True),
    ]
    if certfile and keyfile:
        threads.append(
            threading.Thread(target=serve_doh, args=(address, certfile, keyfile), daemon=True)
        )

    for thread in threads:
        thread.start()

    COUNTERS._write()
    print(f"stub internet up on {address} (dns:53, doh:443, tcp:80)", flush=True)
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
