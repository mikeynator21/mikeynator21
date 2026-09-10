"""Send and listen for multicast, to test the discovery reflector.

Deliberately protocol-agnostic: it sends and receives raw payloads on a
multicast group. Whether a packet crosses between two networks is then a plain
observation, with no mDNS parsing in the way to confuse the result.
"""

from __future__ import annotations

import json
import socket
import struct
import sys
import time


def make_socket(group: str, port: int, interface: str) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode() + b"\0")
    sock.bind(("", port))

    index = socket.if_nametoindex(interface)
    membership = struct.pack("4s4si", socket.inet_aton(group), b"\x00" * 4, index)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, membership)
    # mDNS requires 255, and receivers are entitled to check it.
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
    return sock


def listen(group: str, port: int, interface: str, seconds: float, expect: bytes) -> int:
    sock = make_socket(group, port, interface)
    sock.settimeout(0.5)
    deadline = time.monotonic() + seconds
    heard = []

    while time.monotonic() < deadline:
        try:
            payload, sender = sock.recvfrom(9000)
        except socket.timeout:
            continue
        except OSError as exc:
            print(json.dumps({"error": str(exc)}))
            return 1
        heard.append({"from": sender[0], "bytes": len(payload),
                      "match": expect in payload})
        if expect in payload:
            break

    sock.close()
    print(json.dumps({
        "received": len(heard),
        "matched": any(item["match"] for item in heard),
        "senders": sorted({item["from"] for item in heard}),
    }))
    return 0


def send(group: str, port: int, interface: str, payload: bytes, count: int) -> int:
    sock = make_socket(group, port, interface)
    for _ in range(count):
        sock.sendto(payload, (group, port))
        time.sleep(0.2)
    sock.close()
    print(json.dumps({"sent": count}))
    return 0


def main() -> int:
    mode = sys.argv[1]
    group = sys.argv[2]
    port = int(sys.argv[3])
    interface = sys.argv[4]

    if mode == "listen":
        return listen(group, port, interface, float(sys.argv[5]), sys.argv[6].encode())
    if mode == "send":
        return send(group, port, interface, sys.argv[5].encode(), int(sys.argv[6]))
    print(json.dumps({"error": f"unknown mode {mode!r}"}))
    return 2


if __name__ == "__main__":
    sys.exit(main())
