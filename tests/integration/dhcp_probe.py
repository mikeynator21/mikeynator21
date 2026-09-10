"""Read the DHCP options a server offers, without configuring anything.

Sends a DISCOVER asking for the options a real device asks for, and reports
what came back. Separate from dhcp_client.py so a scenario can inspect the
offer without disturbing an interface that is already configured.
"""

import json
import random
import socket
import struct
import sys

MAGIC = b"\x63\x82\x53\x63"


def main() -> int:
    interface = sys.argv[1] if len(sys.argv) > 1 else "eth0"
    with open(f"/sys/class/net/{interface}/address") as handle:
        mac = bytes.fromhex(handle.read().strip().replace(":", ""))
    xid = bytes(random.getrandbits(8) for _ in range(4))

    packet = bytearray()
    packet += struct.pack("!BBBB", 1, 1, 6, 0)
    packet += xid
    packet += struct.pack("!HH", 0, 0x8000)
    packet += b"\x00" * 16
    packet += mac + b"\x00" * 10
    packet += b"\x00" * 192
    packet += MAGIC
    packet += bytes([53, 1, 1])                        # DISCOVER
    packet += bytes([12, 6]) + b"sensor"               # hostname
    # The options a device that needs a clock and a working MTU asks for.
    packet += bytes([55, 7, 1, 3, 6, 15, 26, 42, 119])
    packet += bytes([255])

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode() + b"\0")
    sock.bind(("", 68))
    sock.settimeout(6)

    try:
        sock.sendto(bytes(packet), ("255.255.255.255", 67))
        while True:
            reply, _ = sock.recvfrom(2048)
            if len(reply) >= 240 and reply[236:240] == MAGIC and reply[4:8] == xid:
                break
    except OSError as exc:
        print(json.dumps({"error": f"{type(exc).__name__}: {exc}"}))
        return 1
    finally:
        sock.close()

    options = {}
    cursor = 240
    while cursor < len(reply):
        code = reply[cursor]
        if code == 255:
            break
        if code == 0:
            cursor += 1
            continue
        length = reply[cursor + 1]
        options[code] = reply[cursor + 2 : cursor + 2 + length]
        cursor += 2 + length

    def addresses(raw):
        return [socket.inet_ntoa(raw[i : i + 4]) for i in range(0, len(raw) - 3, 4)]

    def labels(raw):
        names, cursor, current = [], 0, []
        while cursor < len(raw):
            size = raw[cursor]
            cursor += 1
            if size == 0:
                if current:
                    names.append(".".join(current))
                current = []
                continue
            current.append(raw[cursor : cursor + size].decode("ascii", "replace"))
            cursor += size
        return names

    print(json.dumps({
        "address": socket.inet_ntoa(reply[16:20]),
        "dns": addresses(options.get(6, b"")),
        "router": addresses(options.get(3, b"")),
        "ntp": addresses(options.get(42, b"")),
        "mtu": struct.unpack("!H", options[26])[0] if 26 in options else 0,
        "domain": options.get(15, b"").decode("ascii", "replace"),
        "domain_search": labels(options.get(119, b"")),
    }))
    return 0


if __name__ == "__main__":
    sys.exit(main())
