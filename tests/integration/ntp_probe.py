"""Ask a server for the time, the way a device with no clock would.

Written straight from RFC 5905's packet layout rather than reusing WiFiGuard's
own encoder, so a shared misunderstanding of the format cannot pass.
"""

import json
import socket
import struct
import sys
import time

NTP_EPOCH_OFFSET = 2_208_988_800


def main() -> int:
    server = sys.argv[1] if len(sys.argv) > 1 else "10.42.7.1"

    packet = bytearray(48)
    packet[0] = (4 << 3) | 3  # Version 4, mode 3 (client).
    sent = time.time()
    seconds = int(sent) + NTP_EPOCH_OFFSET
    fraction = int((sent - int(sent)) * (1 << 32))
    struct.pack_into("!II", packet, 40, seconds, fraction)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    try:
        sock.sendto(bytes(packet), (server, 123))
        reply, _ = sock.recvfrom(1024)
    except OSError as exc:
        print(json.dumps({"ok": False, "error": f"{type(exc).__name__}: {exc}"}))
        return 1
    finally:
        sock.close()

    if len(reply) < 48:
        print(json.dumps({"ok": False, "error": f"short reply ({len(reply)} bytes)"}))
        return 1

    received = time.time()
    transmit_seconds, transmit_fraction = struct.unpack_from("!II", reply, 40)
    server_time = (transmit_seconds - NTP_EPOCH_OFFSET) + transmit_fraction / (1 << 32)

    print(json.dumps({
        "ok": True,
        "mode": reply[0] & 0x07,
        "version": (reply[0] >> 3) & 0x07,
        "stratum": reply[1],
        "server_time": server_time,
        "offset": server_time - received,
    }))
    return 0


if __name__ == "__main__":
    sys.exit(main())
