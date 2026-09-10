"""A small SNTP server, so devices on the network can set their clocks.

A device with the wrong time rejects every TLS certificate as not yet valid,
and reports nothing useful about why. Cheap IoT hardware has no battery-backed
clock at all, so it is in exactly that state every time the power blinks.

DHCP can hand out an NTP server, but option 42 carries IPv4 addresses rather
than names -- there is no way to say "use pool.ntp.org". Resolving the pool at
start-up and handing out whatever it returned is fragile: those addresses
rotate, and a device may keep a lease for days.

Serving time from the gateway solves it properly. Clients get a stable address
that is always reachable, it keeps working while the uplink is down, and time
still arrives even when a blocklist somewhere is swallowing NTP domains.

This answers from the host's own clock, so it is only as good as the host's
sync -- which is the normal arrangement for a LAN time server, and is announced
honestly in the stratum field.
"""

from __future__ import annotations

import logging
import socket
import struct
import threading
import time

log = logging.getLogger(__name__)

NTP_PORT = 123
#: Seconds between 1900-01-01 (the NTP epoch) and 1970-01-01 (the Unix epoch).
NTP_EPOCH_OFFSET = 2_208_988_800
PACKET_SIZE = 48

MODE_CLIENT = 3
MODE_SERVER = 4

#: Refuse to serve if the host clock is obviously unset. Handing out a wrong
#: time is worse than handing out none: the client would trust it and then fail
#: every certificate check with no idea why.
MINIMUM_PLAUSIBLE_TIME = 1_735_689_600  # 2025-01-01


def to_ntp_timestamp(unix_time: float) -> bytes:
    """Encode a Unix timestamp as a 64-bit NTP timestamp."""
    seconds = int(unix_time) + NTP_EPOCH_OFFSET
    fraction = int((unix_time - int(unix_time)) * (1 << 32))
    return struct.pack("!II", seconds & 0xFFFFFFFF, fraction & 0xFFFFFFFF)


def from_ntp_timestamp(raw: bytes) -> float:
    seconds, fraction = struct.unpack("!II", raw[:8])
    if seconds == 0 and fraction == 0:
        return 0.0
    return (seconds - NTP_EPOCH_OFFSET) + fraction / (1 << 32)


class TimeServer:
    """Answers SNTP requests from the host clock."""

    def __init__(
        self,
        address: str,
        interface: str = "",
        *,
        stratum: int = 3,
        reference: bytes = b"LOCL",
    ) -> None:
        self.address = address
        self.interface = interface
        self.stratum = stratum
        self.reference = reference[:4].ljust(4, b"\0")
        self.served = 0
        self.refused = 0

        self._socket: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    @property
    def clock_is_plausible(self) -> bool:
        return time.time() > MINIMUM_PLAUSIBLE_TIME

    def start(self) -> None:
        if not self.clock_is_plausible:
            log.warning(
                "not starting the time server: this host's own clock reads %s, "
                "which cannot be right. Fix the host's time first -- serving a "
                "wrong time to clients is worse than serving none.",
                time.strftime("%Y-%m-%d %H:%M:%S"),
            )
            return

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if self.interface:
            try:
                sock.setsockopt(
                    socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                    self.interface.encode() + b"\0",
                )
            except (AttributeError, OSError) as exc:
                log.debug("could not bind the time server to %s: %s", self.interface, exc)
        try:
            sock.bind((self.address, NTP_PORT))
        except OSError as exc:
            sock.close()
            log.warning(
                "could not start the time server on %s:%d (%s). Devices without a "
                "clock will have to reach an NTP server on the internet instead.",
                self.address, NTP_PORT, exc,
            )
            return

        sock.settimeout(1.0)
        self._socket = sock
        self._stop.clear()
        self._thread = threading.Thread(target=self._serve, name="ntp", daemon=True)
        self._thread.start()
        log.info("time server on %s:%d (stratum %d)", self.address, NTP_PORT, self.stratum)

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=3)
            self._thread = None
        if self._socket is not None:
            self._socket.close()
            self._socket = None

    @property
    def running(self) -> bool:
        return self._socket is not None

    def _serve(self) -> None:
        assert self._socket is not None
        while not self._stop.is_set():
            try:
                payload, peer = self._socket.recvfrom(1024)
            except socket.timeout:
                continue
            except OSError:
                return

            received_at = time.time()
            reply = self.build_reply(payload, received_at)
            if reply is None:
                self.refused += 1
                continue

            try:
                self._socket.sendto(reply, peer)
                self.served += 1
            except OSError as exc:
                log.debug("could not answer an NTP request from %s: %s", peer[0], exc)

    def build_reply(self, payload: bytes, received_at: float) -> bytes | None:
        """Build an SNTP response, or None if the request is not one."""
        if len(payload) < PACKET_SIZE:
            return None

        first = payload[0]
        version = (first >> 3) & 0x07
        mode = first & 0x07

        # Only answer client requests. Answering mode 6 or 7 is how NTP servers
        # get recruited into amplification attacks.
        if mode != MODE_CLIENT:
            return None
        if not 1 <= version <= 4:
            return None
        if not self.clock_is_plausible:
            return None

        # The client's transmit timestamp becomes our originate timestamp; that
        # is what lets it work out the round trip and correct for it.
        originate = payload[40:48]

        packet = bytearray(PACKET_SIZE)
        packet[0] = (0 << 6) | (version << 3) | MODE_SERVER  # LI = 0, no warning
        packet[1] = self.stratum
        packet[2] = payload[2] if payload[2] else 6          # Echo the poll interval.
        packet[3] = 0xEC                                     # Precision: ~2^-20 s.
        struct.pack_into("!I", packet, 4, 0)                 # Root delay.
        struct.pack_into("!I", packet, 8, 0x00000100)        # Root dispersion.
        packet[12:16] = self.reference

        # Reference time: when this server last considered its clock good. The
        # host keeps itself in sync, so "recently" is the honest answer.
        packet[16:24] = to_ntp_timestamp(received_at - 1)
        packet[24:32] = originate
        packet[32:40] = to_ntp_timestamp(received_at)
        packet[40:48] = to_ntp_timestamp(time.time())
        return bytes(packet)

    def status(self) -> dict[str, object]:
        return {
            "running": self.running,
            "address": self.address,
            "stratum": self.stratum,
            "requests_served": self.served,
            "requests_refused": self.refused,
            "clock_plausible": self.clock_is_plausible,
        }
