"""DNS wire-format codec (RFC 1035 + EDNS0), standard library only.

Only as much of the protocol as a filtering forwarder needs: read the question,
walk the resource records well enough to find TTLs and CNAME targets, and build
synthetic answers for domains we block.  Record payloads other than A/AAAA/CNAME
are skipped by RDLENGTH rather than decoded.
"""

from __future__ import annotations

import ipaddress
import random
import struct
from typing import Iterator, NamedTuple

# Record types we name explicitly.
TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
TYPE_SOA = 6
TYPE_PTR = 12
TYPE_MX = 15
TYPE_TXT = 16
TYPE_AAAA = 28
TYPE_SRV = 33
TYPE_OPT = 41
TYPE_SVCB = 64
TYPE_HTTPS = 65
TYPE_ANY = 255

TYPE_NAMES = {
    TYPE_A: "A",
    TYPE_NS: "NS",
    TYPE_CNAME: "CNAME",
    TYPE_SOA: "SOA",
    TYPE_PTR: "PTR",
    TYPE_MX: "MX",
    TYPE_TXT: "TXT",
    TYPE_AAAA: "AAAA",
    TYPE_SRV: "SRV",
    TYPE_OPT: "OPT",
    TYPE_SVCB: "SVCB",
    TYPE_HTTPS: "HTTPS",
    TYPE_ANY: "ANY",
}

CLASS_IN = 1

RCODE_NOERROR = 0
RCODE_FORMERR = 1
RCODE_SERVFAIL = 2
RCODE_NXDOMAIN = 3
RCODE_NOTIMP = 4
RCODE_REFUSED = 5

HEADER_LEN = 12
MAX_LABEL_LEN = 63
MAX_NAME_LEN = 255

# A response we synthesise never grows past this, so it is always safe to send
# over UDP without truncation.
SAFE_UDP_PAYLOAD = 1232


class DNSFormatError(ValueError):
    """The message is malformed and cannot be parsed."""


def type_name(rtype: int) -> str:
    return TYPE_NAMES.get(rtype, f"TYPE{rtype}")


class Header(NamedTuple):
    id: int
    flags: int
    qdcount: int
    ancount: int
    nscount: int
    arcount: int

    @property
    def is_response(self) -> bool:
        return bool(self.flags & 0x8000)

    @property
    def opcode(self) -> int:
        return (self.flags >> 11) & 0x0F

    @property
    def truncated(self) -> bool:
        return bool(self.flags & 0x0200)

    @property
    def recursion_desired(self) -> bool:
        return bool(self.flags & 0x0100)

    @property
    def rcode(self) -> int:
        return self.flags & 0x000F


class Question(NamedTuple):
    name: str
    qtype: int
    qclass: int


class ResourceRecord(NamedTuple):
    name: str
    rtype: int
    rclass: int
    ttl: int
    rdata: bytes
    # Offset of the 4-byte TTL field within the message, so TTLs can be
    # rewritten in place when a cached response is replayed.
    ttl_offset: int


def parse_header(data: bytes) -> Header:
    if len(data) < HEADER_LEN:
        raise DNSFormatError(f"message shorter than a DNS header ({len(data)} bytes)")
    return Header(*struct.unpack("!6H", data[:HEADER_LEN]))


def read_name(data: bytes, offset: int) -> tuple[str, int]:
    """Decode a possibly-compressed name.

    Returns the lowercased dotted name and the offset just past the name *as it
    appears at `offset`* -- following a compression pointer does not advance the
    caller's cursor beyond the pointer itself.
    """
    labels: list[str] = []
    total = 0
    jumped = False
    cursor = offset
    end_of_name = -1
    # Every jump must move strictly backwards, so the number of jumps is bounded
    # by the message length; cap it anyway to keep malformed input cheap.
    jumps = 0

    while True:
        if cursor >= len(data):
            raise DNSFormatError("name runs past the end of the message")
        length = data[cursor]

        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(data):
                raise DNSFormatError("truncated compression pointer")
            pointer = struct.unpack("!H", data[cursor : cursor + 2])[0] & 0x3FFF
            if not jumped:
                end_of_name = cursor + 2
                jumped = True
            if pointer >= cursor:
                raise DNSFormatError("compression pointer does not point backwards")
            jumps += 1
            if jumps > 64:
                raise DNSFormatError("too many compression pointers")
            cursor = pointer
            continue

        if length & 0xC0:
            raise DNSFormatError(f"reserved label type 0x{length:02x}")

        cursor += 1
        if length == 0:
            if not jumped:
                end_of_name = cursor
            break

        if cursor + length > len(data):
            raise DNSFormatError("label runs past the end of the message")
        total += length + 1
        if total > MAX_NAME_LEN:
            raise DNSFormatError("name exceeds 255 bytes")
        labels.append(data[cursor : cursor + length].decode("latin-1").lower())
        cursor += length

    return ".".join(labels), end_of_name


def encode_name(name: str) -> bytes:
    """Encode a dotted name into wire format, without compression."""
    name = name.strip(".")
    if not name:
        return b"\x00"
    out = bytearray()
    for label in name.split("."):
        raw = label.encode("idna") if not label.isascii() else label.encode("ascii")
        if not raw:
            raise ValueError(f"empty label in name {name!r}")
        if len(raw) > MAX_LABEL_LEN:
            raise ValueError(f"label longer than 63 bytes in name {name!r}")
        out.append(len(raw))
        out += raw
    out.append(0)
    if len(out) > MAX_NAME_LEN:
        raise ValueError(f"name longer than 255 bytes: {name!r}")
    return bytes(out)


def parse_questions(data: bytes) -> tuple[list[Question], int]:
    """Parse the question section, returning the questions and the offset after."""
    header = parse_header(data)
    offset = HEADER_LEN
    questions = []
    for _ in range(header.qdcount):
        name, offset = read_name(data, offset)
        if offset + 4 > len(data):
            raise DNSFormatError("truncated question record")
        qtype, qclass = struct.unpack("!HH", data[offset : offset + 4])
        offset += 4
        questions.append(Question(name, qtype, qclass))
    return questions, offset


def first_question(data: bytes) -> Question | None:
    """The question a filtering decision is made against, or None if absent."""
    questions, _ = parse_questions(data)
    return questions[0] if questions else None


def iter_records(data: bytes) -> Iterator[ResourceRecord]:
    """Yield every RR in the answer, authority and additional sections."""
    header = parse_header(data)
    _, offset = parse_questions(data)
    count = header.ancount + header.nscount + header.arcount

    for _ in range(count):
        name, offset = read_name(data, offset)
        if offset + 10 > len(data):
            raise DNSFormatError("truncated resource record header")
        rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset : offset + 10])
        ttl_offset = offset + 4
        offset += 10
        if offset + rdlength > len(data):
            raise DNSFormatError("resource record data runs past the end of the message")
        rdata = data[offset : offset + rdlength]
        offset += rdlength
        yield ResourceRecord(name, rtype, rclass, ttl, rdata, ttl_offset)


def message_ttl(data: bytes, default: int = 0) -> int:
    """The smallest TTL in the message -- how long the whole answer is valid.

    OPT records are skipped: their "TTL" field carries extended flags, not a
    lifetime.
    """
    ttls = [rr.ttl for rr in iter_records(data) if rr.rtype != TYPE_OPT]
    return min(ttls) if ttls else default


def with_ttls_reduced(data: bytes, elapsed: int) -> bytes:
    """Return the message with every TTL reduced by `elapsed` seconds.

    Cached answers must age: replaying the original TTLs would pin a record in
    downstream resolvers forever.  TTLs floor at 0 and OPT records are left
    alone.
    """
    if elapsed <= 0:
        return data
    out = bytearray(data)
    for rr in iter_records(data):
        if rr.rtype == TYPE_OPT:
            continue
        struct.pack_into("!I", out, rr.ttl_offset, max(0, rr.ttl - elapsed))
    return bytes(out)


def cname_chain(data: bytes) -> list[str]:
    """CNAME targets in the answer section.

    Trackers hide behind CNAMEs pointing into a first-party subdomain, so the
    filter checks these targets as well as the name that was asked for.
    """
    targets = []
    header = parse_header(data)
    for index, rr in enumerate(iter_records(data)):
        if index >= header.ancount:
            break
        if rr.rtype == TYPE_CNAME and rr.rclass == CLASS_IN:
            try:
                target, _ = read_name(data, rr.ttl_offset + 6)
            except DNSFormatError:
                continue
            if target:
                targets.append(target)
    return targets


def answer_addresses(data: bytes) -> list[str]:
    """A/AAAA addresses in the answer section, as strings."""
    addresses = []
    header = parse_header(data)
    for index, rr in enumerate(iter_records(data)):
        if index >= header.ancount:
            break
        if rr.rclass != CLASS_IN:
            continue
        if rr.rtype == TYPE_A and len(rr.rdata) == 4:
            addresses.append(str(ipaddress.IPv4Address(rr.rdata)))
        elif rr.rtype == TYPE_AAAA and len(rr.rdata) == 16:
            addresses.append(str(ipaddress.IPv6Address(rr.rdata)))
    return addresses


def _edns_payload_size(data: bytes) -> int | None:
    """The client's advertised EDNS0 buffer size, or None if it sent no OPT."""
    try:
        for rr in iter_records(data):
            if rr.rtype == TYPE_OPT:
                # For OPT, the CLASS field holds the requestor's payload size.
                return rr.rclass
    except DNSFormatError:
        return None
    return None


#: In an OPT record the 32-bit "TTL" field carries extended rcode, version and
#: flags. The top flag bit is DO -- "DNSSEC OK" -- by which a client says it
#: wants signatures and intends to validate them itself.
EDNS_DO_BIT = 0x8000


def wants_dnssec(data: bytes) -> bool:
    """Whether the client set the DNSSEC OK bit.

    A validating client that asks for signatures and is handed an unsigned
    answer treats it as an attack and fails the lookup, so this has to be
    honoured rather than quietly dropped.
    """
    try:
        for record in iter_records(data):
            if record.rtype == TYPE_OPT:
                return bool(record.ttl & EDNS_DO_BIT)
    except DNSFormatError:
        return False
    return False


def checking_disabled(data: bytes) -> bool:
    """Whether the client set CD, meaning it will validate for itself."""
    try:
        return bool(parse_header(data).flags & 0x0010)
    except DNSFormatError:
        return False


def _opt_record(payload_size: int) -> bytes:
    # Root name, type OPT, class = payload size, extended rcode/version/flags 0,
    # no options.  The DO bit is deliberately cleared: we do not sign answers.
    return struct.pack("!BHHIH", 0, TYPE_OPT, payload_size, 0, 0)


def _response_skeleton(query: bytes, rcode: int, ancount: int) -> tuple[bytearray, bytes, bytes]:
    """Header and question bytes shared by every synthetic response."""
    header = parse_header(query)
    _, question_end = parse_questions(query)
    question = query[HEADER_LEN:question_end]

    flags = 0x8000  # QR: this is a response.
    flags |= header.flags & 0x7800  # Preserve OPCODE.
    flags |= header.flags & 0x0100  # Preserve RD.
    flags |= 0x0080  # RA: we do provide recursion.
    flags |= header.flags & 0x0010  # Preserve CD.
    flags |= rcode & 0x000F

    client_payload = _edns_payload_size(query)
    additional = b""
    arcount = 0
    if client_payload is not None:
        additional = _opt_record(min(max(client_payload, 512), SAFE_UDP_PAYLOAD))
        arcount = 1

    out = bytearray(
        struct.pack("!6H", header.id, flags, header.qdcount, ancount, 0, arcount)
    )
    return out, question, additional


def build_error_response(query: bytes, rcode: int) -> bytes:
    """An answer carrying only a status code (NXDOMAIN, REFUSED, SERVFAIL...)."""
    out, question, additional = _response_skeleton(query, rcode, ancount=0)
    out += question
    out += additional
    return bytes(out)


def build_address_response(
    query: bytes,
    qtype: int,
    address: str | None,
    ttl: int,
) -> bytes:
    """An answer pointing the name at `address` (or an empty NOERROR if None).

    `address` must match `qtype`: an IPv4 literal for A, IPv6 for AAAA.  When it
    is None -- the qtype has no sinkhole address, e.g. an AAAA query while only
    an IPv4 sinkhole is configured -- the result is NOERROR with no records,
    which stops the client from retrying elsewhere.
    """
    if address is None:
        out, question, additional = _response_skeleton(query, RCODE_NOERROR, ancount=0)
        out += question
        out += additional
        return bytes(out)

    packed = ipaddress.ip_address(address).packed
    out, question, additional = _response_skeleton(query, RCODE_NOERROR, ancount=1)
    out += question
    # 0xC00C is a compression pointer to offset 12, where the question's name
    # begins -- the question section always starts immediately after the header.
    out += struct.pack("!HHHIH", 0xC00C, qtype, CLASS_IN, ttl, len(packed))
    out += packed
    out += additional
    return bytes(out)


def build_query(name: str, qtype: int, want_edns: bool = True) -> bytes:
    """A recursive query for `name`, used for upstream lookups and health checks."""
    flags = 0x0100  # RD
    arcount = 1 if want_edns else 0
    out = bytearray(struct.pack("!6H", random.getrandbits(16), flags, 1, 0, 0, arcount))
    out += encode_name(name)
    out += struct.pack("!HH", qtype, CLASS_IN)
    if want_edns:
        out += _opt_record(SAFE_UDP_PAYLOAD)
    return bytes(out)


def set_message_id(data: bytes, message_id: int) -> bytes:
    """Rewrite the transaction ID, which upstream transports reassign."""
    if len(data) < 2:
        raise DNSFormatError("message too short to carry an ID")
    return struct.pack("!H", message_id & 0xFFFF) + data[2:]
