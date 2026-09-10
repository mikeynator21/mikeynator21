"""QR code generation (ISO/IEC 18004), standard library only.

Onboarding a phone means getting a ~400-byte WireGuard config onto it, and
scanning a code is the only pleasant way to do that. Pulling in a QR library
for it would undo the "installs anywhere with just Python" property, so the
encoder lives here.

Byte mode only, versions 1-20, which tops out around 850 bytes -- comfortably
more than any WireGuard profile. The version/block tables are cross-checked
against the matrix geometry in the test suite, so a mistranscribed row fails
loudly rather than producing a code that will not scan.
"""

from __future__ import annotations

import zlib
from dataclasses import dataclass
from typing import Iterable, Literal

ECLevel = Literal["L", "M", "Q", "H"]

# Error-correction level as encoded in the format information field.
_EC_INDICATOR = {"L": 0b01, "M": 0b00, "Q": 0b11, "H": 0b10}

# (ec_codewords_per_block, (blocks, data_codewords), (blocks, data_codewords))
# The second group is empty for versions where every block is the same size.
_BLOCK_TABLE: dict[tuple[int, str], tuple[int, tuple[int, int], tuple[int, int]]] = {
    (1, "L"): (7, (1, 19), (0, 0)),
    (1, "M"): (10, (1, 16), (0, 0)),
    (1, "Q"): (13, (1, 13), (0, 0)),
    (1, "H"): (17, (1, 9), (0, 0)),
    (2, "L"): (10, (1, 34), (0, 0)),
    (2, "M"): (16, (1, 28), (0, 0)),
    (2, "Q"): (22, (1, 22), (0, 0)),
    (2, "H"): (28, (1, 16), (0, 0)),
    (3, "L"): (15, (1, 55), (0, 0)),
    (3, "M"): (26, (1, 44), (0, 0)),
    (3, "Q"): (18, (2, 17), (0, 0)),
    (3, "H"): (22, (2, 13), (0, 0)),
    (4, "L"): (20, (1, 80), (0, 0)),
    (4, "M"): (18, (2, 32), (0, 0)),
    (4, "Q"): (26, (2, 24), (0, 0)),
    (4, "H"): (16, (4, 9), (0, 0)),
    (5, "L"): (26, (1, 108), (0, 0)),
    (5, "M"): (24, (2, 43), (0, 0)),
    (5, "Q"): (18, (2, 15), (2, 16)),
    (5, "H"): (22, (2, 11), (2, 12)),
    (6, "L"): (18, (2, 68), (0, 0)),
    (6, "M"): (16, (4, 27), (0, 0)),
    (6, "Q"): (24, (4, 19), (0, 0)),
    (6, "H"): (28, (4, 15), (0, 0)),
    (7, "L"): (20, (2, 78), (0, 0)),
    (7, "M"): (18, (4, 31), (0, 0)),
    (7, "Q"): (18, (2, 14), (4, 15)),
    (7, "H"): (26, (4, 13), (1, 14)),
    (8, "L"): (24, (2, 97), (0, 0)),
    (8, "M"): (22, (2, 38), (2, 39)),
    (8, "Q"): (22, (4, 18), (2, 19)),
    (8, "H"): (26, (4, 14), (2, 15)),
    (9, "L"): (30, (2, 116), (0, 0)),
    (9, "M"): (22, (3, 36), (2, 37)),
    (9, "Q"): (20, (4, 16), (4, 17)),
    (9, "H"): (24, (4, 12), (4, 13)),
    (10, "L"): (18, (2, 68), (2, 69)),
    (10, "M"): (26, (4, 43), (1, 44)),
    (10, "Q"): (24, (6, 19), (2, 20)),
    (10, "H"): (28, (6, 15), (2, 16)),
    (11, "L"): (20, (4, 81), (0, 0)),
    (11, "M"): (30, (1, 50), (4, 51)),
    (11, "Q"): (28, (4, 22), (4, 23)),
    (11, "H"): (24, (3, 12), (8, 13)),
    (12, "L"): (24, (2, 92), (2, 93)),
    (12, "M"): (22, (6, 36), (2, 37)),
    (12, "Q"): (26, (4, 20), (6, 21)),
    (12, "H"): (28, (7, 14), (4, 15)),
    (13, "L"): (26, (4, 107), (0, 0)),
    (13, "M"): (22, (8, 37), (1, 38)),
    (13, "Q"): (24, (8, 20), (4, 21)),
    (13, "H"): (22, (12, 11), (4, 12)),
    (14, "L"): (30, (3, 115), (1, 116)),
    (14, "M"): (24, (4, 40), (5, 41)),
    (14, "Q"): (20, (11, 16), (5, 17)),
    (14, "H"): (24, (11, 12), (5, 13)),
    (15, "L"): (22, (5, 87), (1, 88)),
    (15, "M"): (24, (5, 41), (5, 42)),
    (15, "Q"): (30, (5, 24), (7, 25)),
    (15, "H"): (24, (11, 12), (7, 13)),
    (16, "L"): (24, (5, 98), (1, 99)),
    (16, "M"): (28, (7, 45), (3, 46)),
    (16, "Q"): (24, (15, 19), (2, 20)),
    (16, "H"): (30, (3, 15), (13, 16)),
    (17, "L"): (28, (1, 107), (5, 108)),
    (17, "M"): (28, (10, 46), (1, 47)),
    (17, "Q"): (28, (1, 22), (15, 23)),
    (17, "H"): (28, (2, 14), (17, 15)),
    (18, "L"): (30, (5, 120), (1, 121)),
    (18, "M"): (26, (9, 43), (4, 44)),
    (18, "Q"): (28, (17, 22), (1, 23)),
    (18, "H"): (28, (2, 14), (19, 15)),
    (19, "L"): (28, (3, 113), (4, 114)),
    (19, "M"): (26, (3, 44), (11, 45)),
    (19, "Q"): (26, (17, 21), (4, 22)),
    (19, "H"): (26, (9, 13), (16, 14)),
    (20, "L"): (28, (3, 107), (5, 108)),
    (20, "M"): (26, (3, 41), (13, 42)),
    (20, "Q"): (30, (15, 24), (5, 25)),
    (20, "H"): (28, (15, 15), (10, 16)),
}

MAX_VERSION = 20

# Row/column centres of the alignment patterns, indexed by version.
_ALIGNMENT_POSITIONS: dict[int, list[int]] = {
    1: [],
    2: [6, 18],
    3: [6, 22],
    4: [6, 26],
    5: [6, 30],
    6: [6, 34],
    7: [6, 22, 38],
    8: [6, 24, 42],
    9: [6, 26, 46],
    10: [6, 28, 50],
    11: [6, 30, 54],
    12: [6, 32, 58],
    13: [6, 34, 62],
    14: [6, 26, 46, 66],
    15: [6, 26, 48, 70],
    16: [6, 26, 50, 74],
    17: [6, 30, 54, 78],
    18: [6, 30, 56, 82],
    19: [6, 30, 58, 86],
    20: [6, 34, 62, 90],
}


class QRError(ValueError):
    """The payload does not fit, or the requested parameters are invalid."""


# -- GF(256) arithmetic for Reed-Solomon ---------------------------------------

_EXP = [0] * 512
_LOG = [0] * 256


def _init_tables() -> None:
    value = 1
    for power in range(255):
        _EXP[power] = value
        _LOG[value] = power
        value <<= 1
        # The QR standard's primitive polynomial, x^8 + x^4 + x^3 + x^2 + 1.
        if value & 0x100:
            value ^= 0x11D
    for power in range(255, 512):
        _EXP[power] = _EXP[power - 255]


_init_tables()


def _gf_multiply(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def _generator_polynomial(degree: int) -> list[int]:
    """The RS generator polynomial (x - a^0)(x - a^1)...(x - a^(degree-1))."""
    polynomial = [1]
    for power in range(degree):
        # Multiply by (x - a^power); in GF(2) subtraction is XOR.
        polynomial = polynomial + [0]
        for index in range(len(polynomial) - 1):
            polynomial[index] ^= _gf_multiply(polynomial[index + 1], _EXP[power])
    return polynomial


def reed_solomon(data: bytes, ec_count: int) -> bytes:
    """The `ec_count` error-correction codewords for `data`."""
    generator = _generator_polynomial(ec_count)
    remainder = [0] * ec_count

    for byte in data:
        factor = byte ^ remainder[0]
        remainder = remainder[1:] + [0]
        if factor:
            for index in range(ec_count):
                remainder[index] ^= _gf_multiply(generator[ec_count - index], factor)
    return bytes(remainder)


# -- BCH codes for format and version information ------------------------------


def _bch(value: int, generator: int, data_bits: int, total_bits: int) -> int:
    """Append BCH check bits to `value`."""
    check_bits = total_bits - data_bits
    remainder = value << check_bits
    generator_length = generator.bit_length()
    while remainder.bit_length() >= generator_length:
        remainder ^= generator << (remainder.bit_length() - generator_length)
    return (value << check_bits) | remainder


def format_information(ec_level: ECLevel, mask: int) -> int:
    """The 15-bit format information field for a level and mask pattern."""
    data = (_EC_INDICATOR[ec_level] << 3) | mask
    # BCH(15,5) with generator x^10+x^8+x^5+x^4+x^2+x+1, XORed with a fixed
    # pattern so that an all-zero format never yields an all-zero field.
    return _bch(data, 0b10100110111, 5, 15) ^ 0b101010000010010


def version_information(version: int) -> int:
    """The 18-bit version field, present from version 7 upwards."""
    return _bch(version, 0b1111100100101, 6, 18)


# -- encoding ------------------------------------------------------------------


def _capacity_bits(version: int, ec_level: ECLevel) -> int:
    ec_per_block, group1, group2 = _BLOCK_TABLE[(version, ec_level)]
    return (group1[0] * group1[1] + group2[0] * group2[1]) * 8


def _character_count_bits(version: int) -> int:
    """Byte mode uses an 8-bit length below version 10 and 16 bits above."""
    return 8 if version <= 9 else 16


def choose_version(payload: bytes, ec_level: ECLevel) -> int:
    for version in range(1, MAX_VERSION + 1):
        overhead = 4 + _character_count_bits(version)
        if overhead + len(payload) * 8 <= _capacity_bits(version, ec_level):
            return version
    raise QRError(
        f"{len(payload)} bytes does not fit in a version-{MAX_VERSION} code at "
        f"level {ec_level}; use a lower error-correction level or a shorter payload"
    )


def _encode_payload(payload: bytes, version: int, ec_level: ECLevel) -> bytes:
    """Build the data codewords: mode, length, payload, terminator and padding."""
    count_bits = _character_count_bits(version)
    capacity = _capacity_bits(version, ec_level)

    bits: list[int] = []
    bits.extend((0, 1, 0, 0))  # Byte mode.
    for position in range(count_bits - 1, -1, -1):
        bits.append((len(payload) >> position) & 1)
    for byte in payload:
        for position in range(7, -1, -1):
            bits.append((byte >> position) & 1)

    # Up to four terminator zeros, then pad to a byte boundary.
    bits.extend([0] * min(4, capacity - len(bits)))
    if len(bits) % 8:
        bits.extend([0] * (8 - len(bits) % 8))

    codewords = bytearray()
    for index in range(0, len(bits), 8):
        codewords.append(int("".join(str(bit) for bit in bits[index : index + 8]), 2))

    # The standard's alternating pad bytes fill any remaining capacity.
    for index in range((capacity // 8) - len(codewords)):
        codewords.append(0xEC if index % 2 == 0 else 0x11)
    return bytes(codewords)


def _interleave(codewords: bytes, version: int, ec_level: ECLevel) -> bytes:
    """Split into blocks, add error correction, and interleave.

    Interleaving is what makes a QR code survive a smudge: a burst of damage is
    spread across every block instead of destroying one block outright.
    """
    ec_per_block, (blocks1, data1), (blocks2, data2) = _BLOCK_TABLE[(version, ec_level)]

    data_blocks: list[bytes] = []
    offset = 0
    for _ in range(blocks1):
        data_blocks.append(codewords[offset : offset + data1])
        offset += data1
    for _ in range(blocks2):
        data_blocks.append(codewords[offset : offset + data2])
        offset += data2

    ec_blocks = [reed_solomon(block, ec_per_block) for block in data_blocks]

    result = bytearray()
    for index in range(max(len(block) for block in data_blocks)):
        for block in data_blocks:
            if index < len(block):
                result.append(block[index])
    for index in range(ec_per_block):
        for block in ec_blocks:
            result.append(block[index])
    return bytes(result)


# -- matrix construction -------------------------------------------------------


class _Matrix:
    """The module grid, tracking which cells are reserved for function patterns."""

    def __init__(self, size: int) -> None:
        self.size = size
        self.modules = [[False] * size for _ in range(size)]
        self.reserved = [[False] * size for _ in range(size)]

    def set(self, row: int, column: int, value: bool, reserve: bool = True) -> None:
        self.modules[row][column] = value
        if reserve:
            self.reserved[row][column] = True

    def free_cells(self) -> int:
        return sum(row.count(False) for row in self.reserved)


def _place_finder(matrix: _Matrix, row: int, column: int) -> None:
    """A finder pattern plus its separator, clipped at the matrix edge."""
    for delta_row in range(-1, 8):
        for delta_column in range(-1, 8):
            r, c = row + delta_row, column + delta_column
            if not (0 <= r < matrix.size and 0 <= c < matrix.size):
                continue
            # The 7x7 pattern is a filled 3x3 inside a ring; everything in the
            # surrounding one-module border is light.
            inside = 0 <= delta_row <= 6 and 0 <= delta_column <= 6
            dark = inside and (
                delta_row in (0, 6)
                or delta_column in (0, 6)
                or (2 <= delta_row <= 4 and 2 <= delta_column <= 4)
            )
            matrix.set(r, c, dark)


def _place_alignment(matrix: _Matrix, version: int) -> None:
    positions = _ALIGNMENT_POSITIONS[version]
    last = len(positions) - 1
    for row_index, row in enumerate(positions):
        for column_index, column in enumerate(positions):
            # The three finder corners have no alignment pattern.
            if (row_index, column_index) in {(0, 0), (0, last), (last, 0)}:
                continue
            for delta_row in range(-2, 3):
                for delta_column in range(-2, 3):
                    dark = max(abs(delta_row), abs(delta_column)) != 1
                    matrix.set(row + delta_row, column + delta_column, dark)


def _place_timing(matrix: _Matrix) -> None:
    for position in range(8, matrix.size - 8):
        dark = position % 2 == 0
        matrix.set(6, position, dark)
        matrix.set(position, 6, dark)


def _reserve_format_areas(matrix: _Matrix, version: int) -> None:
    size = matrix.size
    for position in range(9):
        if position != 6:
            matrix.set(8, position, False)
            matrix.set(position, 8, False)
    for position in range(8):
        matrix.set(8, size - 1 - position, False)
        matrix.set(size - 1 - position, 8, False)
    # The dark module, always set, always in the same place.
    matrix.set(size - 8, 8, True)

    if version >= 7:
        for position in range(18):
            row, column = position // 3, position % 3
            matrix.set(size - 11 + column, row, False)
            matrix.set(row, size - 11 + column, False)


def _write_format_information(matrix: _Matrix, ec_level: ECLevel, mask: int) -> None:
    bits = format_information(ec_level, mask)
    size = matrix.size
    for position in range(15):
        bit = bool((bits >> position) & 1)
        # The field is written twice: once around the top-left finder, and once
        # split between the other two, so a damaged corner is recoverable.
        if position < 6:
            matrix.set(8, position, bit)
        elif position == 6:
            matrix.set(8, 7, bit)
        elif position == 7:
            matrix.set(8, 8, bit)
        elif position == 8:
            matrix.set(7, 8, bit)
        else:
            matrix.set(14 - position, 8, bit)

        if position < 8:
            matrix.set(8, size - 1 - position, bit)
        else:
            matrix.set(size - 15 + position, 8, bit)


def _write_version_information(matrix: _Matrix, version: int) -> None:
    if version < 7:
        return
    bits = version_information(version)
    size = matrix.size
    for position in range(18):
        bit = bool((bits >> position) & 1)
        row, column = position // 3, position % 3
        matrix.set(size - 11 + column, row, bit)
        matrix.set(row, size - 11 + column, bit)


def _place_data(matrix: _Matrix, data: bytes) -> None:
    """Fill the free modules in the standard upward/downward zigzag."""
    size = matrix.size
    bit_index = 0
    total_bits = len(data) * 8
    upward = True

    column = size - 1
    while column > 0:
        # Column 6 is the vertical timing pattern and is skipped entirely.
        if column == 6:
            column -= 1
        rows = range(size - 1, -1, -1) if upward else range(size)
        for row in rows:
            for offset in range(2):
                current_column = column - offset
                if matrix.reserved[row][current_column]:
                    continue
                bit = False
                if bit_index < total_bits:
                    bit = bool((data[bit_index >> 3] >> (7 - (bit_index & 7))) & 1)
                    bit_index += 1
                # Remaining modules stay light; they are the remainder bits.
                matrix.set(row, current_column, bit, reserve=False)
        upward = not upward
        column -= 2


def _mask_condition(mask: int, row: int, column: int) -> bool:
    if mask == 0:
        return (row + column) % 2 == 0
    if mask == 1:
        return row % 2 == 0
    if mask == 2:
        return column % 3 == 0
    if mask == 3:
        return (row + column) % 3 == 0
    if mask == 4:
        return (row // 2 + column // 3) % 2 == 0
    if mask == 5:
        return (row * column) % 2 + (row * column) % 3 == 0
    if mask == 6:
        return ((row * column) % 2 + (row * column) % 3) % 2 == 0
    if mask == 7:
        return ((row + column) % 2 + (row * column) % 3) % 2 == 0
    raise QRError(f"mask pattern must be 0-7, got {mask}")


def _apply_mask(matrix: _Matrix, mask: int) -> _Matrix:
    masked = _Matrix(matrix.size)
    for row in range(matrix.size):
        for column in range(matrix.size):
            value = matrix.modules[row][column]
            if not matrix.reserved[row][column] and _mask_condition(mask, row, column):
                value = not value
            masked.modules[row][column] = value
            masked.reserved[row][column] = matrix.reserved[row][column]
    return masked


def _penalty(matrix: _Matrix) -> int:
    """Score a masked matrix by the standard's four penalty rules (lower is better)."""
    size = matrix.size
    modules = matrix.modules
    score = 0

    # Rule 1: runs of five or more same-coloured modules in a row or column.
    for line in list(modules) + [list(column) for column in zip(*modules)]:
        run_length = 1
        for index in range(1, size):
            if line[index] == line[index - 1]:
                run_length += 1
            else:
                if run_length >= 5:
                    score += 3 + (run_length - 5)
                run_length = 1
        if run_length >= 5:
            score += 3 + (run_length - 5)

    # Rule 2: 2x2 blocks of one colour.
    for row in range(size - 1):
        for column in range(size - 1):
            block = (
                modules[row][column],
                modules[row][column + 1],
                modules[row + 1][column],
                modules[row + 1][column + 1],
            )
            if all(block) or not any(block):
                score += 3

    # Rule 3: patterns that look like a finder pattern, which would confuse a
    # scanner about where the code's corners are.
    finder = [True, False, True, True, True, False, True]
    quiet = [False] * 4
    for line in list(modules) + [list(column) for column in zip(*modules)]:
        for index in range(size - 6):
            if line[index : index + 7] == finder:
                before = line[max(0, index - 4) : index]
                after = line[index + 7 : index + 11]
                if before == quiet[: len(before)] and len(before) == 4:
                    score += 40
                elif after == quiet[: len(after)] and len(after) == 4:
                    score += 40

    # Rule 4: deviation from an even balance of dark and light.
    dark = sum(row.count(True) for row in modules)
    percent = dark * 100 // (size * size)
    score += 10 * (min(abs(percent - 50) // 5, 10))
    return score


@dataclass
class QRCode:
    """A rendered QR matrix. `modules[row][column]` is True where dark."""

    modules: list[list[bool]]
    version: int
    ec_level: ECLevel
    mask: int

    @property
    def size(self) -> int:
        return len(self.modules)

    def to_text(self, quiet_zone: int = 2, invert: bool = False) -> str:
        """Render for a terminal, two rows per line using half-block characters.

        A QR code drawn one module per character cell is twice as tall as it is
        wide and often will not scan; pairing rows keeps it square.
        """
        size = self.size
        padded_size = size + quiet_zone * 2

        def dark(row: int, column: int) -> bool:
            inner_row, inner_column = row - quiet_zone, column - quiet_zone
            if 0 <= inner_row < size and 0 <= inner_column < size:
                return self.modules[inner_row][inner_column] != invert
            return invert

        lines = []
        for row in range(0, padded_size, 2):
            line = []
            for column in range(padded_size):
                top = dark(row, column)
                bottom = dark(row + 1, column) if row + 1 < padded_size else invert
                # Dark modules are drawn as the *absence* of ink so the code
                # reads correctly on a light-on-dark terminal.
                if top and bottom:
                    line.append(" ")
                elif top:
                    line.append("▄")
                elif bottom:
                    line.append("▀")
                else:
                    line.append("█")
            lines.append("".join(line))
        return "\n".join(lines)

    def to_svg(self, module_size: int = 8, quiet_zone: int = 4) -> str:
        size = self.size
        dimension = (size + quiet_zone * 2) * module_size
        parts = [
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{dimension}" '
            f'height="{dimension}" viewBox="0 0 {dimension} {dimension}" '
            f'shape-rendering="crispEdges" role="img" aria-label="QR code">',
            f'<rect width="{dimension}" height="{dimension}" fill="#ffffff"/>',
            '<path fill="#000000" d="',
        ]
        path = []
        for row in range(size):
            for column in range(size):
                if self.modules[row][column]:
                    x = (column + quiet_zone) * module_size
                    y = (row + quiet_zone) * module_size
                    path.append(f"M{x} {y}h{module_size}v{module_size}h-{module_size}z")
        parts.append("".join(path))
        parts.append('"/></svg>')
        return "".join(parts)

    def to_png(self, module_size: int = 8, quiet_zone: int = 4) -> bytes:
        """A 1-bit greyscale PNG, assembled with zlib from the standard library."""
        size = self.size
        dimension = (size + quiet_zone * 2) * module_size

        rows = bytearray()
        for y in range(dimension):
            rows.append(0)  # PNG filter type 0 (None) for this scanline.
            module_row = y // module_size - quiet_zone
            line = bytearray()
            for x in range(dimension):
                module_column = x // module_size - quiet_zone
                dark = (
                    0 <= module_row < size
                    and 0 <= module_column < size
                    and self.modules[module_row][module_column]
                )
                line.append(0 if dark else 255)
            rows += line

        def chunk(tag: bytes, payload: bytes) -> bytes:
            body = tag + payload
            return (
                len(payload).to_bytes(4, "big")
                + body
                + zlib.crc32(body).to_bytes(4, "big")
            )

        header = (
            dimension.to_bytes(4, "big")
            + dimension.to_bytes(4, "big")
            + bytes([8, 0, 0, 0, 0])  # 8-bit depth, greyscale, no interlacing.
        )
        return (
            b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", header)
            + chunk(b"IDAT", zlib.compress(bytes(rows), 9))
            + chunk(b"IEND", b"")
        )


def encode(
    payload: str | bytes,
    ec_level: ECLevel = "M",
    version: int | None = None,
    mask: int | None = None,
) -> QRCode:
    """Encode `payload` as a QR code.

    The default error-correction level M tolerates about 15% damage, which is
    the right trade-off for a code shown on a screen and scanned from a phone.
    """
    data = payload.encode("utf-8") if isinstance(payload, str) else payload
    if ec_level not in _EC_INDICATOR:
        raise QRError(f"error-correction level must be L, M, Q or H, got {ec_level!r}")

    if version is None:
        version = choose_version(data, ec_level)
    elif not 1 <= version <= MAX_VERSION:
        raise QRError(f"version must be 1-{MAX_VERSION}, got {version}")
    elif 4 + _character_count_bits(version) + len(data) * 8 > _capacity_bits(version, ec_level):
        raise QRError(f"{len(data)} bytes does not fit in version {version} at level {ec_level}")

    codewords = _interleave(_encode_payload(data, version, ec_level), version, ec_level)

    size = version * 4 + 17
    base = _Matrix(size)
    _place_finder(base, 0, 0)
    _place_finder(base, 0, size - 7)
    _place_finder(base, size - 7, 0)
    _place_alignment(base, version)
    _place_timing(base)
    _reserve_format_areas(base, version)
    _place_data(base, codewords)

    candidates = range(8) if mask is None else [mask]
    best: tuple[int, int, _Matrix] | None = None
    for candidate in candidates:
        masked = _apply_mask(base, candidate)
        _write_format_information(masked, ec_level, candidate)
        _write_version_information(masked, version)
        score = _penalty(masked)
        if best is None or score < best[0]:
            best = (score, candidate, masked)

    assert best is not None  # `candidates` is never empty.
    _, chosen_mask, matrix = best
    return QRCode(matrix.modules, version, ec_level, chosen_mask)


def total_codewords(version: int, ec_level: ECLevel) -> int:
    """Data plus error-correction codewords, used to validate the tables."""
    ec_per_block, group1, group2 = _BLOCK_TABLE[(version, ec_level)]
    blocks = group1[0] + group2[0]
    return group1[0] * group1[1] + group2[0] * group2[1] + blocks * ec_per_block


def free_module_count(version: int) -> int:
    """Modules available for data, derived from geometry rather than a table."""
    size = version * 4 + 17
    matrix = _Matrix(size)
    _place_finder(matrix, 0, 0)
    _place_finder(matrix, 0, size - 7)
    _place_finder(matrix, size - 7, 0)
    _place_alignment(matrix, version)
    _place_timing(matrix)
    _reserve_format_areas(matrix, version)
    return matrix.free_cells()


def render_terminal(payload: str, ec_level: ECLevel = "M") -> str:
    """Convenience wrapper: encode and render in one call."""
    return encode(payload, ec_level).to_text()
