#!/usr/bin/env python3
"""Wrap a cooked 2048-byte ISO in valid raw Mode 1 sectors for Aaru.

Aaru's MDS/MDF writer requests 2352-byte sectors. This helper adds the raw-CD
sync/header, EDC, and P/Q error-correction bytes without changing the ISO user
data, then writes a matching single-track CUE sheet.
"""

from __future__ import annotations

import argparse
from pathlib import Path

COOKED_SECTOR_SIZE = 2048
RAW_SECTOR_SIZE = 2352


def build_edc_table() -> list[int]:
    table = []
    for value in range(256):
        entry = value
        for _ in range(8):
            entry = (entry >> 1) ^ (0xD8018001 if entry & 1 else 0)
        table.append(entry)
    return table


def build_ecc_tables() -> tuple[list[int], list[int]]:
    forward = [0] * 256
    backward = [0] * 256
    for value in range(256):
        doubled = value << 1
        if doubled & 0x100:
            doubled ^= 0x11D
        forward[value] = doubled
        backward[value ^ doubled] = value
    return forward, backward


EDC_TABLE = build_edc_table()
ECC_FORWARD, ECC_BACKWARD = build_ecc_tables()


def bcd(value: int) -> int:
    return ((value // 10) << 4) | (value % 10)


def edc(data: bytes | bytearray) -> int:
    checksum = 0
    for value in data:
        checksum = (checksum >> 8) ^ EDC_TABLE[(checksum ^ value) & 0xFF]
    return checksum


def ecc(data: bytes | bytearray, major_count: int, minor_count: int, major_mult: int, minor_inc: int) -> bytes:
    size = major_count * minor_count
    result = bytearray(major_count * 2)
    for major in range(major_count):
        index = (major >> 1) * major_mult + (major & 1)
        ecc_a = 0
        ecc_b = 0
        for _ in range(minor_count):
            value = data[index]
            index = (index + minor_inc) % size
            ecc_a ^= value
            ecc_b ^= value
            ecc_a = ECC_FORWARD[ecc_a]
        ecc_a = ECC_BACKWARD[ECC_FORWARD[ecc_a] ^ ecc_b]
        result[major] = ecc_a
        result[major + major_count] = ecc_a ^ ecc_b
    return bytes(result)


def raw_mode1_sector(lba: int, payload: bytes) -> bytes:
    if len(payload) != COOKED_SECTOR_SIZE:
        raise ValueError(f"expected {COOKED_SECTOR_SIZE} payload bytes, got {len(payload)}")

    absolute = lba + 150
    minute = absolute // (75 * 60)
    second = (absolute // 75) % 60
    frame = absolute % 75
    if minute > 99:
        raise ValueError("image is too large for a two-digit CD minute field")

    sector = bytearray(b"\x00" + b"\xff" * 10 + b"\x00")
    sector.extend((bcd(minute), bcd(second), bcd(frame), 1))
    sector.extend(payload)
    sector.extend(edc(sector).to_bytes(4, "little"))
    sector.extend(b"\x00" * 8)
    sector.extend(ecc(sector[12:2076], 86, 24, 2, 86))
    sector.extend(ecc(sector[12:2248], 52, 43, 86, 88))
    assert len(sector) == RAW_SECTOR_SIZE
    return bytes(sector)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("iso", type=Path, help="input cooked ISO with 2048-byte sectors")
    parser.add_argument("cue", type=Path, help="output CUE path; the BIN is written beside it")
    args = parser.parse_args()

    image = args.iso.read_bytes()
    if not image or len(image) % COOKED_SECTOR_SIZE:
        raise SystemExit(f"{args.iso} is not a non-empty multiple of {COOKED_SECTOR_SIZE} bytes")

    args.cue.parent.mkdir(parents=True, exist_ok=True)
    bin_path = args.cue.with_suffix(".bin")
    with bin_path.open("wb") as output:
        for lba, offset in enumerate(range(0, len(image), COOKED_SECTOR_SIZE)):
            output.write(raw_mode1_sector(lba, image[offset : offset + COOKED_SECTOR_SIZE]))

    args.cue.write_text(
        f'FILE "{bin_path.name}" BINARY\n'
        "  TRACK 01 MODE1/2352\n"
        "    INDEX 01 00:00:00\n",
        encoding="ascii",
    )


if __name__ == "__main__":
    main()
