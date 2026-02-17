#!/usr/bin/env python3
"""Check for Rich header presence in a PE file."""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("pe_path", help="Path to PE executable (e.g. Imperialism.exe)")
    return parser.parse_args()


def main() -> int:
    try:
        args = parse_args()
        pe_path = Path(args.pe_path)
        data = pe_path.read_bytes()

        if len(data) < 0x40 or data[:2] != b"MZ":
            raise RuntimeError(f"Not a valid DOS/PE file: {pe_path}")

        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew + 4 > len(data):
            raise RuntimeError(f"Invalid e_lfanew value: 0x{e_lfanew:X}")

        pe_sig = data[e_lfanew : e_lfanew + 4]
        dos_region = data[:e_lfanew]
        rich_present = b"Rich" in dos_region
        dans_present = b"DanS" in dos_region

        print(f"file: {pe_path}")
        print(f"size: {len(data)}")
        print(f"e_lfanew: 0x{e_lfanew:X}")
        print(f"pe_signature: {pe_sig!r}")
        print(f"rich_in_dos_region: {rich_present}")
        print(f"dans_in_dos_region: {dans_present}")

        rich_offsets = []
        start = 0
        while True:
            idx = data.find(b"Rich", start)
            if idx < 0:
                break
            rich_offsets.append(idx)
            start = idx + 1

        print(
            "rich_offsets_before_pe_header: {}".format(
                [f"0x{off:X}" for off in rich_offsets if off < e_lfanew]
            )
        )
        return 0
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
