#!/usr/bin/env python3
"""Prune incremental-link (ILT) `jmp` thunk rows from config/symbols.csv.

The original Imperialism.exe was linked incrementally, so the start of .text
(0x401000..) is a dense table of 5-byte `jmp <real body>` stubs. These are
linker artifacts, not source functions: reccmp auto-detects unannotated jmp
thunks in both binaries (EntityType.THUNK, skip=True) and excludes them from
the report, and hand-writing bodies for them is forbidden (fake source).

A row is pruned only when ALL of these hold:
  1. type == function and the address lies inside the contiguous ILT region;
  2. the original exe byte at the address is 0xE9 (jmp rel32);
  3. no manual source file claims the address with a FUNCTION/STUB/SYNTHETIC
     marker (those need a separate retirement pass first);
  4. no manual source references the symbol name (the sanctioned
     extern-thunk-cast callsite pattern still needs the autogen stub to link).

Run after `just sync-ghidra` regenerates config/symbols.csv.
"""

from __future__ import annotations

import argparse
import glob
import re
import struct
from pathlib import Path

from tools.common.repo import repo_root_from_file

MARKER_RE = re.compile(
    r"// (?:FUNCTION|STUB|SYNTHETIC|TEMPLATE|LIBRARY): IMPERIALISM 0x([0-9a-fA-F]{8})"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--symbols-csv", default="config/symbols.csv")
    parser.add_argument(
        "--original-exe",
        default=None,
        help="Path to the original Imperialism.exe (default: from reccmp-user.yml)",
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Report what would be pruned, change nothing."
    )
    return parser.parse_args()


def original_exe_from_user_yml(repo_root: Path) -> Path:
    from ruamel.yaml import YAML

    user_yml = repo_root / "reccmp-user.yml"
    payload = YAML(typ="safe").load(user_yml.read_text())
    return Path(payload["targets"]["IMPERIALISM"]["path"])


class TextSection:
    def __init__(self, exe_bytes: bytes):
        self.exe = exe_bytes
        pe_off = struct.unpack_from("<I", exe_bytes, 0x3C)[0]
        nsec = struct.unpack_from("<H", exe_bytes, pe_off + 6)[0]
        opt_size = struct.unpack_from("<H", exe_bytes, pe_off + 20)[0]
        image_base = struct.unpack_from("<I", exe_bytes, pe_off + 0x34)[0]
        off = pe_off + 24 + opt_size
        self.raw = None
        for _ in range(nsec):
            name = exe_bytes[off : off + 8].rstrip(b"\0").decode()
            vsize, va, _rsize, raw = struct.unpack_from("<IIII", exe_bytes, off + 8)
            if name == ".text":
                self.raw = raw
                self.va = image_base + va
                self.vsize = vsize
            off += 40
        if self.raw is None:
            raise RuntimeError("No .text section found")
        assert isinstance(self.raw, int)

    def byte_at(self, addr: int) -> int:
        if not (self.va <= addr < self.va + self.vsize):
            raise ValueError("address outside .text: 0x%x" % addr)
        return self.exe[self.raw + addr - self.va]

    def ilt_region(self) -> tuple[int, int]:
        """Contiguous run of jmp stubs (with int3 padding) from the start of .text."""
        addr = self.va
        last = self.va
        while addr < self.va + self.vsize:
            b = self.byte_at(addr)
            if b == 0xE9:
                last = addr + 4
                addr += 5
            elif b == 0xCC and addr - last < 0x10:
                addr += 1
            else:
                break
        return (self.va, last)


def collect_claimed_addresses(repo_root: Path) -> set[int]:
    claimed: set[int] = set()
    patterns = ["src/**/*.cpp", "include/**/*.h"]
    for pattern in patterns:
        for f in glob.glob(str(repo_root / pattern), recursive=True):
            if "autogen" in f:
                continue
            text = Path(f).read_text(errors="ignore")
            for m in MARKER_RE.finditer(text):
                claimed.add(int(m.group(1), 16))
    return claimed


def collect_manual_text(repo_root: Path) -> str:
    chunks = []
    for pattern in ["src/**/*.cpp", "include/**/*.h"]:
        for f in glob.glob(str(repo_root / pattern), recursive=True):
            if "autogen" in f:
                continue
            chunks.append(Path(f).read_text(errors="ignore"))
    return "\n".join(chunks)


def main() -> int:
    args = parse_args()
    repo_root = repo_root_from_file(__file__, levels_up=2)
    csv_path = repo_root / args.symbols_csv
    exe_path = (
        Path(args.original_exe) if args.original_exe else original_exe_from_user_yml(repo_root)
    )

    text = TextSection(exe_path.read_bytes())
    ilt_lo, ilt_hi = text.ilt_region()
    claimed = collect_claimed_addresses(repo_root)
    manual_text = collect_manual_text(repo_root)

    lines = csv_path.read_text().splitlines(keepends=True)
    out = [lines[0]]
    pruned = kept_claimed = kept_referenced = 0
    for line in lines[1:]:
        parts = line.rstrip("\n").split("|")
        if len(parts) < 5:
            out.append(line)
            continue
        addr_text, name, row_type = parts[0], parts[1], parts[4]
        try:
            addr = int(addr_text, 16)
        except ValueError:
            out.append(line)
            continue
        if row_type != "function" or not (ilt_lo <= addr <= ilt_hi):
            out.append(line)
            continue
        if text.byte_at(addr) != 0xE9:
            out.append(line)
            continue
        if addr in claimed:
            kept_claimed += 1
            out.append(line)
            continue
        ident = re.sub(r"[^A-Za-z0-9_]", "_", name.split("::")[-1])
        if ident and re.search(r"\b" + re.escape(ident) + r"\b", manual_text):
            kept_referenced += 1
            out.append(line)
            continue
        pruned += 1

    print(
        "ILT region 0x{:08x}..0x{:08x}: pruned {} rows "
        "(kept {} claimed-by-manual-source, {} referenced-by-name)".format(
            ilt_lo, ilt_hi, pruned, kept_claimed, kept_referenced
        )
    )
    if not args.dry_run:
        csv_path.write_text("".join(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
