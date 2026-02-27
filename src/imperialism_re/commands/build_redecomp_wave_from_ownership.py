#!/usr/bin/env python3
"""
Build Ghidra wave CSVs from the re-decomp project's ownership + symbols tables.

Inputs (from sibling `../imperialism-decomp` by default):
  - config/function_ownership.csv (pipe-delimited)
  - config/symbols.csv (pipe-delimited)

Outputs:
  - <out-prefix>_renames.csv
  - <out-prefix>_signatures.csv

Rename CSV columns:
  address,new_name,comment

Signature CSV columns:
  address,calling_convention,return_type,params
  params format: name:type;name:type
"""

from __future__ import annotations

import os
import argparse
import csv
import re
from pathlib import Path
from imperialism_re.core.config import repo_root

SIG_RE = re.compile(
    r"^\s*(?P<ret>.+?)\s+"
    r"(?P<cc>__thiscall|__cdecl|__stdcall|__fastcall|default)\s+"
    r"(?P<name>[^\s(]+)\s*"
    r"\((?P<params>.*)\)\s*$"
)

def normalize_type(raw: str) -> str:
    t = raw.strip()
    t = re.sub(r"\s+", " ", t)
    t = t.replace(" *", "*").replace("* ", "*")
    tl = t.lower()

    synonym_map = {
        "unsigned int": "uint",
        "uint32_t": "uint",
        "unsigned short": "ushort",
        "uint16_t": "ushort",
        "unsigned char": "byte",
        "uint8_t": "byte",
        "signed char": "char",
        "int32_t": "int",
        "signed int": "int",
        "int16_t": "short",
        "int8_t": "char",
        "undefined1": "byte",
        "undefined2": "ushort",
        "undefined4": "int",
        "undefined": "int",
        "undefined8": "int",
    }

    if tl in synonym_map:
        return synonym_map[tl]
    return t

def split_param(param: str, index: int) -> tuple[str, str]:
    p = re.sub(r"\s+", " ", param.strip())
    if not p:
        return f"arg{index}", "int"

    m = re.match(r"^(?P<typ>.+?)\s+(?P<name>[A-Za-z_]\w*)$", p)
    if not m:
        # Type-only form; keep the type and synthesize a name.
        return f"arg{index}", normalize_type(p)

    typ = normalize_type(m.group("typ"))
    name = m.group("name")
    return name, typ

def parse_signature(sig: str) -> tuple[str, str, str, list[tuple[str, str]]] | None:
    m = SIG_RE.match(sig.strip())
    if not m:
        return None

    cc = m.group("cc")
    ret = normalize_type(m.group("ret"))
    parsed_name = m.group("name").strip()
    params_raw = m.group("params").strip()
    params: list[tuple[str, str]] = []
    if params_raw and params_raw.lower() != "void":
        parts = [x.strip() for x in params_raw.split(",") if x.strip()]
        for i, part in enumerate(parts, start=1):
            nm, typ = split_param(part, i)
            params.append((nm, typ))
    return cc, ret, parsed_name, params

def name_leaf(raw: str) -> str:
    n = raw.strip()
    if "::" in n:
        n = n.split("::")[-1].strip()
    return n

def load_ownership_rows(path: Path, target_cpp: str) -> list[str]:
    addrs: list[str] = []
    with path.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh, delimiter="|")
        for row in reader:
            if (row.get("target_cpp") or "").strip() != target_cpp:
                continue
            addr = (row.get("address") or "").strip().lower()
            if addr:
                addrs.append(addr)
    return addrs

def load_symbols(path: Path) -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    with path.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh, delimiter="|")
        for row in reader:
            addr = (row.get("address") or "").strip().lower()
            if not addr:
                continue
            out[addr] = row
    return out

def addr_hex_prefixed(addr: str) -> str:
    a = addr.lower().strip()
    if a.startswith("0x"):
        return a
    return f"0x{a}"

def main() -> int:
    default_decomp_root = (
        Path(
            os.getenv(
                "IMPK_REDECOMP_ROOT",
                str(repo_root().parent / "imperialism-decomp"),
            )
        ).resolve()
    )

    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--decomp-root",
        default=str(default_decomp_root),
        help="Path to re-decomp repo root",
    )
    ap.add_argument(
        "--target-cpp",
        required=True,
        help="Ownership target path, e.g. src/game/trade_screen.cpp",
    )
    ap.add_argument(
        "--out-prefix",
        required=True,
        help="Output prefix (without _renames/_signatures suffix)",
    )
    ap.add_argument(
        "--strict-signatures",
        action="store_true",
        help=(
            "Only keep signatures where prototype function token is undecorated and "
            "matches the leaf name from symbols.csv"
        ),
    )
    args = ap.parse_args()

    root = Path(args.decomp_root).resolve()
    own_csv = root / "config/function_ownership.csv"
    sym_csv = root / "config/symbols.csv"
    if not own_csv.exists():
        print(f"[error] missing {own_csv}")
        return 1
    if not sym_csv.exists():
        print(f"[error] missing {sym_csv}")
        return 1

    owned_addrs = load_ownership_rows(own_csv, args.target_cpp)
    symbol_rows = load_symbols(sym_csv)
    out_prefix = Path(args.out_prefix)
    out_prefix.parent.mkdir(parents=True, exist_ok=True)
    ren_csv = out_prefix.with_name(out_prefix.name + "_renames.csv")
    sig_csv = out_prefix.with_name(out_prefix.name + "_signatures.csv")

    ren_rows: list[dict[str, str]] = []
    sig_rows: list[dict[str, str]] = []
    missing = unparsable = sig_rejected = 0

    for addr in owned_addrs:
        row = symbol_rows.get(addr)
        if row is None:
            missing += 1
            continue
        if (row.get("type") or "").strip().lower() != "function":
            continue

        name = name_leaf((row.get("name") or "").strip())
        sig = ((row.get("prototype") or "").strip() or (row.get("signature") or "").strip())
        if not name:
            continue

        ren_rows.append(
            {
                "address": addr_hex_prefixed(addr),
                "new_name": name,
                "comment": f"imported from redecomp:{args.target_cpp}",
            }
        )

        parsed = parse_signature(sig)
        if parsed is None:
            unparsable += 1
            continue

        cc, ret, parsed_name, params = parsed
        parsed_leaf = name_leaf(parsed_name)
        if args.strict_signatures:
            if (
                not parsed_leaf
                or parsed_name.startswith("?")
                or "@@" in parsed_name
                or parsed_leaf != name
            ):
                sig_rejected += 1
                continue

        params_txt = ";".join(f"{nm}:{typ}" for nm, typ in params)
        sig_rows.append(
            {
                "address": addr_hex_prefixed(addr),
                "calling_convention": cc,
                "return_type": ret,
                "params": params_txt,
            }
        )

    with ren_csv.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=["address", "new_name", "comment"])
        writer.writeheader()
        writer.writerows(ren_rows)

    with sig_csv.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(
            fh, fieldnames=["address", "calling_convention", "return_type", "params"]
        )
        writer.writeheader()
        writer.writerows(sig_rows)

    print(f"[source] target_cpp={args.target_cpp} owned_addrs={len(owned_addrs)}")
    print(f"[saved] {ren_csv} rows={len(ren_rows)}")
    print(f"[saved] {sig_csv} rows={len(sig_rows)}")
    print(
        f"[stats] missing_symbols={missing} unparsable_signatures={unparsable} "
        f"rejected_signatures={sig_rejected} strict_signatures={int(args.strict_signatures)}"
    )
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
