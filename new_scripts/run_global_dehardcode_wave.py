#!/usr/bin/env python3
"""
Run a high-throughput global dehardcode wave in one pyghidra session.

Flow:
1) scan globals and build an in-memory atlas (xref/read/write + top readers/writers),
2) generate rename/type/comment candidates using conservative templates,
3) optionally apply candidates,
4) emit pre/post counters and CSV artifacts.

This is intended to reduce per-wave overhead versus running separate scripts.

Usage:
  .venv/bin/python new_scripts/run_global_dehardcode_wave.py \
    --batch-tag batch600 \
    --start 0x00600000 --end 0x00700000 \
    --name-regex '^DAT_' \
    --min-code-refs 3 \
    --min-confidence medium

  .venv/bin/python new_scripts/run_global_dehardcode_wave.py \
    --batch-tag batch600 \
    --start 0x00600000 --end 0x00700000 \
    --name-regex '^DAT_' \
    --min-code-refs 3 \
    --min-confidence high \
    --apply
"""

from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import pyghidra

GHIDRA_DIR = Path(
    "/home/andrzej.gluszak/Downloads/ghidra_12.0.2_PUBLIC_20260129/ghidra_12.0.2_PUBLIC"
)
PROJECT_NAME = "imperialism-decomp"
PROGRAM_PATH = "/Imperialism.exe"

STOPWORDS = {
    "the",
    "and",
    "with",
    "from",
    "for",
    "into",
    "by",
    "to",
    "of",
    "at",
    "or",
    "if",
    "is",
    "set",
    "get",
    "update",
    "initialize",
    "construct",
    "create",
    "destroy",
    "process",
    "handle",
    "wrapper",
    "thunk",
    "fun",
    "impl",
    "state",
    "global",
}

RUNTIME_HINTS = (
    "Runtime",
    "Locale",
    "TimeZone",
    "Api",
    "Win32",
    "Mfc",
    "Crt",
    "Signal",
    "Exception",
    "Environment",
)


def is_bad_anchor_name(name: str) -> bool:
    n = (name or "").strip()
    if not n:
        return True
    bad_prefixes = (
        "FUN_",
        "thunk_",
        "WrapperFor_",
        "Cluster_",
        "OrphanCallChain_",
        "OrphanLeaf_",
    )
    return n.startswith(bad_prefixes)


def choose_anchor_name(row: "AtlasRow") -> str:
    for group in (row.top_writers, row.top_readers, row.top_callers):
        for name, _cnt in group:
            if not is_bad_anchor_name(name):
                return name
    # If only generic/orphan anchors are available, prefer symbol fallback
    # to avoid baking low-quality function names into globals.
    return row.old_name


def open_project_with_lock_cleanup(root: Path):
    try:
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)
    except Exception:
        for lock_file in (root / f"{PROJECT_NAME}.lock", root / f"{PROJECT_NAME}.lock~"):
            if lock_file.exists():
                lock_file.unlink()
        return pyghidra.open_project(str(root), PROJECT_NAME, create=False)


def parse_hex(text: str) -> int:
    t = text.strip().lower()
    if t.startswith("0x"):
        return int(t, 16)
    return int(t, 16)


def split_camel_and_symbols(text: str) -> list[str]:
    s = re.sub(r"[^A-Za-z0-9_]", "_", text)
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s)
    parts = [p for p in s.split("_") if p]
    return parts


def sanitize_symbol_name(text: str) -> str:
    s = re.sub(r"[^A-Za-z0-9_]", "_", text)
    s = re.sub(r"_+", "_", s).strip("_")
    if not s:
        s = "Global"
    if s[0].isdigit():
        s = "_" + s
    return s


def parse_top_list(raw: str) -> list[tuple[str, int]]:
    out: list[tuple[str, int]] = []
    txt = (raw or "").strip()
    if not txt:
        return out
    for item in txt.split(";"):
        part = item.strip()
        if not part or ":" not in part:
            continue
        name, cnt = part.rsplit(":", 1)
        try:
            out.append((name.strip(), int(cnt)))
        except Exception:
            continue
    return out


def infer_type(existing_type: str, symbol_name: str) -> str:
    t = (existing_type or "").lower()
    n = (symbol_name or "").lower()
    if "pointer" in t or n.startswith("ptr_"):
        return "void*"
    if "undefined1" in t or t == "byte" or "char" in t:
        return "byte"
    if "undefined2" in t or "ushort" in t:
        return "ushort"
    if "undefined4" in t or t in {"int", "dword", "uint"}:
        return "int"
    return ""


def confidence_rank(name: str) -> int:
    return {"low": 1, "medium": 2, "high": 3}.get(name, 2)


def classify_bucket(
    write_refs: int,
    read_refs: int,
    code_refs: int,
    anchor_name: str,
    in_cluster: bool,
    runtime_hit: bool,
    allow_code1_low_signal: bool,
) -> tuple[str, str]:
    if runtime_hit:
        return ("runtime_api_cache", "high" if code_refs >= 3 else "medium")
    if write_refs >= 3:
        return ("write_hot_scalar", "high" if code_refs >= 4 else "medium")
    if write_refs == 0 and read_refs >= 4:
        return ("read_mostly_table", "high")
    if in_cluster and code_refs >= 3:
        return ("contiguous_cluster", "medium")
    if write_refs >= 1 and read_refs >= 1:
        return ("mixed_state", "medium")
    if code_refs >= 2:
        return ("low_signal", "low")
    if allow_code1_low_signal and code_refs >= 1:
        return ("low_signal", "low")
    return ("skip", "low")


def build_name_tokens(anchor_name: str) -> list[str]:
    toks = split_camel_and_symbols(anchor_name)
    out: list[str] = []
    for tok in toks:
        low = tok.lower()
        if low in STOPWORDS:
            continue
        if len(tok) <= 1:
            continue
        if low.isdigit():
            continue
        out.append(tok)
        if len(out) >= 4:
            break
    if not out:
        out = ["Global"]
    return out


def build_role(bucket: str, inferred_type: str, write_refs: int) -> str:
    if bucket == "runtime_api_cache":
        return "RuntimeCache"
    if bucket == "read_mostly_table":
        return "LookupTable"
    if bucket == "contiguous_cluster":
        return "ClusterState"
    if inferred_type == "byte" and write_refs > 0:
        return "Flag"
    if inferred_type == "ushort":
        return "WordState"
    if write_refs > 0:
        return "State"
    return "Value"


def make_unique_name(existing_names: set[str], desired: str, addr: int) -> str:
    if desired not in existing_names:
        existing_names.add(desired)
        return desired
    base = f"{desired}_At{addr:08X}"
    cur = base
    idx = 2
    while cur in existing_names:
        cur = f"{base}_{idx}"
        idx += 1
    existing_names.add(cur)
    return cur


def ref_kind_flags(ref_type) -> tuple[bool, bool]:
    s = str(ref_type).upper()
    is_read = False
    is_write = False
    try:
        is_read = bool(ref_type.isRead())
    except Exception:
        is_read = "READ" in s or "DATA" in s
    try:
        is_write = bool(ref_type.isWrite())
    except Exception:
        is_write = "WRITE" in s
    if not is_read and not is_write and "DATA" in s:
        is_read = True
    return is_read, is_write


@dataclass
class AtlasRow:
    address: int
    old_name: str
    data_type: str
    data_len: str
    code_refs: int
    read_refs: int
    write_refs: int
    top_readers: list[tuple[str, int]]
    top_writers: list[tuple[str, int]]
    top_callers: list[tuple[str, int]]


def contiguous_clusters(addrs: Iterable[int], stride: int, min_len: int) -> set[int]:
    sorted_addrs = sorted(set(addrs))
    in_cluster: set[int] = set()
    if not sorted_addrs:
        return in_cluster
    run = [sorted_addrs[0]]
    for a in sorted_addrs[1:]:
        if a - run[-1] == stride:
            run.append(a)
            continue
        if len(run) >= min_len:
            in_cluster.update(run)
        run = [a]
    if len(run) >= min_len:
        in_cluster.update(run)
    return in_cluster


def compute_dat_with_refs(program) -> int:
    st = program.getSymbolTable()
    rm = program.getReferenceManager()
    mem = program.getMemory()
    total = 0
    it = st.getAllSymbols(True)
    while it.hasNext():
        sym = it.next()
        if not sym.getName().startswith("DAT_"):
            continue
        if mem.getBlock(sym.getAddress()) is None:
            continue
        if rm.getReferenceCountTo(sym.getAddress()) > 0:
            total += 1
    return total


def compute_unresolved_dat_code_ge(program, min_code_refs: int) -> int:
    st = program.getSymbolTable()
    rm = program.getReferenceManager()
    fm = program.getFunctionManager()
    mem = program.getMemory()
    total = 0
    it = st.getAllSymbols(True)
    while it.hasNext():
        sym = it.next()
        if not sym.getName().startswith("DAT_"):
            continue
        if mem.getBlock(sym.getAddress()) is None:
            continue
        refs = rm.getReferencesTo(sym.getAddress())
        code_refs = 0
        for ref in refs:
            if fm.getFunctionContaining(ref.getFromAddress()) is not None:
                code_refs += 1
        if code_refs >= min_code_refs:
            total += 1
    return total


def resolve_data_type(program, type_name: str):
    from ghidra.program.model.data import (
        ArrayDataType,
        ByteDataType,
        CharDataType,
        DWordDataType,
        DoubleDataType,
        FloatDataType,
        IntegerDataType,
        PointerDataType,
        ShortDataType,
        UnsignedIntegerDataType,
        UnsignedShortDataType,
        VoidDataType,
    )

    raw = (type_name or "").strip()
    if not raw:
        return None
    arr_len = 0
    m = re.fullmatch(r"(.+)\[(\d+)\]", raw)
    if m:
        raw = m.group(1).strip()
        arr_len = int(m.group(2))

    t = raw.replace(" ", "")
    ptr_depth = 0
    while t.endswith("*"):
        ptr_depth += 1
        t = t[:-1]
    base = t.lower()
    base_map = {
        "byte": ByteDataType.dataType,
        "char": CharDataType.dataType,
        "short": ShortDataType.dataType,
        "ushort": UnsignedShortDataType.dataType,
        "int": IntegerDataType.dataType,
        "uint": UnsignedIntegerDataType.dataType,
        "dword": DWordDataType.dataType,
        "float": FloatDataType.dataType,
        "double": DoubleDataType.dataType,
        "void": VoidDataType.dataType,
    }
    dt = base_map.get(base)
    if dt is None:
        return None
    for _ in range(ptr_depth):
        dt = PointerDataType(dt)
    if arr_len > 0:
        dt = ArrayDataType(dt, arr_len, dt.getLength())
    return dt


def write_csv(path: Path, rows: list[dict[str, str]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--batch-tag", required=True)
    ap.add_argument("--project-root", default=str(Path(__file__).resolve().parents[1]))
    ap.add_argument("--start", default="0x00600000")
    ap.add_argument("--end", default="0x00700000")
    ap.add_argument("--name-regex", default=r"^DAT_")
    ap.add_argument("--min-code-refs", type=int, default=3)
    ap.add_argument("--min-confidence", choices=["low", "medium", "high"], default="medium")
    ap.add_argument("--max-candidates", type=int, default=0, help="0 = no limit")
    ap.add_argument("--read-table-min", type=int, default=4)
    ap.add_argument("--write-hot-min", type=int, default=3)
    ap.add_argument("--cluster-stride", type=int, default=4)
    ap.add_argument("--cluster-min-len", type=int, default=4)
    ap.add_argument(
        "--allow-code1-low-signal",
        action="store_true",
        help="Allow low-signal candidates even when code_refs==1 (use with caution).",
    )
    ap.add_argument(
        "--buckets",
        default="",
        help=(
            "Optional comma-separated bucket allow-list. "
            "Known: runtime_api_cache,write_hot_scalar,read_mostly_table,contiguous_cluster,mixed_state,low_signal"
        ),
    )
    ap.add_argument("--append-csv", default="", help="Optional append target in apply_global_data_from_csv format")
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args()

    root = Path(args.project_root).resolve()
    out_dir = root / "tmp_decomp"
    out_dir.mkdir(parents=True, exist_ok=True)
    tag = args.batch_tag

    atlas_csv = out_dir / f"{tag}_global_atlas.csv"
    atlas_json = out_dir / f"{tag}_global_atlas.json"
    cands_csv = out_dir / f"{tag}_global_candidates.csv"
    apply_csv = out_dir / f"{tag}_global_apply.csv"
    summary_txt = out_dir / f"{tag}_global_wave_summary.txt"

    start_i = parse_hex(args.start)
    end_i = parse_hex(args.end)
    name_re = re.compile(args.name_regex)
    min_conf = confidence_rank(args.min_confidence)
    bucket_allow: set[str] = set()
    if args.buckets.strip():
        bucket_allow = {b.strip() for b in args.buckets.split(",") if b.strip()}

    pyghidra.start(install_dir=GHIDRA_DIR)
    project = open_project_with_lock_cleanup(root)

    with pyghidra.program_context(project, PROGRAM_PATH) as program:
        from ghidra.program.model.symbol import SourceType

        st = program.getSymbolTable()
        rm = program.getReferenceManager()
        fm = program.getFunctionManager()
        listing = program.getListing()
        af = program.getAddressFactory().getDefaultAddressSpace()

        pre_dat_with_refs = compute_dat_with_refs(program)
        pre_unresolved_dat_code_ge = compute_unresolved_dat_code_ge(program, args.min_code_refs)

        atlas_rows: list[AtlasRow] = []
        it = st.getAllSymbols(True)
        while it.hasNext():
            sym = it.next()
            old_name = sym.getName()
            if not name_re.search(old_name):
                continue
            addr = sym.getAddress()
            if addr is None:
                continue
            addr_i = int(str(addr), 16)
            if addr_i < start_i or addr_i >= end_i:
                continue

            refs = list(rm.getReferencesTo(addr))
            code_refs = 0
            read_refs = 0
            write_refs = 0
            readers: defaultdict[str, int] = defaultdict(int)
            writers: defaultdict[str, int] = defaultdict(int)
            callers: defaultdict[str, int] = defaultdict(int)
            for ref in refs:
                from_addr = ref.getFromAddress()
                fn = fm.getFunctionContaining(from_addr)
                if fn is None:
                    continue
                code_refs += 1
                fn_name = fn.getName()
                callers[fn_name] += 1
                is_read, is_write = ref_kind_flags(ref.getReferenceType())
                if is_read:
                    read_refs += 1
                    readers[fn_name] += 1
                if is_write:
                    write_refs += 1
                    writers[fn_name] += 1
            if code_refs < args.min_code_refs:
                continue

            data = listing.getDataAt(addr)
            data_type = str(data.getDataType()) if data is not None else ""
            data_len = str(data.getLength()) if data is not None else ""
            atlas_rows.append(
                AtlasRow(
                    address=addr_i,
                    old_name=old_name,
                    data_type=data_type,
                    data_len=data_len,
                    code_refs=code_refs,
                    read_refs=read_refs,
                    write_refs=write_refs,
                    top_readers=sorted(readers.items(), key=lambda kv: (-kv[1], kv[0]))[:8],
                    top_writers=sorted(writers.items(), key=lambda kv: (-kv[1], kv[0]))[:8],
                    top_callers=sorted(callers.items(), key=lambda kv: (-kv[1], kv[0]))[:8],
                )
            )

        atlas_dict_rows: list[dict[str, str]] = []
        for r in sorted(
            atlas_rows, key=lambda x: (-x.code_refs, -x.write_refs, x.address)
        ):
            atlas_dict_rows.append(
                {
                    "address": f"0x{r.address:08x}",
                    "name": r.old_name,
                    "data_type": r.data_type,
                    "data_len": r.data_len,
                    "code_refs": str(r.code_refs),
                    "read_refs": str(r.read_refs),
                    "write_refs": str(r.write_refs),
                    "top_readers": ";".join(f"{n}:{c}" for n, c in r.top_readers),
                    "top_writers": ";".join(f"{n}:{c}" for n, c in r.top_writers),
                    "top_callers": ";".join(f"{n}:{c}" for n, c in r.top_callers),
                }
            )
        write_csv(
            atlas_csv,
            atlas_dict_rows,
            [
                "address",
                "name",
                "data_type",
                "data_len",
                "code_refs",
                "read_refs",
                "write_refs",
                "top_readers",
                "top_writers",
                "top_callers",
            ],
        )

        cluster_set = contiguous_clusters(
            [r.address for r in atlas_rows], args.cluster_stride, args.cluster_min_len
        )

        all_symbol_names: set[str] = set()
        sit = st.getAllSymbols(True)
        while sit.hasNext():
            all_symbol_names.add(sit.next().getName())

        candidate_rows: list[dict[str, str]] = []
        apply_rows: list[dict[str, str]] = []

        for r in sorted(
            atlas_rows, key=lambda x: (-x.code_refs, -x.write_refs, x.address)
        ):
            anchor = choose_anchor_name(r)

            runtime_hit = any(h in anchor for h in RUNTIME_HINTS)
            bucket, conf = classify_bucket(
                r.write_refs,
                r.read_refs,
                r.code_refs,
                anchor,
                r.address in cluster_set,
                runtime_hit,
                args.allow_code1_low_signal,
            )
            if bucket_allow and bucket not in bucket_allow:
                continue
            if confidence_rank(conf) < min_conf:
                continue

            inferred = infer_type(r.data_type, r.old_name)
            role = build_role(bucket, inferred, r.write_refs)
            toks = build_name_tokens(anchor or r.old_name)
            core = sanitize_symbol_name("_".join(toks[:3]))
            desired = sanitize_symbol_name(f"g_{core}_{role}_{r.address:08X}")
            new_name = make_unique_name(all_symbol_names, desired, r.address)

            comment = (
                f"[auto:{bucket}] refs={r.code_refs} rd={r.read_refs} wr={r.write_refs}; "
                f"anchor={anchor or 'n/a'}"
            )

            candidate_rows.append(
                {
                    "address": f"0x{r.address:08x}",
                    "old_name": r.old_name,
                    "new_name": new_name,
                    "type": inferred,
                    "bucket": bucket,
                    "confidence": conf,
                    "code_refs": str(r.code_refs),
                    "read_refs": str(r.read_refs),
                    "write_refs": str(r.write_refs),
                    "anchor_fn": anchor,
                    "comment": comment,
                }
            )
            apply_rows.append(
                {
                    "address": f"0x{r.address:08x}",
                    "new_name": new_name,
                    "type": inferred,
                    "comment": comment,
                }
            )

        if args.max_candidates > 0:
            candidate_rows = candidate_rows[: args.max_candidates]
            apply_rows = apply_rows[: args.max_candidates]

        write_csv(
            cands_csv,
            candidate_rows,
            [
                "address",
                "old_name",
                "new_name",
                "type",
                "bucket",
                "confidence",
                "code_refs",
                "read_refs",
                "write_refs",
                "anchor_fn",
                "comment",
            ],
        )
        write_csv(apply_csv, apply_rows, ["address", "new_name", "type", "comment"])

        bucket_ctr = Counter(r["bucket"] for r in candidate_rows)
        conf_ctr = Counter(r["confidence"] for r in candidate_rows)

        apply_ok = 0
        apply_skip = 0
        apply_fail = 0
        appended_rows = 0

        if args.apply and apply_rows:
            tx = program.startTransaction("Run global dehardcode wave")
            try:
                for row in apply_rows:
                    try:
                        addr_i = parse_hex(row["address"])
                        addr = af.getAddress(f"0x{addr_i:08x}")
                        new_name = (row.get("new_name") or "").strip()
                        type_txt = (row.get("type") or "").strip()
                        cmt = (row.get("comment") or "").strip()

                        changed = False
                        if type_txt:
                            dt = resolve_data_type(program, type_txt)
                            if dt is not None:
                                end = addr.add(dt.getLength() - 1)
                                listing.clearCodeUnits(addr, end, False)
                                listing.createData(addr, dt)
                                changed = True

                        if new_name:
                            ps = st.getPrimarySymbol(addr)
                            if ps is None:
                                sym = st.createLabel(addr, new_name, SourceType.USER_DEFINED)
                                sym.setPrimary()
                                changed = True
                            elif ps.getName() != new_name:
                                ps.setName(new_name, SourceType.USER_DEFINED)
                                changed = True

                        if cmt:
                            cu = listing.getCodeUnitAt(addr)
                            if cu is not None:
                                cur = cu.getComment(cu.EOL_COMMENT)
                                if cur != cmt:
                                    cu.setComment(cu.EOL_COMMENT, cmt)
                                    changed = True

                        if changed:
                            apply_ok += 1
                        else:
                            apply_skip += 1
                    except Exception:
                        apply_fail += 1
            finally:
                program.endTransaction(tx, True)
            program.save("run global dehardcode wave", None)

            if args.append_csv:
                append_path = Path(args.append_csv)
                if not append_path.is_absolute():
                    append_path = root / append_path
                append_path.parent.mkdir(parents=True, exist_ok=True)
                exists = append_path.exists() and append_path.stat().st_size > 0
                with append_path.open("a", encoding="utf-8", newline="") as fh:
                    w = csv.DictWriter(
                        fh, fieldnames=["address", "new_name", "type", "comment"]
                    )
                    if not exists:
                        w.writeheader()
                    w.writerows(apply_rows)
                    appended_rows = len(apply_rows)

        post_dat_with_refs = compute_dat_with_refs(program)
        post_unresolved_dat_code_ge = compute_unresolved_dat_code_ge(program, args.min_code_refs)

        summary = {
            "batch_tag": tag,
            "scope": {
                "start": f"0x{start_i:08x}",
                "end": f"0x{end_i:08x}",
                "name_regex": args.name_regex,
                "min_code_refs": args.min_code_refs,
            },
            "atlas_rows": len(atlas_rows),
            "candidate_rows": len(candidate_rows),
            "bucket_counts": dict(bucket_ctr),
            "confidence_counts": dict(conf_ctr),
            "applied": bool(args.apply),
            "apply_stats": {
                "ok": apply_ok,
                "skip": apply_skip,
                "fail": apply_fail,
                "appended_rows": appended_rows,
            },
            "pre": {
                "dat_with_refs": pre_dat_with_refs,
                "unresolved_dat_code_ge_min": pre_unresolved_dat_code_ge,
            },
            "post": {
                "dat_with_refs": post_dat_with_refs,
                "unresolved_dat_code_ge_min": post_unresolved_dat_code_ge,
            },
            "outputs": {
                "atlas_csv": str(atlas_csv),
                "atlas_json": str(atlas_json),
                "candidates_csv": str(cands_csv),
                "apply_csv": str(apply_csv),
                "summary_txt": str(summary_txt),
            },
        }

        atlas_json.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        with summary_txt.open("w", encoding="utf-8") as fh:
            fh.write(f"[wave] tag={tag}\n")
            fh.write(f"[scope] start=0x{start_i:08x} end=0x{end_i:08x} regex={args.name_regex}\n")
            fh.write(f"[atlas] rows={len(atlas_rows)}\n")
            fh.write(f"[candidates] rows={len(candidate_rows)} min_conf={args.min_confidence}\n")
            fh.write(
                f"[pre] dat_with_refs={pre_dat_with_refs} unresolved_dat_code_ge_{args.min_code_refs}={pre_unresolved_dat_code_ge}\n"
            )
            fh.write(
                f"[post] dat_with_refs={post_dat_with_refs} unresolved_dat_code_ge_{args.min_code_refs}={post_unresolved_dat_code_ge}\n"
            )
            fh.write(
                f"[apply] enabled={int(args.apply)} ok={apply_ok} skip={apply_skip} fail={apply_fail} append={appended_rows}\n"
            )

        print(
            f"[wave] tag={tag} atlas={len(atlas_rows)} candidates={len(candidate_rows)} "
            f"min_conf={args.min_confidence}"
        )
        print(
            f"[pre] dat_with_refs={pre_dat_with_refs} "
            f"unresolved_dat_code_ge_{args.min_code_refs}={pre_unresolved_dat_code_ge}"
        )
        print(
            f"[post] dat_with_refs={post_dat_with_refs} "
            f"unresolved_dat_code_ge_{args.min_code_refs}={post_unresolved_dat_code_ge}"
        )
        print(
            f"[apply] enabled={int(args.apply)} ok={apply_ok} skip={apply_skip} fail={apply_fail} "
            f"append={appended_rows}"
        )
        print(f"[saved] {atlas_csv}")
        print(f"[saved] {cands_csv}")
        print(f"[saved] {apply_csv}")
        print(f"[saved] {summary_txt}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
