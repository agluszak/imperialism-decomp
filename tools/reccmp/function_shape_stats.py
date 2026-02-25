#!/usr/bin/env python3
"""Classify function inventory by shape (stub/no-op/wrapper/non-trivial)."""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path

from tools.common.pipe_csv import read_pipe_rows

ANNOTATION_RE_TEMPLATE = (
    r"//\s*(FUNCTION|STUB|TEMPLATE|SYNTHETIC|LIBRARY)\s*:\s*{target}\s+"
    r"(?:0x)?([0-9a-fA-F]+)"
)

LINE_COMMENT_RE = re.compile(r"//.*?$", re.MULTILINE)
BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
WS_RE = re.compile(r"\s+")
CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_:]*)\s*\(")

KEYWORD_CALLS = {
    "if",
    "for",
    "while",
    "switch",
    "return",
    "sizeof",
    "catch",
    "do",
}
CONTROL_KEYWORDS = ("if", "for", "while", "switch", "goto", "try", "catch", "do")


@dataclass(frozen=True)
class FunctionInfo:
    address: int
    name: str
    source_file: str
    body_kind: str
    bucket: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="IMPERIALISM")
    parser.add_argument("--symbols-csv", default="config/symbols.csv")
    parser.add_argument("--source-dir", default="src")
    parser.add_argument("--top", type=int, default=15)
    parser.add_argument("--json-out", default="")
    return parser.parse_args()


def load_symbols(symbols_csv: Path) -> dict[int, str]:
    if not symbols_csv.is_file():
        raise FileNotFoundError(f"Missing symbols CSV: {symbols_csv}")

    out: dict[int, str] = {}
    for row in read_pipe_rows(symbols_csv):
        row_type = (row.get("type") or "").strip().lower()
        if row_type != "function":
            continue
        addr_text = (row.get("address") or "").strip()
        name = (row.get("name") or "").strip()
        if not addr_text or not name:
            continue
        out[int(addr_text, 16)] = name
    return out


def iter_annotated_blocks(source_dir: Path, target: str) -> list[tuple[int, str, str]]:
    annotation_re = re.compile(
        ANNOTATION_RE_TEMPLATE.format(target=re.escape(target)), re.IGNORECASE
    )
    rows: list[tuple[int, str, str]] = []

    for path in sorted(source_dir.rglob("*.cpp")):
        text = path.read_text(encoding="utf-8", errors="ignore")
        matches = list(annotation_re.finditer(text))
        if not matches:
            continue
        for i, match in enumerate(matches):
            start = match.start()
            end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
            addr = int(match.group(2), 16)
            rows.append((addr, str(path), text[start:end]))
    return rows


def extract_body(block: str) -> str:
    brace_start = block.find("{")
    if brace_start < 0:
        return ""
    depth = 0
    for idx in range(brace_start, len(block)):
        ch = block[idx]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return block[brace_start + 1 : idx]
    return ""


def normalize_body(body: str) -> str:
    text = BLOCK_COMMENT_RE.sub(" ", body)
    text = LINE_COMMENT_RE.sub(" ", text)
    text = WS_RE.sub(" ", text).strip()
    return text


def classify_body(body: str) -> str:
    normalized = normalize_body(body)
    if not normalized:
        return "empty"

    if any(re.search(rf"\b{kw}\b", normalized) for kw in CONTROL_KEYWORDS):
        return "nontrivial_control_flow"

    if re.fullmatch(r"(\(void\)\s*[A-Za-z_][A-Za-z0-9_]*\s*;\s*)*return\s*;", normalized):
        return "noop_return_void"

    if re.fullmatch(
        r"(\(void\)\s*[A-Za-z_][A-Za-z0-9_]*\s*;\s*)*return\s+[-]?[0-9]+\s*;",
        normalized,
    ):
        return "noop_return_const"

    if re.fullmatch(
        r"(\(void\)\s*[A-Za-z_][A-Za-z0-9_]*\s*;\s*)*"
        r"[A-Za-z_][A-Za-z0-9_:]*\s*\([^;{}]*\)\s*;\s*return\s*;",
        normalized,
    ):
        return "wrapper_call_then_return"

    if re.fullmatch(r"return\s+[A-Za-z_][A-Za-z0-9_:]*\s*\([^;{}]*\)\s*;", normalized):
        return "wrapper_return_call"

    calls = [name for name in CALL_RE.findall(normalized) if name not in KEYWORD_CALLS]
    if len(calls) == 1 and normalized.count(";") <= 3:
        return "wrapper_likely"

    return "nontrivial"


def classify_bucket(path: str, name: str, body_kind: str) -> str:
    if path.endswith("src/autogen/stubs.cpp"):
        return "autogen_stub"

    if body_kind in {"noop_return_void", "noop_return_const", "empty"}:
        return "manual_noop"

    if body_kind in {"wrapper_call_then_return", "wrapper_return_call", "wrapper_likely"}:
        if name.startswith("thunk_"):
            return "manual_thunk_wrapper"
        return "manual_wrapper"

    if name.startswith("thunk_"):
        return "manual_thunk_nontrivial"

    return "manual_nontrivial"


def pct(part: int, total: int) -> float:
    if total <= 0:
        return 0.0
    return (part / total) * 100.0


def print_counts(title: str, counts: dict[str, int], total: int) -> None:
    print(title)
    for key, value in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
        print(f"  {key}: {value} ({pct(value, total):.2f}%)")


def main() -> int:
    args = parse_args()
    symbols_csv = Path(args.symbols_csv)
    source_dir = Path(args.source_dir)

    names_by_addr = load_symbols(symbols_csv)
    blocks = iter_annotated_blocks(source_dir=source_dir, target=args.target)
    blocks_by_addr = {addr: (path, block) for addr, path, block in blocks}

    function_infos: list[FunctionInfo] = []
    missing_in_src = 0
    for addr, name in sorted(names_by_addr.items()):
        entry = blocks_by_addr.get(addr)
        if entry is None:
            missing_in_src += 1
            continue
        path, block = entry
        body_kind = classify_body(extract_body(block))
        bucket = classify_bucket(path=path, name=name, body_kind=body_kind)
        function_infos.append(
            FunctionInfo(
                address=addr,
                name=name,
                source_file=path,
                body_kind=body_kind,
                bucket=bucket,
            )
        )

    total = len(names_by_addr)
    classified_total = len(function_infos)
    named_thunk = sum(1 for info in function_infos if info.name.startswith("thunk_"))
    named_noop = sum(1 for info in function_infos if "noop" in info.name.lower())

    bucket_counts: dict[str, int] = {}
    body_counts: dict[str, int] = {}
    for info in function_infos:
        bucket_counts[info.bucket] = bucket_counts.get(info.bucket, 0) + 1
        body_counts[info.body_kind] = body_counts.get(info.body_kind, 0) + 1

    manual_infos = [info for info in function_infos if info.bucket != "autogen_stub"]
    manual_bucket_counts: dict[str, int] = {}
    manual_body_counts: dict[str, int] = {}
    for info in manual_infos:
        manual_bucket_counts[info.bucket] = manual_bucket_counts.get(info.bucket, 0) + 1
        manual_body_counts[info.body_kind] = manual_body_counts.get(info.body_kind, 0) + 1

    print(f"Target: {args.target}")
    print(f"Functions in symbols CSV: {total}")
    print(f"Classified from source markers: {classified_total}")
    print(f"Missing marker entries: {missing_in_src}")
    print()
    print(f"Named thunks (prefix 'thunk_'): {named_thunk} ({pct(named_thunk, total):.2f}%)")
    print(f"Named no-ops (contains 'noop'): {named_noop} ({pct(named_noop, total):.2f}%)")
    print()

    print_counts("Bucket breakdown:", bucket_counts, total)
    print()
    print_counts("Body-shape breakdown:", body_counts, total)
    print()
    print(f"Manual functions only: {len(manual_infos)}")
    print_counts("Manual bucket breakdown:", manual_bucket_counts, len(manual_infos))
    print()
    print_counts("Manual body-shape breakdown:", manual_body_counts, len(manual_infos))

    top_nontrivial = [
        info
        for info in function_infos
        if info.bucket in {"manual_nontrivial", "manual_thunk_nontrivial"}
    ]
    top_nontrivial = sorted(top_nontrivial, key=lambda i: i.address)[: args.top]
    if top_nontrivial:
        print()
        print(f"Sample manual non-trivial ({min(args.top, len(top_nontrivial))}):")
        for info in top_nontrivial:
            print(f"  0x{info.address:08x} {info.name} [{info.body_kind}] ({info.source_file})")

    if args.json_out:
        out_path = Path(args.json_out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "target": args.target,
            "total_functions": total,
            "classified_functions": classified_total,
            "missing_in_source": missing_in_src,
            "named_thunk_count": named_thunk,
            "named_noop_count": named_noop,
            "bucket_counts": bucket_counts,
            "body_counts": body_counts,
            "manual_function_count": len(manual_infos),
            "manual_bucket_counts": manual_bucket_counts,
            "manual_body_counts": manual_body_counts,
        }
        out_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        print()
        print(f"Wrote JSON: {out_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
