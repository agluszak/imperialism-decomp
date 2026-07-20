#!/usr/bin/env python3
"""Gate real-C++-construction anti-patterns in gameplay code.

Enforces the mechanically-checkable subset of the "real C++ construction and
inheritance" Hard Rules in AGENTS.md. Like the raw-vtable gate, it compares
current per-file pattern counts against a checked-in baseline:
- New files with any tracked pattern fail.
- Existing files may not increase a pattern's count.

The baseline lets pre-existing, knowingly-temporary bridges stay (tracked so they
ratchet downward) while blocking any new occurrence. Patterns that should never
appear (inline asm, placement-new on this, manual vptr writes, thiscall
reinterpret_cast) carry a baseline of 0, so the first new occurrence fails.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

from tools.common.file_scan import is_excluded_scan_path, strip_generated_blocks
from tools.common.ratchet import compare, read_baseline, write_baseline
from tools.common.repo import normalize_repo_relative_path, repo_root_from_file, resolve_repo_path

PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    # Hard Rule 1: no inline assembly.
    ("inline_asm", re.compile(r"\b(?:__asm|_asm)\b|\basm\s*\(")),
    # Construction rule 7: placement-new on this is not base construction.
    ("placement_new_this", re.compile(r"\bnew\s*\(\s*this\s*\)")),
    # Construction rule 2: no manual vtable-pointer writes. Catches the write through
    # `this` (C-style or reinterpret_cast), the same write through ANY object variable,
    # and explicit `obj->vtable = ...` / `obj.vptr = ...` member assignments. To avoid
    # flagging legitimate offset-0 out-param writes (e.g. TFileStream::ReadByte stores a
    # deserialized object pointer), the raw-pointer form requires a vtable-looking RHS:
    # `& <symbol>` or `reinterpret_cast<void*>(0x<const>)`.
    ("manual_vptr_write", re.compile(
        r"\*\s*\(\s*void\s*\*\*\s*\)\s*this\s*="
        r"|\bvptr\s*=\s*g_vtbl"
        r"|\*\s*(?:reinterpret_cast<\s*void\s*\*\*\s*>\s*\(\s*\w+\s*\)|\(\s*void\s*\*\*\s*\)\s*\w+)"
        r"\s*=\s*(?:&|reinterpret_cast<\s*void\s*\*\s*>\s*\(\s*0x)"
        r"|->\s*v(?:f?table|ptr)\s*=\s*(?:reinterpret_cast<\s*void\s*\*\s*>|&)"
        r"|\.\s*v(?:f?table|ptr)\s*=\s*(?:reinterpret_cast<\s*void\s*\*\s*>|&)")),
    # Heuristic note: never reinterpret_cast to a __thiscall function pointer.
    ("thiscall_cast", re.compile(r"reinterpret_cast<[^>]*__thiscall[^>]*>")),
    # Faking a thiscall as __fastcall with a dummy edx second arg (the most-repeated
    # correction in this repo): any function-pointer cast that spells __fastcall, and
    # any fastcall signature whose second parameter is a dummy/edx placeholder.
    ("fastcall_dummy_edx", re.compile(
        r"reinterpret_cast<[^>]*__fastcall[^>]*>"
        r"|__fastcall\s*\*?\s*\w*\s*\)?\s*\([^)]*,\s*(?:int|unsigned int|void\s*\*)\s*"
        r"(?:/\*\s*edx\s*\*/|\bedx\w*|\bunused\w*|\bdummy\w*)")),
    # Function-pointer casts of known symbols in ANY spelling (typedef'd or inline
    # cast to a fn-ptr type): the durable fix is a real method/prototype, not a cast.
    # Baseline-tracked so the legacy bridge inventory can only ratchet down.
    ("fnptr_cast", re.compile(
        r"reinterpret_cast<\s*\w[^>]*\(\s*(?:__cdecl|__stdcall|__fastcall|__thiscall)?\s*\*")),
    # Construction rules 8/16: temporary construction-bridge helper names.
    ("bridge_name", re.compile(r"\b(?:Construct\w*AtThis|VCall_\w*Runtime|\w*AndMaybeFree)\b")),
    # Banned porting approach: class operator new/delete used as a construction factory.
    # Port real methods + real inheritance instead. (Baseline-tracked: ratchet down.)
    ("operator_new_delete", re.compile(r"\boperator\s+(?:new|delete)\s*\(")),
    # Hard Rule 8: raw byte-offset access through `this` instead of a typed field.
    # Baseline-tracked: the existing inventory may only shrink as fields get promoted.
    ("raw_this_offset", re.compile(
        r"reinterpret_cast<\s*(?:unsigned\s+)?char\s*\*\s*>\s*\(\s*this\s*\)\s*\+"
        r"|\(\s*(?:unsigned\s+)?(?:char|BYTE)\s*\*\s*\)\s*this\s*\+")),
)

KEYS = [key for key, _ in PATTERNS]

# Low-level runtime files that may legitimately contain raw construction mechanics,
# documented in-place. Keep this list minimal.
INFRA_ALLOWLIST: set[str] = set()

DEFAULT_EXTENSIONS = {".h", ".hpp", ".c", ".cc", ".cpp"}
GENERATED_MARKERS = ("/ghidra_autogen/", "/autogen/stubs/")


def parse_args() -> argparse.Namespace:
    repo_root = repo_root_from_file(__file__)
    parser = argparse.ArgumentParser()
    parser.add_argument("--roots", nargs="+", default=["src", "include"], help="Root paths to scan.")
    parser.add_argument(
        "--baseline",
        default=str(repo_root / "config" / "baselines" / "construction_gate_baseline.csv"),
        help="CSV file with baseline per-file pattern counts.",
    )
    parser.add_argument(
        "--write-baseline",
        action="store_true",
        help="Write current counts as baseline and exit successfully.",
    )
    return parser.parse_args()


def is_generated(rel: str) -> bool:
    return any(marker in f"/{rel}" for marker in GENERATED_MARKERS)


def collect_files(repo_root: Path, roots: list[str]) -> list[Path]:
    files: list[Path] = []
    for root_value in roots:
        root = resolve_repo_path(repo_root, root_value)
        if not root.exists():
            continue
        if root.is_file():
            if root.suffix.lower() in DEFAULT_EXTENSIONS:
                files.append(root)
            continue
        for path in root.rglob("*"):
            if is_excluded_scan_path(path, roots=[root]):
                continue
            if path.is_file() and path.suffix.lower() in DEFAULT_EXTENSIONS:
                files.append(path)
    return sorted(set(files))


def count_patterns(file_path: Path) -> dict[str, int]:
    text = strip_generated_blocks(file_path.read_text(encoding="utf-8", errors="ignore"))
    return {key: len(pattern.findall(text)) for key, pattern in PATTERNS}


def main() -> int:
    args = parse_args()
    repo_root = repo_root_from_file(__file__)
    baseline_path = resolve_repo_path(repo_root, args.baseline)

    current: dict[str, dict[str, int]] = {}
    for file_path in collect_files(repo_root, args.roots):
        rel = normalize_repo_relative_path(file_path, repo_root)
        if rel in INFRA_ALLOWLIST or is_generated(rel):
            continue
        counts = count_patterns(file_path)
        if sum(counts.values()) == 0:
            continue
        current[rel] = counts

    if args.write_baseline:
        write_baseline(baseline_path, current, KEYS)
        print(f"Wrote baseline: {baseline_path} ({len(current)} files)")
        return 0

    baseline = read_baseline(baseline_path, KEYS)
    if not baseline:
        print(f"Baseline missing: {baseline_path}")
        print("Run with --write-baseline once, then re-run the gate.")
        return 1

    def _new_file(file_key: str, counts: dict[str, int]) -> str:
        present = ", ".join(k for k in KEYS if counts.get(k, 0))
        return f"{file_key}: new construction anti-pattern(s) [{present}] (not in baseline)"

    violations = compare(current, baseline, KEYS, new_file_message=_new_file)

    if violations:
        print("Construction anti-pattern gate failed:")
        for item in violations:
            print(f"  - {item}")
        print("See AGENTS.md 'Hard rules: real C++ construction and inheritance'.")
        print(f"Baseline: {baseline_path}")
        return 1

    scanned_total = sum(sum(values.values()) for values in current.values())
    print(
        f"Construction anti-pattern gate passed. Baseline-tracked files: {len(current)} "
        f"(total matches: {scanned_total})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
