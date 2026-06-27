#!/usr/bin/env python3
"""Migrate proven CObject runtime-class bodies to MFC macros.

The source migration is intentionally evidence-driven.  The input scan records
the original CRuntimeClass descriptor address, base descriptor, schema, and
create-object pointer.  This script chooses the narrowest MFC macro matching
that descriptor:

* schema != 0xffff  -> DECLARE/IMPLEMENT_SERIAL
* create != 0       -> DECLARE/IMPLEMENT_DYNCREATE
* otherwise         -> DECLARE/IMPLEMENT_DYNAMIC

Dry-run is the default.  Pass --apply after reviewing the skipped candidates.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tools.common.repo import normalize_repo_relative_path, repo_root_from_file, resolve_repo_path
from tools.workflow.function_ownership import (
    FunctionOwnership,
    load_function_ownership,
    write_function_ownership,
)

SCHEMA_DYNAMIC = 0xFFFF
COBJECT_DESC_ADDR = 0x006706E0
IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


@dataclass(frozen=True)
class RuntimeRecord:
    class_name: str
    base_name: str
    desc_addr: int
    fn_addr: int
    schema: int
    create_addr: int


@dataclass
class Candidate:
    record: RuntimeRecord
    macro_kind: str
    header_path: Path
    source_path: Path
    existing_decl: str | None
    old_descriptor_symbol: str | None

    @property
    def declare_macro(self) -> str:
        return f"DECLARE_{self.macro_kind}({self.record.class_name})"

    @property
    def implement_macro(self) -> str:
        cls = self.record.class_name
        base = self.record.base_name
        if self.macro_kind == "SERIAL":
            return f"IMPLEMENT_SERIAL({cls}, {base}, {self.record.schema})"
        if self.macro_kind == "DYNCREATE":
            return f"IMPLEMENT_DYNCREATE({cls}, {base})"
        return f"IMPLEMENT_DYNAMIC({cls}, {base})"


@dataclass(frozen=True)
class Skip:
    class_name: str
    reason: str


def parse_args() -> argparse.Namespace:
    repo_root = repo_root_from_file(__file__)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--scan",
        default=str(repo_root / "tmp_decomp" / "cobject_backbone_scan.json"),
        help="JSON scan with CRuntimeClass descriptor-chain evidence.",
    )
    parser.add_argument("--symbols-csv", default=str(repo_root / "config" / "symbols.csv"))
    parser.add_argument(
        "--ownership-csv", default=str(repo_root / "config" / "function_ownership.csv")
    )
    parser.add_argument(
        "--classes",
        default="",
        help="Comma-separated class-name allowlist. Default: every eligible scan record.",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Write source/config changes. Default is dry-run.",
    )
    parser.add_argument("--limit", type=int, default=0, help="Process at most N candidates.")
    parser.add_argument("--verbose", action="store_true", help="Print skipped classes.")
    return parser.parse_args()


def as_int(value: Any) -> int:
    if value is None:
        return 0
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return 0
        return int(text, 0)
    raise TypeError(f"unexpected integer value: {value!r}")


def load_records(scan_path: Path, only: set[str] | None) -> tuple[list[RuntimeRecord], list[Skip]]:
    payload = json.loads(scan_path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise SystemExit(f"Expected list payload in {scan_path}")

    records: list[RuntimeRecord] = []
    skips: list[Skip] = []
    seen: set[str] = set()
    for raw in payload:
        if not isinstance(raw, dict):
            continue
        cls = str(raw.get("class_name") or raw.get("class_guess") or "").strip()
        if not cls:
            continue
        if only is not None and cls not in only:
            continue
        if cls in seen:
            skips.append(Skip(cls, "duplicate scan record"))
            continue
        seen.add(cls)
        if not IDENT_RE.match(cls):
            skips.append(Skip(cls, "class name is not a C++ identifier"))
            continue
        if not raw.get("rooted_cobject"):
            skips.append(Skip(cls, "descriptor chain is not CObject-rooted"))
            continue

        chain_names = raw.get("chain_names")
        chain = raw.get("chain")
        if not isinstance(chain_names, list) or len(chain_names) < 2:
            skips.append(Skip(cls, "missing base chain name"))
            continue
        if not isinstance(chain, list) or len(chain) < 2:
            skips.append(Skip(cls, "missing base descriptor chain"))
            continue

        base_label = str(chain_names[1]).strip()
        base_desc = as_int(chain[1])
        if base_desc == COBJECT_DESC_ADDR:
            base_name = "CObject"
        elif IDENT_RE.match(base_label):
            base_name = base_label
        else:
            skips.append(Skip(cls, f"unresolved base descriptor {base_label}"))
            continue

        records.append(
            RuntimeRecord(
                class_name=cls,
                base_name=base_name,
                desc_addr=as_int(raw.get("desc")),
                fn_addr=as_int(raw.get("fn")),
                schema=as_int(raw.get("schema")),
                create_addr=as_int(raw.get("create")),
            )
        )
    return records, skips


def choose_macro(record: RuntimeRecord) -> str:
    if record.schema != SCHEMA_DYNAMIC:
        return "SERIAL"
    if record.create_addr != 0:
        return "DYNCREATE"
    return "DYNAMIC"


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def write_text_if_changed(path: Path, text: str) -> bool:
    current = read_text(path)
    if current == text:
        return False
    path.write_text(text, encoding="utf-8", newline="\n")
    return True


def find_class_file(
    root: Path, subdir: str, cls: str, suffixes: tuple[str, ...], pattern: re.Pattern[str]
) -> Path | None:
    preferred = root / subdir / f"{cls}{suffixes[0]}"
    if preferred.is_file() and pattern.search(read_text(preferred)):
        return preferred

    matches: list[Path] = []
    for path in sorted((root / subdir).rglob("*")):
        if path.suffix.lower() not in {".h", ".hpp", ".cpp", ".cc", ".cxx"}:
            continue
        if path.name == preferred.name:
            continue
        if pattern.search(read_text(path)):
            matches.append(path)
    if len(matches) == 1:
        return matches[0]
    return None


def find_header(repo_root: Path, record: RuntimeRecord) -> tuple[Path | None, str | None]:
    cls = re.escape(record.class_name)
    class_re = re.compile(rf"\bclass\s+{cls}\s*:\s*public\s+([A-Za-z_][A-Za-z0-9_]*)")
    path = find_class_file(repo_root, "include/game", record.class_name, (".h",), class_re)
    if path is None:
        return None, "header class declaration not uniquely found"

    match = class_re.search(read_text(path))
    if match is None:
        return None, "header class declaration not found"
    actual_base = match.group(1)
    if actual_base != record.base_name:
        return None, f"header base is {actual_base or '<none>'}, descriptor base is {record.base_name}"
    return path, None


def class_body(text: str, cls: str) -> str | None:
    match = re.search(rf"\bclass\s+{re.escape(cls)}\s*:\s*public\s+[A-Za-z_][A-Za-z0-9_]*", text)
    if match is None:
        return None
    brace = text.find("{", match.end())
    if brace < 0:
        return None
    depth = 0
    for index in range(brace, len(text)):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[brace + 1 : index]
    return None


def has_default_constructor_declaration(header_text: str, cls: str) -> bool:
    """Return True if the class has (or can synthesize) a default constructor.

    A default constructor is available when:
    - no constructors are declared at all (compiler synthesises one), OR
    - at least one constructor takes no required arguments (no args, or all
      args have defaults).
    Inline-defined constructors in the header count as declarations here.
    """
    body = class_body(header_text, cls)
    if body is None:
        return False

    constructor_re = re.compile(rf"(?m)^\s*(?:explicit\s+)?{re.escape(cls)}\s*\((?P<args>[^)]*)\)")
    constructors = list(constructor_re.finditer(body))
    if not constructors:
        return True  # compiler will synthesise a default ctor

    for constructor in constructors:
        args = constructor.group("args").strip()
        if not args or args == "void":
            return True
    return False


# Keep the old name as an alias used by make_candidate
has_default_constructor_available = has_default_constructor_declaration


def source_defines_default_constructor(source_text: str, cls: str) -> bool:
    """Return True if source_text contains an out-of-line definition of cls::cls()."""
    ctor_re = re.compile(
        rf"(?m)^\s*{re.escape(cls)}::{re.escape(cls)}\s*\([^)]*\)\s*(?::|{{)"
    )
    return bool(ctor_re.search(source_text))


def header_has_inline_ctor_body(header_text: str, cls: str) -> bool:
    """Return True if the header defines the default constructor with a body inline."""
    body = class_body(header_text, cls)
    if body is None:
        return False
    # Match ClassName(...) { or ClassName(...) : base(...) {
    inline_re = re.compile(
        rf"(?s)\b{re.escape(cls)}\s*\([^)]*\)\s*(?::[^{{]*)?{{"
    )
    return bool(inline_re.search(body))


def inject_default_constructor(text: str, cls: str) -> str:
    """Insert ClassName::ClassName() {} after the IMPLEMENT macro for cls."""
    impl_re = re.compile(
        rf"(\bIMPLEMENT_(?:DYNCREATE|SERIAL|DYNAMIC)\s*\(\s*{re.escape(cls)}\s*,[^)]*\))",
        re.MULTILINE,
    )
    m = impl_re.search(text)
    if not m:
        return text
    insert_pos = m.end()
    return text[:insert_pos] + f"\n\n{cls}::{cls}() {{}}" + text[insert_pos:]


def find_source(repo_root: Path, record: RuntimeRecord) -> tuple[Path | None, str | None]:
    cls = re.escape(record.class_name)
    method_re = re.compile(rf"\bCRuntimeClass\s*\*\s*{cls}::GetRuntimeClass\s*\(\s*\)\s*const\b")
    macro_re = re.compile(
        rf"\bIMPLEMENT_(?:DYNAMIC|DYNCREATE|SERIAL)\s*\(\s*{cls}\s*,", re.MULTILINE
    )
    preferred = repo_root / "src/game" / f"{record.class_name}.cpp"
    if preferred.is_file():
        text = read_text(preferred)
        if method_re.search(text) or macro_re.search(text):
            return preferred, None

    matches: list[Path] = []
    for path in sorted((repo_root / "src/game").rglob("*.cpp")):
        if path == preferred:
            continue
        text = read_text(path)
        if method_re.search(text) or macro_re.search(text):
            matches.append(path)
    if len(matches) != 1:
        return None, "source GetRuntimeClass/IMPLEMENT macro not uniquely found"
    return matches[0], None


def make_candidate(repo_root: Path, record: RuntimeRecord) -> Candidate | Skip:
    header_path, header_error = find_header(repo_root, record)
    if header_path is None:
        return Skip(record.class_name, header_error or "header not found")
    header_text = read_text(header_path)
    if choose_macro(record) in {"SERIAL", "DYNCREATE"} and not has_default_constructor_available(
        header_text, record.class_name
    ):
        return Skip(record.class_name, "no visible default constructor for MFC CreateObject")
    source_path, source_error = find_source(repo_root, record)
    if source_path is None:
        return Skip(record.class_name, source_error or "source not found")

    decl_match = re.search(
        rf"\bDECLARE_(DYNAMIC|DYNCREATE|SERIAL)\s*\(\s*{re.escape(record.class_name)}\s*\)",
        header_text,
    )
    existing_decl = decl_match.group(1) if decl_match else None

    source_text = read_text(source_path)
    old_descriptor_symbol = extract_returned_descriptor_symbol(source_text, record.class_name)
    return Candidate(
        record=record,
        macro_kind=choose_macro(record),
        header_path=header_path,
        source_path=source_path,
        existing_decl=existing_decl,
        old_descriptor_symbol=old_descriptor_symbol,
    )


def get_runtime_class_regex(cls: str) -> re.Pattern[str]:
    return re.compile(
        rf"(?ms)"
        rf"(?P<marker>\s*//\s*FUNCTION:\s*IMPERIALISM\s+0x[0-9a-fA-F]+\s*)?"
        rf"\n?\s*CRuntimeClass\s*\*\s*{re.escape(cls)}::GetRuntimeClass\s*"
        rf"\(\s*\)\s*const\s*\{{(?P<body>.*?)\}}",
    )


def extract_returned_descriptor_symbol(source_text: str, cls: str) -> str | None:
    match = get_runtime_class_regex(cls).search(source_text)
    if match is None:
        return None
    body = match.group("body")
    ret = re.search(r"\breturn\s+&\s*([A-Za-z_][A-Za-z0-9_]*)\s*;", body)
    if ret:
        return ret.group(1)
    return None


def replace_header_decl(text: str, candidate: Candidate) -> tuple[str, bool]:
    cls = candidate.record.class_name
    macro = candidate.declare_macro
    existing_macro_re = re.compile(
        rf"\bDECLARE_(?:DYNAMIC|DYNCREATE|SERIAL)\s*\(\s*{re.escape(cls)}\s*\)"
    )
    if existing_macro_re.search(text):
        return existing_macro_re.sub(macro, text, count=1), True

    decl_re = re.compile(
        rf"(?m)^(?P<indent>\s*)(?:virtual\s+)?CRuntimeClass\s*\*\s*GetRuntimeClass\s*"
        rf"\(\s*\)\s*const\s*(?:override)?\s*;\s*(?P<comment>//[^\n]*)?$"
    )

    def repl(match: re.Match[str]) -> str:
        return f"{match.group('indent')}{macro}"

    updated, count = decl_re.subn(repl, text, count=1)
    return updated, bool(count)


def remove_descriptor_declaration(text: str, symbol: str | None) -> str:
    if not symbol:
        return text

    sym = re.escape(symbol)
    line_re = re.compile(
        rf"(?m)^\s*(?:extern\s+\"C\"\s+)?CRuntimeClass\s+{sym}\s*=\s*"
        rf"\{{[^;\n]*\}};\s*\n?"
    )
    text = line_re.sub("", text)

    block_re = re.compile(r"(?ms)extern\s+\"C\"\s*\{\s*(?P<body>.*?)\s*\}\s*")

    def clean_block(match: re.Match[str]) -> str:
        body = match.group("body")
        body = line_re.sub("", body)
        if body.strip():
            return 'extern "C" {\n' + body.strip("\n") + "\n}\n\n"
        return ""

    return block_re.sub(clean_block, text)


def replace_source_impl(text: str, candidate: Candidate) -> tuple[str, bool]:
    cls = candidate.record.class_name
    impl = candidate.implement_macro
    macro_re = re.compile(
        rf"\bIMPLEMENT_(?:DYNAMIC|DYNCREATE|SERIAL)\s*\(\s*{re.escape(cls)}\s*,[^;\n]*\)",
        re.MULTILINE,
    )
    if macro_re.search(text):
        updated = macro_re.sub(impl, text, count=1)
        return remove_descriptor_declaration(updated, candidate.old_descriptor_symbol), True

    method_re = get_runtime_class_regex(cls)
    if not method_re.search(text):
        return text, False
    updated = method_re.sub("\n" + impl, text, count=1)
    updated = remove_descriptor_declaration(updated, candidate.old_descriptor_symbol)
    updated = re.sub(r"\n{3,}", "\n\n", updated)
    return updated, True


def load_pipe_table(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with path.open("r", encoding="utf-8", newline="") as fd:
        reader = csv.DictReader(fd, delimiter="|")
        return list(reader.fieldnames or []), list(reader)


def write_pipe_table(path: Path, fieldnames: list[str], rows: list[dict[str, str]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as fd:
        writer = csv.DictWriter(fd, fieldnames=fieldnames, delimiter="|", lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def update_symbols(symbols_path: Path, candidates: list[Candidate]) -> int:
    fields, rows = load_pipe_table(symbols_path)
    if not fields:
        raise SystemExit(f"Missing header in {symbols_path}")

    by_addr: dict[int, dict[str, str]] = {}
    for row in rows:
        raw = (row.get("address") or "").strip()
        if not raw:
            continue
        try:
            by_addr[int(raw, 16)] = row
        except ValueError:
            continue

    updates = 0
    for candidate in candidates:
        rec = candidate.record
        desc_name = f"{rec.class_name}::class{rec.class_name}"
        desc_row = by_addr.get(rec.desc_addr)
        if desc_row is None:
            desc_row = {field: "" for field in fields}
            desc_row["address"] = format(rec.desc_addr, "x")
            by_addr[rec.desc_addr] = desc_row
            insert_at = len(rows)
            for index, row in enumerate(rows):
                try:
                    row_addr = int((row.get("address") or "0"), 16)
                except ValueError:
                    continue
                if row_addr > rec.desc_addr:
                    insert_at = index
                    break
            rows.insert(insert_at, desc_row)
            updates += 1
        for key, value in (("name", desc_name), ("type", "global"), ("size", ""), ("prototype", "")):
            if desc_row.get(key, "") != value:
                desc_row[key] = value
                updates += 1

        fn_row = by_addr.get(rec.fn_addr)
        if fn_row is not None:
            fn_name = f"{rec.class_name}::GetRuntimeClass"
            if fn_row.get("name") != fn_name:
                fn_row["name"] = fn_name
                updates += 1

    if updates:
        write_pipe_table(symbols_path, fields, rows)
    return updates


def update_ownership(repo_root: Path, ownership_path: Path, candidates: list[Candidate]) -> int:
    entries = load_function_ownership(ownership_path)
    updates = 0
    for candidate in candidates:
        rel_source = normalize_repo_relative_path(candidate.source_path, repo_root)
        entry = FunctionOwnership(
            address=candidate.record.fn_addr,
            target_cpp=rel_source,
            ownership="manual",
            note="mfc_runtime_macro",
        )
        if entries.get(candidate.record.fn_addr) != entry:
            entries[candidate.record.fn_addr] = entry
            updates += 1
    write_function_ownership(ownership_path, entries)
    return updates


def apply_candidates(candidates: list[Candidate]) -> tuple[int, int]:
    header_edits = 0
    source_edits = 0

    by_header: dict[Path, list[Candidate]] = {}
    by_source: dict[Path, list[Candidate]] = {}
    for candidate in candidates:
        by_header.setdefault(candidate.header_path, []).append(candidate)
        by_source.setdefault(candidate.source_path, []).append(candidate)

    for path, path_candidates in by_header.items():
        text = read_text(path)
        changed = False
        for candidate in path_candidates:
            text, ok = replace_header_decl(text, candidate)
            changed = changed or ok
        if write_text_if_changed(path, text):
            header_edits += 1
        elif changed:
            header_edits += 0

    for path, path_candidates in by_source.items():
        text = read_text(path)
        changed = False
        for candidate in path_candidates:
            text, ok = replace_source_impl(text, candidate)
            changed = changed or ok

            # Inject a no-arg constructor body when DYNCREATE/SERIAL needs
            # `new ClassName` but no out-of-line definition exists yet and the
            # header doesn't have an inline body either.
            if (
                ok
                and candidate.macro_kind in {"DYNCREATE", "SERIAL"}
                and not source_defines_default_constructor(text, candidate.record.class_name)
                and not header_has_inline_ctor_body(read_text(candidate.header_path), candidate.record.class_name)
            ):
                text = inject_default_constructor(text, candidate.record.class_name)
                changed = True

        if write_text_if_changed(path, text):
            source_edits += 1
        elif changed:
            source_edits += 0

    return header_edits, source_edits


def main() -> int:
    args = parse_args()
    repo_root = repo_root_from_file(__file__)
    scan_path = resolve_repo_path(repo_root, args.scan)
    symbols_path = resolve_repo_path(repo_root, args.symbols_csv)
    ownership_path = resolve_repo_path(repo_root, args.ownership_csv)

    only = {item.strip() for item in args.classes.split(",") if item.strip()} or None
    records, scan_skips = load_records(scan_path, only)

    candidates: list[Candidate] = []
    skips: list[Skip] = list(scan_skips)
    for record in records:
        candidate = make_candidate(repo_root, record)
        if isinstance(candidate, Skip):
            skips.append(candidate)
            continue
        candidates.append(candidate)

    if args.limit:
        candidates = candidates[: args.limit]

    print("MFC runtime macro migration")
    print(f"Mode: {'APPLY' if args.apply else 'DRY-RUN'}")
    print(f"Candidates: {len(candidates)}")
    print(f"Skipped: {len(skips)}")
    by_kind: dict[str, int] = {}
    for candidate in candidates:
        by_kind[candidate.macro_kind] = by_kind.get(candidate.macro_kind, 0) + 1
    for kind in ("SERIAL", "DYNCREATE", "DYNAMIC"):
        print(f"  {kind}: {by_kind.get(kind, 0)}")

    for candidate in candidates[:30]:
        rel_header = normalize_repo_relative_path(candidate.header_path, repo_root)
        rel_source = normalize_repo_relative_path(candidate.source_path, repo_root)
        print(
            f"  {candidate.record.class_name}: {candidate.implement_macro} "
            f"desc=0x{candidate.record.desc_addr:08x} fn=0x{candidate.record.fn_addr:08x} "
            f"{rel_header} {rel_source}"
        )
    if len(candidates) > 30:
        print(f"  ... {len(candidates) - 30} more candidates")

    if args.verbose and skips:
        print("Skipped candidates:")
        for skip in skips:
            print(f"  {skip.class_name}: {skip.reason}")

    if not args.apply:
        print("Re-run with --apply to write source/config changes.")
        return 0

    header_edits, source_edits = apply_candidates(candidates)
    symbol_updates = update_symbols(symbols_path, candidates)
    ownership_updates = update_ownership(repo_root, ownership_path, candidates)
    print(f"Edited headers: {header_edits}")
    print(f"Edited sources: {source_edits}")
    print(f"symbols.csv cell/row updates: {symbol_updates}")
    print(f"function_ownership.csv updates: {ownership_updates}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
