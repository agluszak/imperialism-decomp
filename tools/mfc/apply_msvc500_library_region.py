#!/usr/bin/env python3
"""Apply MSVC500 FID matches as generated `// LIBRARY:` markers for a bounded range."""

from __future__ import annotations

import argparse
import csv
import re
from dataclasses import dataclass
from pathlib import Path

from reccmp.cvdump.demangler import msvc_demangle

from tools.common.hexutil import parse_hex_address
from tools.common.pipe_csv import read_pipe_table
from tools.common.repo import normalize_repo_relative_path, repo_root_from_file, resolve_repo_path
from tools.ghidra.merge_curated_symbols import write_symbols_csv


DEFAULT_START = "0x005e539c"
DEFAULT_END = "0x00626c7d"
DEFAULT_FID_MATCHES = "tmp_decomp/msvc500_fid_matches.csv"
DEFAULT_REVIEW_MAP = "tmp_decomp/msvc500_library_identity_map.csv"
DEFAULT_SYMBOLS = "config/original_entities.csv"
DEFAULT_MARKERS = "src/game/library_msvc500_fid.cpp"
DEFAULT_FAMILIES = "nafxcw,libcmt"
DEFAULT_RANGE_AUDIT = "tmp_decomp/msvc500_library_range_audit.csv"
DEFAULT_LIBRARY_FUNCTIONS = "vendor/msvc500/fid-generation/fidb/functions.txt"

MARKER_RE = re.compile(
    r"//\s*(?P<kind>FUNCTION|STUB|TEMPLATE|SYNTHETIC|LIBRARY)\s*:\s*"
    r"(?P<target>\w+)\s+(?:0x)?(?P<address>[0-9a-fA-F]+)",
    re.IGNORECASE,
)
IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
SymbolTarget = tuple[str, str | None, bool]


@dataclass(frozen=True)
class SourceMarker:
    kind: str
    path: str
    name: str = ""


@dataclass
class Candidate:
    address: int
    current_name: str
    fid_name: str
    display_name: str
    symbol_name: str
    fid_name_has_address_suffix: bool
    domain_path: str
    library_family: str
    library_version: str
    library_variant: str
    overall_score: str
    existing_marker_kind: str = ""
    existing_marker_path: str = ""
    existing_ownership: str = ""
    existing_target_cpp: str = ""
    action: str = ""
    reason: str = ""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate/apply LIBRARY markers from MSVC500 FID matches."
    )
    parser.add_argument("--fid-matches", default=DEFAULT_FID_MATCHES)
    parser.add_argument("--symbols", default=DEFAULT_SYMBOLS)
    parser.add_argument("--range-audit", default=DEFAULT_RANGE_AUDIT)
    parser.add_argument("--library-functions", default=DEFAULT_LIBRARY_FUNCTIONS)
    parser.add_argument("--library-markers", default=DEFAULT_MARKERS)
    parser.add_argument("--out-map", default=DEFAULT_REVIEW_MAP)
    parser.add_argument("--target", default="IMPERIALISM")
    parser.add_argument("--start", default=DEFAULT_START)
    parser.add_argument("--end", default=DEFAULT_END)
    parser.add_argument(
        "--families",
        default=DEFAULT_FAMILIES,
        help="Comma-separated FID library families to accept.",
    )
    parser.add_argument(
        "--include-manual",
        action="store_true",
        help="Allow converting existing non-LIBRARY source markers. Default: report-only skip.",
    )
    parser.add_argument("--apply", action="store_true", help="Write symbols/markers.")
    parser.add_argument(
        "--allow-marker-removals",
        action="store_true",
        help=(
            "Permit shrinking the generated LIBRARY marker set. The matches CSV is "
            "treated as the complete source of truth, so running --apply with a "
            "partial tmp_decomp/msvc500_fid_matches.csv would otherwise silently "
            "wipe previously generated markers (near-miss on 2026-07-02)."
        ),
    )
    return parser.parse_args()


def iter_source_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for base in (root / "src", root / "include"):
        if not base.is_dir():
            continue
        for pattern in ("*.cpp", "*.cc", "*.cxx", "*.h", "*.hpp", "*.hh", "*.hxx"):
            files.extend(sorted(base.rglob(pattern)))
    return files


def collect_source_markers(repo_root: Path, target: str) -> dict[int, SourceMarker]:
    markers: dict[int, SourceMarker] = {}
    for path in iter_source_files(repo_root):
        posix = path.as_posix()
        if "/ghidra_autogen/" in posix or "/autogen/" in posix:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = normalize_repo_relative_path(path, repo_root)
        lines = text.splitlines()
        for idx, line in enumerate(lines):
            match = MARKER_RE.search(line)
            if match is None:
                continue
            if match.group("target").upper() != target.upper():
                continue
            address = int(match.group("address"), 16)
            kind = match.group("kind").upper()
            name = ""
            if idx + 1 < len(lines):
                next_line = lines[idx + 1].strip()
                if next_line.startswith("//"):
                    next_match = MARKER_RE.search(next_line)
                    if next_match is None:
                        name = next_line[2:].strip()
            existing = markers.get(address)
            if existing is not None and existing.kind == "LIBRARY":
                continue
            markers[address] = SourceMarker(kind=kind, path=rel, name=name)
    return markers


def strip_address_suffix(symbol: str) -> str:
    return re.sub(r"@[0-9a-fA-F]{8}$", "", symbol.strip())


def has_address_suffix(symbol: str) -> bool:
    return strip_address_suffix(symbol) != symbol.strip()


def is_decorated_symbol(name: str) -> bool:
    return name.startswith("?")


def demangled_base_name(symbol: str) -> str:
    if not symbol:
        return ""
    demangled = msvc_demangle(symbol)
    if not demangled:
        return ""
    head, sep, _tail = demangled.partition("(")
    if not sep:
        return ""
    if "`" in head:
        tick = head.rfind("`")
        prefix_end = head.rfind(" ", 0, tick)
        return head[prefix_end + 1 :].strip() if prefix_end >= 0 else head.strip()
    return head.rsplit(None, 1)[-1].strip()


def qualified_conflict_name(cand: Candidate, fallback_symbol: str) -> str:
    prefix = "FID_conflict:"
    if not cand.current_name.startswith(prefix):
        return ""
    method = cand.current_name[len(prefix) :].strip()
    if not method:
        return ""
    demangled = demangled_base_name(fallback_symbol)
    if "::" not in demangled:
        return method
    class_name = demangled.rsplit("::", 1)[0]
    if method.startswith("~"):
        return f"{class_name}::{method}"
    if method.startswith("`"):
        return f"{class_name}::{method}"
    return f"{class_name}::{method}"


def choose_display_name(cand: Candidate, marker: SourceMarker | None) -> str:
    if marker is not None and marker.name and not is_decorated_symbol(marker.name):
        return marker.name
    demangled = demangled_base_name(cand.symbol_name)
    if demangled:
        return demangled
    conflict = qualified_conflict_name(cand, strip_address_suffix(cand.fid_name))
    if conflict:
        return conflict
    if cand.current_name and not is_decorated_symbol(cand.current_name):
        return cand.current_name
    return cand.symbol_name


def load_library_symbol_index(path: Path) -> dict[tuple[str, str], set[str]]:
    """Map (domain_path, demangled base name) to decorated symbols."""
    index: dict[tuple[str, str], set[str]] = {}
    if not path.is_file():
        return index
    with path.open(encoding="utf-8", errors="ignore") as fd:
        for line in fd:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                domain_path, symbol = line.rsplit(" ", 1)
            except ValueError:
                continue
            base_name = demangled_base_name(symbol)
            if not base_name:
                continue
            index.setdefault((domain_path, base_name), set()).add(symbol)
    return index


def resolve_conflict_symbol(
    cand: Candidate, library_symbols: dict[tuple[str, str], set[str]]
) -> str:
    conflict_name = qualified_conflict_name(cand, strip_address_suffix(cand.fid_name))
    if not conflict_name:
        return ""
    symbols = library_symbols.get((cand.domain_path, conflict_name), set())
    if len(symbols) != 1:
        return ""
    return next(iter(symbols))


def collect_manual_source_references(
    repo_root: Path, names: set[str], *, marker_rel: str
) -> set[str]:
    identifiers = {name for name in names if IDENT_RE.match(name)}
    if not identifiers:
        return set()
    found: set[str] = set()
    patterns = {name: re.compile(rf"\b{re.escape(name)}\b") for name in identifiers}
    for path in iter_source_files(repo_root):
        rel = normalize_repo_relative_path(path, repo_root)
        if rel == marker_rel:
            continue
        posix = path.as_posix()
        if "/ghidra_autogen/" in posix or "/autogen/" in posix:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for name, pattern in patterns.items():
            if name not in found and pattern.search(text):
                found.add(name)
    return found


def load_candidates(
    path: Path,
    *,
    start: int,
    end: int,
    families: set[str],
    library_symbols: dict[tuple[str, str], set[str]],
) -> list[Candidate]:
    rows: list[Candidate] = []
    with path.open(newline="", encoding="utf-8") as fd:
        reader = csv.DictReader(fd)
        for row in reader:
            try:
                address = parse_hex_address(row.get("address", ""))
            except ValueError:
                continue
            family = (row.get("library_family") or "").strip()
            if address < start or address > end or family not in families:
                continue
            fid_name = (row.get("matched_name") or "").strip()
            if not fid_name:
                continue
            fid_name_has_address_suffix = has_address_suffix(fid_name)
            symbol_name = (
                resolve_conflict_symbol(
                    Candidate(
                        address=address,
                        current_name=(row.get("current_name") or "").strip(),
                        fid_name=fid_name,
                        display_name="",
                        symbol_name="",
                        fid_name_has_address_suffix=fid_name_has_address_suffix,
                        domain_path=(row.get("domain_path") or "").strip(),
                        library_family=family,
                        library_version=(row.get("library_version") or "").strip(),
                        library_variant=(row.get("library_variant") or "").strip(),
                        overall_score=(row.get("overall_score") or "").strip(),
                    ),
                    library_symbols,
                )
                if fid_name_has_address_suffix
                else strip_address_suffix(fid_name)
            )
            rows.append(
                Candidate(
                    address=address,
                    current_name=(row.get("current_name") or "").strip(),
                    fid_name=fid_name,
                    display_name="",
                    symbol_name=symbol_name,
                    fid_name_has_address_suffix=fid_name_has_address_suffix,
                    domain_path=(row.get("domain_path") or "").strip(),
                    library_family=family,
                    library_version=(row.get("library_version") or "").strip(),
                    library_variant=(row.get("library_variant") or "").strip(),
                    overall_score=(row.get("overall_score") or "").strip(),
                )
            )
    rows.sort(key=lambda c: c.address)
    return rows


def load_function_sizes(path: Path) -> dict[int, str]:
    if not path.is_file():
        return {}
    sizes: dict[int, str] = {}
    with path.open(newline="", encoding="utf-8") as fd:
        reader = csv.DictReader(fd)
        for row in reader:
            if (row.get("range") or "").strip() != "dense":
                continue
            try:
                address = parse_hex_address(row.get("address", ""))
            except ValueError:
                continue
            size = (row.get("size") or "").strip()
            if size:
                sizes[address] = size
    return sizes


def classify_candidates(
    candidates: list[Candidate],
    *,
    markers: dict[int, SourceMarker],
    marker_rel: str,
    referenced_names: set[str],
    include_manual: bool,
) -> None:
    for cand in candidates:
        marker = markers.get(cand.address)
        if marker is not None:
            cand.existing_marker_kind = marker.kind
            cand.existing_marker_path = marker.path
        cand.display_name = choose_display_name(cand, marker)
        if (
            marker is not None
            and marker.kind == "LIBRARY"
            and marker.path != marker_rel
            and marker.name
            and not is_decorated_symbol(marker.name)
            and cand.symbol_name
            and is_decorated_symbol(cand.symbol_name)
            and demangled_base_name(cand.symbol_name) != marker.name
        ):
            cand.symbol_name = ""
        if marker is not None:
            cand.existing_ownership = "library" if marker.kind == "LIBRARY" else "manual"
            cand.existing_target_cpp = marker.path

        if (
            marker is not None
            and marker.kind == "LIBRARY"
            and marker.path == marker_rel
            and cand.current_name
            and cand.current_name != cand.symbol_name
            and cand.current_name in referenced_names
            and not include_manual
        ):
            cand.action = "skip_referenced_project_alias"
            cand.reason = cand.current_name
            continue

        if marker is not None and marker.kind == "LIBRARY":
            if marker.path == marker_rel:
                cand.action = "keep_generated_library_marker"
            else:
                cand.action = "symbols_only_existing_library_marker"
            continue

        if marker is not None and not include_manual:
            cand.action = "skip_existing_source_marker"
            cand.reason = marker.kind
            continue

        if (
            cand.current_name
            and cand.current_name != cand.symbol_name
            and cand.current_name in referenced_names
            and not include_manual
        ):
            cand.action = "skip_referenced_project_alias"
            cand.reason = cand.current_name
            continue

        cand.action = "generate_library_marker"


def accepted_for_symbols(candidates: list[Candidate]) -> list[Candidate]:
    return [
        c
        for c in candidates
        if c.action
        in {
            "generate_library_marker",
            "keep_generated_library_marker",
            "symbols_only_existing_library_marker",
        }
    ]


def generated_marker_candidates(candidates: list[Candidate]) -> list[Candidate]:
    return [
        c
        for c in candidates
        if c.action in {"generate_library_marker", "keep_generated_library_marker"}
    ]


def symbol_targets(candidates: list[Candidate]) -> dict[int, SymbolTarget]:
    targets: dict[int, SymbolTarget] = {}
    for cand in candidates:
        if cand.action in {
            "generate_library_marker",
            "keep_generated_library_marker",
            "symbols_only_existing_library_marker",
        }:
            targets[cand.address] = (cand.display_name, cand.symbol_name, True)
        elif cand.action == "skip_referenced_project_alias":
            targets[cand.address] = (cand.current_name, None, False)
    return targets


def write_review_map(path: Path, candidates: list[Candidate]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "address",
        "current_name",
        "fid_name",
        "display_name",
        "symbol_name",
        "library_family",
        "library_version",
        "library_variant",
        "domain_path",
        "overall_score",
        "existing_marker_kind",
        "existing_marker_path",
        "existing_ownership",
        "existing_target_cpp",
        "action",
        "reason",
    ]
    with path.open("w", newline="", encoding="utf-8") as fd:
        writer = csv.DictWriter(fd, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        for c in candidates:
            writer.writerow(
                {
                    "address": f"0x{c.address:08x}",
                    "current_name": c.current_name,
                    "fid_name": c.fid_name,
                    "display_name": c.display_name,
                    "symbol_name": c.symbol_name,
                    "library_family": c.library_family,
                    "library_version": c.library_version,
                    "library_variant": c.library_variant,
                    "domain_path": c.domain_path,
                    "overall_score": c.overall_score,
                    "existing_marker_kind": c.existing_marker_kind,
                    "existing_marker_path": c.existing_marker_path,
                    "existing_ownership": c.existing_ownership,
                    "existing_target_cpp": c.existing_target_cpp,
                    "action": c.action,
                    "reason": c.reason,
                }
            )


def apply_symbols(
    symbols_path: Path, targets: dict[int, SymbolTarget], sizes: dict[int, str]
) -> tuple[int, int]:
    fieldnames, rows = read_pipe_table(symbols_path)
    if "symbol" not in fieldnames:
        insert_at = fieldnames.index("size") if "size" in fieldnames else len(fieldnames)
        fieldnames.insert(insert_at, "symbol")
    updated = 0
    seen: set[int] = set()
    for row in rows:
        if (row.get("type") or "").strip().lower() != "function":
            continue
        addr_text = (row.get("address") or "").strip()
        if not addr_text:
            continue
        try:
            address = int(addr_text, 16)
        except ValueError:
            continue
        target = targets.get(address)
        if target is None:
            continue
        seen.add(address)
        target_name, target_symbol, _add_if_missing = target
        if target_name and row.get("name", "") != target_name:
            row["name"] = target_name
            updated += 1
        if target_symbol is not None and row.get("symbol", "") != target_symbol:
            row["symbol"] = target_symbol
            updated += 1
    missing = sorted(address for address, target in targets.items() if target[2] and address not in seen)
    for address in missing:
        target_name, target_symbol, _add_if_missing = targets[address]
        rows.append(
            {
                "address": format(address, "x"),
                "name": target_name,
                "symbol": target_symbol or "",
                "size": sizes.get(address, ""),
                "type": "function",
                "prototype": "",
            }
        )
    rows.sort(key=lambda row: int((row.get("address") or "0"), 16))
    write_symbols_csv(symbols_path, fieldnames, rows)
    return updated, len(missing)


def render_marker_file(candidates: list[Candidate], *, target: str) -> str:
    lines = [
        "// AUTO-GENERATED by tools/mfc/apply_msvc500_library_region.py -- do not hand-edit.",
        "// MSVC500 FID-derived LIBRARY markers for the dense MFC/CRT library range.",
        "// Re-run `just apply-msvc500-library-region --apply` after refreshing FID matches.",
        "",
        "#if 0",
    ]
    for cand in sorted(candidates, key=lambda c: c.address):
        lines.append(f"// LIBRARY: {target} 0x{cand.address:08x}")
        lines.append(f"// {cand.symbol_name or cand.display_name or cand.fid_name}")
        lines.append("")
    lines.append("#endif")
    return "\n".join(lines) + "\n"


def apply_markers(path: Path, candidates: list[Candidate], *, target: str) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = render_marker_file(candidates, target=target)
    path.write_text(text, encoding="utf-8")
    return len(candidates)




def main() -> int:
    args = parse_args()
    repo_root = repo_root_from_file(__file__)
    start = parse_hex_address(args.start)
    end = parse_hex_address(args.end)
    if start > end:
        raise SystemExit("--start must be <= --end")
    families = {part.strip() for part in args.families.split(",") if part.strip()}

    fid_matches = resolve_repo_path(repo_root, args.fid_matches)
    symbols_path = resolve_repo_path(repo_root, args.symbols)
    range_audit_path = resolve_repo_path(repo_root, args.range_audit)
    library_functions_path = resolve_repo_path(repo_root, args.library_functions)
    marker_path = resolve_repo_path(repo_root, args.library_markers)
    marker_rel = normalize_repo_relative_path(marker_path, repo_root)
    out_map = resolve_repo_path(repo_root, args.out_map)

    if not fid_matches.is_file():
        raise FileNotFoundError(fid_matches)
    if not symbols_path.is_file():
        raise FileNotFoundError(symbols_path)

    library_symbols = load_library_symbol_index(library_functions_path)
    candidates = load_candidates(
        fid_matches,
        start=start,
        end=end,
        families=families,
        library_symbols=library_symbols,
    )

    # Reviewed library-identity overrides win over FID (precedence: reviewed
    # override > FID match). Drop FID candidates at override addresses so a manual
    # re-run of this script never overwrites the curated name/symbol/prototype that
    # tools/mfc/apply_library_overrides.py owns (e.g. rand at 0x005e83f0).
    override_path = resolve_repo_path(repo_root, "config/reviewed_library_identities.csv")
    override_addresses: set[int] = set()
    if override_path.is_file():
        try:
            from tools.mfc.apply_library_overrides import load_overrides

            override_addresses = {o.address for o in load_overrides(override_path)}
        except Exception as exc:  # pragma: no cover - defensive
            print(f"warning: could not read library overrides: {exc}")
    if override_addresses:
        before = len(candidates)
        candidates = [c for c in candidates if c.address not in override_addresses]
        dropped = before - len(candidates)
        if dropped:
            print(f"deferred {dropped} FID candidate(s) to reviewed library overrides")
    sizes = load_function_sizes(range_audit_path)
    markers = collect_source_markers(repo_root, args.target)
    referenced_names = collect_manual_source_references(
        repo_root, {c.current_name for c in candidates}, marker_rel=marker_rel
    )
    classify_candidates(
        candidates,
        markers=markers,
        marker_rel=marker_rel,
        referenced_names=referenced_names,
        include_manual=bool(args.include_manual),
    )
    accepted = accepted_for_symbols(candidates)
    generated = generated_marker_candidates(candidates)
    write_review_map(out_map, candidates)

    actions: dict[str, int] = {}
    for cand in candidates:
        actions[cand.action] = actions.get(cand.action, 0) + 1

    print(
        f"library-region candidates={len(candidates)} accepted_symbols={len(accepted)} "
        f"generated_markers={len(generated)} out_map={out_map}"
    )
    for action in sorted(actions):
        print(f"  {action}: {actions[action]}")

    if not args.apply:
        print("dry-run only; re-run with --apply to update symbols and markers.")
        return 0

    existing_generated = sum(
        1 for m in markers.values() if m.kind == "LIBRARY" and m.path == marker_rel
    )
    if len(generated) < existing_generated and not args.allow_marker_removals:
        raise SystemExit(
            f"refusing to shrink the generated LIBRARY marker set "
            f"({existing_generated} -> {len(generated)}): the matches CSV looks partial. "
            f"Re-run with --allow-marker-removals if the removal is intentional."
        )

    symbol_updates, added_symbols = apply_symbols(symbols_path, symbol_targets(candidates), sizes)
    marker_count = apply_markers(marker_path, generated, target=args.target)
    print(
        f"applied: symbols_updated={symbol_updates} symbols_added={added_symbols} "
        f"marker_count={marker_count}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
