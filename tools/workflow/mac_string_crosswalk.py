#!/usr/bin/env python3
"""Crosswalk Mac STR# text with Windows string tables, globals, and source uses.

Mac resource identity remains file scoped.  The resulting matches are semantic
evidence only and do not establish Windows ABI facts.
"""

from __future__ import annotations

import argparse
import ast
from collections import defaultdict
import csv
import json
from pathlib import Path
import re
import unicodedata

import yaml

from tools.common.file_scan import iter_files
from tools.common.repo import repo_root_from_file


FORMAT_VERSION = 1
MAC_STRINGS_PATH = "vendor/macos_codewarrior/evidence/resources/strings.csv"
MAC_SUMMARY_PATH = "vendor/macos_codewarrior/evidence/resources/summary.json"
WINDOWS_STRINGS_PATH = "docs/reference/strenu-strings.tsv"
GLOBAL_DATA_PATH = "src/game/global_data_tables.cpp"
UI_MANIFEST_PATH = "config/ui_factory_codegen.yml"
UI_VIEWS_PATH = "vendor/macos_codewarrior/evidence/resources/ui_views.json"
INDEX_PATH = "docs/reference/mac_string_crosswalk.json"

_FUNCTION_RE = re.compile(r"^// FUNCTION: IMPERIALISM (0x[0-9a-fA-F]+)$", re.MULTILINE)
_GLOBAL_RE = re.compile(
    r"^// GLOBAL: IMPERIALISM (?P<address>0x[0-9a-fA-F]+)\s*$"
    r"(?P<between>(?:(?!^// (?:GLOBAL|FUNCTION|VTABLE):).)*?)"
    r"^(?:extern\s+\"C\"\s+)?(?:const\s+)?char\s+"
    r"(?P<symbol>[A-Za-z_]\w*)\s*\[\s*\]\s*=\s*"
    r"(?P<literals>(?:\"(?:\\.|[^\"\\])*\"\s*)+);",
    re.MULTILINE | re.DOTALL,
)
_STRING_LITERAL_RE = re.compile(r'\"(?:\\.|[^\"\\])*\"')
_PLACEHOLDER_RE = re.compile(
    r"\[(?P<bracket>\d+)(?::[^]]*)?\]|\^(?P<caret>\d+)|%(?:[-+ #0]*\d*(?:\.\d+)?)?[diuoxXfFeEgGaAcsp]"
)
_GROUP_INDEX_CALL_PATTERNS = (
    re.compile(
        r"(?:->|\.)GetString\s*\(\s*(?P<group>0x[0-9a-fA-F]+|\d+)\s*,\s*"
        r"(?P<index>0x[0-9a-fA-F]+|\d+)"
    ),
    re.compile(
        r"LoadUiStringByGroupAndIndexTo(?:ControlObject|GlobalControlTag(?:AndApply)?)\s*\(\s*"
        r"(?P<group>0x[0-9a-fA-F]+|\d+)\s*,\s*(?P<index>0x[0-9a-fA-F]+|\d+)"
    ),
    re.compile(
        r"LoadUiStringResourceByGroupAndIndex\s*\(\s*[^,]+,\s*"
        r"(?P<group>0x[0-9a-fA-F]+|\d+)\s*,\s*(?P<index>0x[0-9a-fA-F]+|\d+)"
    ),
)


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream))


def _normalize_newlines(text: str) -> str:
    return text.replace("\\r\\n", " ").replace("\\n", " ").replace("\\r", " ").replace("\r", " ").replace("\n", " ")


def normalized_text(text: str) -> str:
    text = unicodedata.normalize("NFKC", _normalize_newlines(text))
    text = text.translate(str.maketrans({"‘": "'", "’": "'", "“": '"', "”": '"', "–": "-", "—": "-"}))
    return " ".join(text.casefold().split())


def placeholder_signature(text: str) -> list[str]:
    signature: list[str] = []
    for match in _PLACEHOLDER_RE.finditer(text):
        if match.group("bracket"):
            signature.append(f"arg{match.group('bracket')}")
        elif match.group("caret"):
            signature.append(f"arg{match.group('caret')}")
        else:
            signature.append("printf")
    return signature


def semantic_text(text: str) -> str:
    def replace_placeholder(match: re.Match[str]) -> str:
        number = match.group("bracket") or match.group("caret")
        return f" arg{number} " if number else " printf "

    normalized = normalized_text(_PLACEHOLDER_RE.sub(replace_placeholder, text))
    normalized = re.sub(r"[^\w]+", " ", normalized, flags=re.UNICODE)
    return " ".join(normalized.split())


def _decode_cpp_literals(literals: str) -> str:
    values: list[str] = []
    for token in _STRING_LITERAL_RE.findall(literals):
        value = ast.literal_eval(token)
        if not isinstance(value, str):
            raise ValueError(f"non-string C++ literal {token!r}")
        values.append(value)
    return "".join(values)


def load_embedded_globals(repo_root: Path) -> list[dict]:
    path = repo_root / GLOBAL_DATA_PATH
    source = path.read_text(encoding="utf-8")
    rows: list[dict] = []
    for match in _GLOBAL_RE.finditer(source):
        text = _decode_cpp_literals(match.group("literals"))
        rows.append(
            {
                "source": "embedded_global",
                "address": f"0x{int(match.group('address'), 0):08x}",
                "symbol": match.group("symbol"),
                "text": text,
                "normalized": normalized_text(text),
                "semantic": semantic_text(text),
                "placeholders": placeholder_signature(text),
            }
        )
    return sorted(rows, key=lambda row: (row["address"], row["symbol"]))


def load_windows_strings(repo_root: Path) -> list[dict]:
    rows: list[dict] = []
    with (repo_root / WINDOWS_STRINGS_PATH).open(encoding="utf-8", newline="") as stream:
        for row in csv.DictReader(stream, delimiter="\t"):
            block = int(row["block"])
            index = int(row["index"])
            text = row["text"]
            # Win32 STRINGTABLE resource names are one-based blocks.  The legacy
            # TSV id used block*16+index; retain it for provenance but use the
            # runtime LoadStringA ID below.
            load_string_id = (block - 1) * 16 + index
            rows.append(
                {
                    "source": "windows_gob",
                    "load_string_id": load_string_id,
                    "legacy_tsv_id": int(row["id"]),
                    "block": block,
                    "index": index,
                    "text": text,
                    "normalized": normalized_text(text),
                    "semantic": semantic_text(text),
                    "placeholders": placeholder_signature(text),
                }
            )
    return sorted(rows, key=lambda row: (row["load_string_id"], row["block"], row["index"]))


def load_mac_strings(repo_root: Path) -> list[dict]:
    rows: list[dict] = []
    for row in _read_csv(repo_root / MAC_STRINGS_PATH):
        text = row["text"]
        resource_file = row["resource_file"]
        group_id = int(row["group_id"])
        string_index = int(row["string_index"])
        rows.append(
            {
                "id": f"{resource_file}:STR#:{group_id}:{string_index}",
                "resource_file": resource_file,
                "group_id": group_id,
                "group_name": row["group_name"],
                "string_index": string_index,
                "text": text,
                "normalized": normalized_text(text),
                "semantic": semantic_text(text),
                "placeholders": placeholder_signature(text),
            }
        )
    return rows


def _candidate_identity(candidate: dict) -> tuple:
    if candidate["source"] == "windows_gob":
        return candidate["source"], candidate["load_string_id"]
    return candidate["source"], candidate["address"], candidate["symbol"]


def _add_candidate(candidates: dict[tuple, dict], source: dict, score: int, reason: str) -> None:
    identity = _candidate_identity(source)
    candidate = candidates.get(identity)
    if candidate is None:
        candidate = {key: value for key, value in source.items() if key not in {"normalized", "semantic"}}
        candidate["score"] = score
        candidate["reasons"] = [reason]
        candidates[identity] = candidate
        return
    candidate["score"] = max(candidate["score"], score)
    if reason not in candidate["reasons"]:
        candidate["reasons"].append(reason)


def _text_match_score(mac: dict, windows: dict) -> tuple[int, str] | None:
    if mac["text"] == windows["text"]:
        return 100, "exact_text"
    if mac["normalized"] == windows["normalized"]:
        return 90, "normalized_text"
    if (
        mac["semantic"]
        and mac["semantic"] == windows["semantic"]
        and mac["placeholders"] == windows["placeholders"]
    ):
        return 80, "punctuation_and_placeholder_structure"
    return None


def build_crosswalk(repo_root: Path) -> dict:
    mac_rows = load_mac_strings(repo_root)
    windows_rows = load_windows_strings(repo_root)
    embedded_rows = load_embedded_globals(repo_root)
    windows_by_id: dict[int, list[dict]] = defaultdict(list)
    windows_by_normalized: dict[str, list[dict]] = defaultdict(list)
    windows_by_semantic: dict[str, list[dict]] = defaultdict(list)
    embedded_by_normalized: dict[str, list[dict]] = defaultdict(list)
    embedded_by_semantic: dict[str, list[dict]] = defaultdict(list)
    for row in windows_rows:
        windows_by_id[row["load_string_id"]].append(row)
        windows_by_normalized[row["normalized"]].append(row)
        windows_by_semantic[row["semantic"]].append(row)
    for row in embedded_rows:
        embedded_by_normalized[row["normalized"]].append(row)
        embedded_by_semantic[row["semantic"]].append(row)

    matched = 0
    formula_matches = 0
    for mac in mac_rows:
        candidates: dict[tuple, dict] = {}
        if mac["resource_file"] == "Strings.rsrc":
            runtime_id = (mac["group_id"] * 100 + mac["string_index"]) & 0xFFFF
            for windows in windows_by_id.get(runtime_id, []):
                text_match = _text_match_score(mac, windows)
                suffix = text_match[1] if text_match else "text_differs"
                _add_candidate(candidates, windows, 120 if text_match else 110, f"resource_id_formula_{suffix}")
                formula_matches += 1
        for windows in windows_by_normalized.get(mac["normalized"], []):
            score, reason = _text_match_score(mac, windows) or (90, "normalized_text")
            _add_candidate(candidates, windows, score, reason)
        if mac["semantic"]:
            for windows in windows_by_semantic.get(mac["semantic"], []):
                text_match = _text_match_score(mac, windows)
                if text_match:
                    _add_candidate(candidates, windows, *text_match)
        for embedded in embedded_by_normalized.get(mac["normalized"], []):
            score, reason = _text_match_score(mac, embedded) or (90, "normalized_text")
            _add_candidate(candidates, embedded, score, reason)
        if mac["semantic"]:
            for embedded in embedded_by_semantic.get(mac["semantic"], []):
                text_match = _text_match_score(mac, embedded)
                if text_match:
                    _add_candidate(candidates, embedded, *text_match)
        ranked = sorted(
            candidates.values(),
            key=lambda candidate: (
                -candidate["score"],
                candidate["source"],
                candidate.get("load_string_id", 0),
                candidate.get("address", ""),
                candidate.get("symbol", ""),
            ),
        )
        mac["candidate_count"] = len(ranked)
        mac["candidates"] = ranked[:12]
        mac["ambiguous"] = len(ranked) > 1 and ranked[0]["score"] == ranked[1]["score"]
        if ranked:
            matched += 1

    functions = _build_function_references(repo_root, windows_by_id, embedded_rows, mac_rows)
    summary = json.loads((repo_root / MAC_SUMMARY_PATH).read_text(encoding="utf-8"))
    public_mac_rows = [
        {key: value for key, value in row.items() if key not in {"normalized", "semantic"}}
        for row in mac_rows
    ]
    public_windows_rows = [
        {key: value for key, value in row.items() if key not in {"normalized", "semantic"}}
        for row in windows_rows
    ]
    public_embedded_rows = [
        {key: value for key, value in row.items() if key not in {"normalized", "semantic"}}
        for row in embedded_rows
    ]
    return {
        "format_version": FORMAT_VERSION,
        "policy": (
            "Mac strings are a file-scoped semantic oracle only. Ranked text and resource-ID "
            "matches do not establish Windows ABI, addresses, calling conventions, or ownership."
        ),
        "sources": {
            "mac_strings": MAC_STRINGS_PATH,
            "mac_resource_set_sha256": summary["resource_set_sha256"],
            "windows_strings": WINDOWS_STRINGS_PATH,
            "embedded_globals": GLOBAL_DATA_PATH,
            "text_resources": "pending decoded TEXT evidence (imperialism-decomp-1uj.77.4)",
        },
        "summary": {
            "mac_strings": len(mac_rows),
            "windows_gob_strings": len(windows_rows),
            "embedded_globals": len(embedded_rows),
            "mac_strings_with_candidates": matched,
            "formula_matches": formula_matches,
            "functions_with_references": len(functions),
            "text_resources": 0,
        },
        "mac_strings": public_mac_rows,
        "windows_gob_strings": public_windows_rows,
        "embedded_globals": public_embedded_rows,
        "functions": functions,
    }


def _source_function_sections(repo_root: Path) -> list[tuple[str, str, str]]:
    sections: list[tuple[str, str, str]] = []
    for path in iter_files([str(repo_root / "src" / "game")], patterns=("*.cpp",)):
        source = path.read_text(encoding="utf-8", errors="replace")
        markers = list(_FUNCTION_RE.finditer(source))
        for index, marker in enumerate(markers):
            end = markers[index + 1].start() if index + 1 < len(markers) else len(source)
            address = f"0x{int(marker.group(1), 0):08x}"
            sections.append((address, path.relative_to(repo_root).as_posix(), source[marker.end():end]))
    return sections


def _build_function_references(
    repo_root: Path,
    windows_by_id: dict[int, list[dict]],
    embedded_rows: list[dict],
    mac_rows: list[dict],
) -> dict[str, dict]:
    references: dict[str, dict] = {}
    embedded_symbols = {row["symbol"]: row for row in embedded_rows}
    for address, path, body in _source_function_sections(repo_root):
        rows: list[dict] = []
        body_symbols = set(re.findall(r"\b[A-Za-z_]\w*\b", body))
        for symbol in sorted(body_symbols & embedded_symbols.keys()):
            embedded = embedded_symbols[symbol]
            rows.append(
                {
                    "kind": "embedded_global",
                    "symbol": symbol,
                    "address": embedded["address"],
                    "text": embedded["text"],
                }
            )
        for pattern in _GROUP_INDEX_CALL_PATTERNS:
            for match in pattern.finditer(body):
                group = int(match.group("group"), 0)
                index = int(match.group("index"), 0)
                runtime_id = (group * 100 + index) & 0xFFFF
                for windows in windows_by_id.get(runtime_id, []):
                    rows.append(
                        {
                            "kind": "windows_gob",
                            "group": group,
                            "index": index,
                            "load_string_id": runtime_id,
                            "text": windows["text"],
                        }
                    )
        unique = {json.dumps(row, sort_keys=True): row for row in rows}
        if unique:
            references[address] = {
                "source_file": path,
                "references": sorted(
                    unique.values(), key=lambda row: (row["kind"], row.get("load_string_id", 0), row.get("symbol", ""))
                ),
            }

    mac_by_key = {
        (row["resource_file"], row["group_id"], row["string_index"]): row for row in mac_rows
    }
    views_data = json.loads((repo_root / UI_VIEWS_PATH).read_text(encoding="utf-8"))
    views = {(row["resource_file"], int(row["view_id"])): row for row in views_data["views"]}
    manifest = yaml.safe_load((repo_root / UI_MANIFEST_PATH).read_text(encoding="utf-8"))
    for function in manifest["functions"]:
        address = f"0x{int(function['address']):08x}"
        entry = references.setdefault(address, {"source_file": "generated/ui", "references": []})
        for case in function["cases"]:
            resource = case.get("resource")
            if not resource:
                continue
            resource_file, view_id_text = str(resource).rsplit(":", 1)
            view = views[(resource_file, int(view_id_text, 0))]
            for node in view["nodes"]:
                family = node.get("family", {})
                group = int(family.get("text_resource_id", 0xFFFF))
                index = int(family.get("text_resource_index", 0xFFFF))
                mac = mac_by_key.get((resource_file, group, index))
                if mac is None:
                    continue
                entry["references"].append(
                    {
                        "kind": "generated_mac_resource",
                        "event": int(case["event"]),
                        "resource": f"{resource_file}:{view_id_text}",
                        "mac_string": mac["id"],
                        "text": mac["text"],
                    }
                )
        unique = {json.dumps(row, sort_keys=True): row for row in entry["references"]}
        entry["references"] = sorted(
            unique.values(), key=lambda row: (row["kind"], row.get("event", 0), row.get("mac_string", ""))
        )
        if not entry["references"]:
            references.pop(address, None)
    return dict(sorted(references.items()))


def render_crosswalk(index: dict) -> str:
    return json.dumps(index, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _print_crosswalk(index: dict, group: int, string_index: int, resource_file: str | None) -> None:
    rows = [
        row
        for row in index["mac_strings"]
        if row["group_id"] == group
        and row["string_index"] == string_index
        and (resource_file is None or row["resource_file"] == resource_file)
    ]
    if not rows:
        raise SystemExit("No file-scoped Mac STR# entry matched that group/index")
    for row in rows:
        print(f"{row['id']}: {row['text']}")
        if not row["candidates"]:
            print("  no Windows candidate")
        for candidate in row["candidates"]:
            identity = (
                f"LoadStringA {candidate['load_string_id']}"
                if candidate["source"] == "windows_gob"
                else f"{candidate['symbol']}@{candidate['address']}"
            )
            print(
                f"  score={candidate['score']} {candidate['source']} {identity}: "
                f"{candidate['text']} [{', '.join(candidate['reasons'])}]"
            )


def _print_search(index: dict, query: str) -> None:
    needle = normalized_text(query)
    rows = [row for row in index["mac_strings"] if needle in normalized_text(row["text"])]
    if not rows:
        raise SystemExit(f"No Mac strings matched {query!r}")
    for row in rows:
        print(f"{row['id']}: {row['text']}")
        for candidate in row["candidates"][:3]:
            identity = candidate.get("symbol", candidate.get("load_string_id"))
            print(f"  -> score={candidate['score']} {candidate['source']} {identity}: {candidate['text']}")


def _print_function(index: dict, address_text: str) -> None:
    address = f"0x{int(address_text, 0):08x}"
    entry = index["functions"].get(address)
    if entry is None:
        raise SystemExit(f"No statically resolved string references for {address}")
    print(f"{address} ({entry['source_file']})")
    for row in entry["references"]:
        if row["kind"] == "embedded_global":
            detail = f"{row['symbol']}@{row['address']}"
        elif row["kind"] == "windows_gob":
            detail = f"group={row['group']} index={row['index']} LoadStringA={row['load_string_id']}"
        else:
            detail = f"event=0x{row['event']:x} {row['mac_string']}"
        print(f"  {row['kind']} {detail}: {row['text']}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--check", action="store_true")
    subparsers = parser.add_subparsers(dest="command")
    search = subparsers.add_parser("search")
    search.add_argument("query")
    crosswalk = subparsers.add_parser("crosswalk")
    crosswalk.add_argument("group", type=lambda value: int(value, 0))
    crosswalk.add_argument("index", type=lambda value: int(value, 0))
    crosswalk.add_argument("--resource-file")
    function = subparsers.add_parser("function")
    function.add_argument("address")
    args = parser.parse_args()

    repo_root = repo_root_from_file(__file__)
    path = repo_root / INDEX_PATH
    if not args.write and not args.check and args.command is not None:
        try:
            index = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise SystemExit(f"{INDEX_PATH}: {exc}; run just mac-string-crosswalk-update") from exc
        if args.command == "search":
            _print_search(index, args.query)
        elif args.command == "crosswalk":
            _print_crosswalk(index, args.group, args.index, args.resource_file)
        else:
            _print_function(index, args.address)
        return 0

    index = build_crosswalk(repo_root)
    rendered = render_crosswalk(index)
    if args.write:
        path.write_text(rendered, encoding="utf-8")
        print(f"Wrote {INDEX_PATH}: {index['summary']['mac_strings']} Mac strings")
        return 0
    if args.check:
        try:
            committed = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise SystemExit(f"{INDEX_PATH}: {exc}") from exc
        if committed != rendered:
            raise SystemExit(f"{INDEX_PATH} is stale; run just mac-string-crosswalk-update")
        print("Mac string crosswalk passed: " + ", ".join(f"{key}={value}" for key, value in index["summary"].items()))
        return 0
    print(json.dumps(index["summary"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
