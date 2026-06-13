#!/usr/bin/env python3
"""Parse W32Dasm .alf output into read-only CSV/JSON reports."""

from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter
from pathlib import Path

DEFAULT_ALF = Path(
    "/home/agluszak/Games/gog/imperialism/drive_c/GOG Games/Imperialism/Imperialism.alf"
)
DEFAULT_OUT_DIR = Path("tmp_decomp/w32dasm")

SECTION_RE = re.compile(
    r"^\s+Object(?P<object>\d+):\s+(?P<name>\S+)\s+"
    r"RVA:\s+(?P<rva>[0-9A-Fa-f]+)\s+"
    r"Offset:\s+(?P<offset>[0-9A-Fa-f]+)\s+"
    r"Size:\s+(?P<size>[0-9A-Fa-f]+)\s+"
    r"Flags:\s+(?P<flags>[0-9A-Fa-f]+)"
)
IMPORT_MODULE_RE = re.compile(r"^\s+Import Module\s+(?P<index>\d+):\s+(?P<module>.+?)\s*$")
IMPORT_RE = re.compile(
    r"^\s+Addr:(?P<addr>[0-9A-Fa-f]{8})\s+hint\((?P<hint>[0-9A-Fa-f]+)\)\s+Name:\s+(?P<name>.+?)\s*$"
)
INSTRUCTION_RE = re.compile(r"^:(?P<addr>[0-9A-Fa-f]{8})\s+(?P<bytes>[0-9A-Fa-f?]+)\s*(?P<text>.*?)\s*$")
XREF_HEADER_RE = re.compile(r"^\*\s+Referenced by a (?P<kind>.+?) at Address(?:es)?:\s*$")
ADDR_RE = re.compile(r":(?P<addr>[0-9A-Fa-f]{8})(?:\((?P<jump>[UC])\))?")
POSSIBLE_REF_RE = re.compile(r"^\*\s+(?P<text>Possible .+?)(?::\s*)?$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--alf", type=Path, default=DEFAULT_ALF, help="W32Dasm .alf file")
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR, help="Report output directory")
    return parser.parse_args()


def open_csv(path: Path, fieldnames: list[str]):
    handle = path.open("w", newline="", encoding="utf-8")
    writer = csv.DictWriter(handle, fieldnames=fieldnames)
    writer.writeheader()
    return handle, writer


def normalize_xref_kind(text: str) -> str:
    lowered = text.lower()
    if "call" in lowered:
        return "call"
    if "jump" in lowered or "conditional" in lowered:
        return "jump"
    return re.sub(r"[^a-z0-9]+", "_", lowered).strip("_") or "unknown"


def split_instruction_text(text: str) -> tuple[str, str]:
    stripped = text.strip()
    if not stripped:
        return "", ""
    parts = stripped.split(None, 1)
    if len(parts) == 1:
        return parts[0], ""
    return parts[0], parts[1]


def parse_alf(alf_path: Path, out_dir: Path) -> dict[str, object]:
    out_dir.mkdir(parents=True, exist_ok=True)

    section_handle, section_writer = open_csv(
        out_dir / "sections.csv", ["object", "name", "rva", "offset", "size", "flags"]
    )
    import_handle, import_writer = open_csv(
        out_dir / "imports.csv", ["module_index", "module", "iat_address", "hint", "name"]
    )
    instruction_handle, instruction_writer = open_csv(
        out_dir / "instructions.csv", ["address", "bytes", "mnemonic", "operands", "text"]
    )
    xref_handle, xref_writer = open_csv(
        out_dir / "xrefs.csv", ["target_address", "ref_address", "kind", "jump_hint", "detail"]
    )
    hint_handle, hint_writer = open_csv(
        out_dir / "hints.csv", ["address", "kind", "text"]
    )

    counts: Counter[str] = Counter()
    mnemonic_counts: Counter[str] = Counter()
    xref_counts: Counter[str] = Counter()
    current_module_index = ""
    current_module = ""
    pending_xref_kind = ""
    pending_xref_detail = ""
    pending_xrefs: list[tuple[str, str]] = []
    pending_hints: list[str] = []

    try:
        with alf_path.open("r", encoding="latin-1", errors="replace", newline="") as handle:
            for raw_line in handle:
                line = raw_line.rstrip("\r\n")

                if match := SECTION_RE.match(line):
                    row = match.groupdict()
                    section_writer.writerow(row)
                    counts["sections"] += 1
                    continue

                if match := IMPORT_MODULE_RE.match(line):
                    current_module_index = match.group("index")
                    current_module = match.group("module")
                    counts["import_modules"] += 1
                    continue

                if match := IMPORT_RE.match(line):
                    import_writer.writerow(
                        {
                            "module_index": current_module_index,
                            "module": current_module,
                            "iat_address": f"0x{match.group('addr').upper()}",
                            "hint": match.group("hint"),
                            "name": match.group("name"),
                        }
                    )
                    counts["imports"] += 1
                    continue

                if match := XREF_HEADER_RE.match(line):
                    pending_xref_kind = normalize_xref_kind(match.group("kind"))
                    pending_xref_detail = match.group("kind")
                    pending_xrefs = []
                    continue

                if pending_xref_kind and line.startswith("|"):
                    for ref_match in ADDR_RE.finditer(line):
                        pending_xrefs.append(
                            (f"0x{ref_match.group('addr').upper()}", ref_match.group("jump") or "")
                        )
                    continue

                if match := POSSIBLE_REF_RE.match(line):
                    pending_hints.append(match.group("text"))
                    continue

                if match := INSTRUCTION_RE.match(line):
                    address = f"0x{match.group('addr').upper()}"
                    text = match.group("text")
                    mnemonic, operands = split_instruction_text(text)
                    instruction_writer.writerow(
                        {
                            "address": address,
                            "bytes": match.group("bytes"),
                            "mnemonic": mnemonic,
                            "operands": operands,
                            "text": text,
                        }
                    )
                    counts["instructions"] += 1
                    if mnemonic:
                        mnemonic_counts[mnemonic.lower()] += 1

                    for ref_address, jump_hint in pending_xrefs:
                        xref_writer.writerow(
                            {
                                "target_address": address,
                                "ref_address": ref_address,
                                "kind": pending_xref_kind,
                                "jump_hint": jump_hint,
                                "detail": pending_xref_detail,
                            }
                        )
                        counts["xrefs"] += 1
                        xref_counts[pending_xref_kind] += 1
                    pending_xref_kind = ""
                    pending_xref_detail = ""
                    pending_xrefs = []

                    for hint in pending_hints:
                        kind = re.sub(r"[^A-Za-z0-9]+", "_", hint.lower()).strip("_")
                        hint_writer.writerow({"address": address, "kind": kind, "text": hint})
                        counts["hints"] += 1
                    pending_hints = []
                    continue
    finally:
        for handle in (section_handle, import_handle, instruction_handle, xref_handle, hint_handle):
            handle.close()

    summary = {
        "alf": str(alf_path),
        "out_dir": str(out_dir),
        "counts": dict(counts),
        "top_mnemonics": dict(mnemonic_counts.most_common(25)),
        "xref_kinds": dict(xref_counts),
        "outputs": {
            "sections": str(out_dir / "sections.csv"),
            "imports": str(out_dir / "imports.csv"),
            "instructions": str(out_dir / "instructions.csv"),
            "xrefs": str(out_dir / "xrefs.csv"),
            "hints": str(out_dir / "hints.csv"),
        },
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return summary


def main() -> int:
    args = parse_args()
    summary = parse_alf(args.alf, args.out_dir)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

