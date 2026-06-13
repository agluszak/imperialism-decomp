#!/usr/bin/env python3
"""Extract strings from a W32Dasm .wpj file and classify whether it has extra labels."""

from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter
from pathlib import Path

from tools.w32dasm.parse_alf import DEFAULT_ALF, DEFAULT_OUT_DIR

DEFAULT_WPJ = Path(
    "/home/agluszak/Games/gog/imperialism/drive_c/GOG Games/Imperialism/Imperialism.wpj"
)
PRINTABLE = set(range(0x20, 0x7F)) | {0x09}
SYMBOLISH_RE = re.compile(r"^[A-Za-z_?$@][A-Za-z0-9_?$@:.`'~<> -]{2,}$")
CLASSISH_RE = re.compile(r"\bT[A-Z][A-Za-z0-9_]*(?:Dialog|Control|View|List|Button|Text|Window)?\b")
COMMENTISH_RE = re.compile(r"\s{2,}|[:;]")
FILLER_RE = re.compile(r"^\$?[A-F0-9]{4,}$")
LABEL_SAFE_RE = re.compile(r"^[A-Za-z0-9_?$@:.`'~<> -]+$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wpj", type=Path, default=DEFAULT_WPJ, help="W32Dasm .wpj file")
    parser.add_argument("--alf", type=Path, default=DEFAULT_ALF, help="W32Dasm .alf file for overlap checks")
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR, help="Report output directory")
    parser.add_argument("--min-len", type=int, default=5, help="Minimum ASCII string length")
    parser.add_argument("--max-overlap-checks", type=int, default=5000, help="Maximum strings checked against ALF")
    return parser.parse_args()


def extract_ascii_strings(data: bytes, min_len: int) -> list[tuple[int, str]]:
    strings: list[tuple[int, str]] = []
    start: int | None = None
    buf = bytearray()
    for index, byte in enumerate(data):
        if byte in PRINTABLE:
            if start is None:
                start = index
            buf.append(byte)
            continue
        if start is not None and len(buf) >= min_len:
            strings.append((start, buf.decode("ascii", errors="replace").strip()))
        start = None
        buf = bytearray()
    if start is not None and len(buf) >= min_len:
        strings.append((start, buf.decode("ascii", errors="replace").strip()))
    return strings


def classify(text: str) -> str:
    lowered = text.lower()
    if FILLER_RE.fullmatch(text):
        return "filler"
    if "\\" in text or "/" in text or lowered.endswith((".exe", ".wpj", ".alf")):
        return "path"
    if lowered.endswith((".dll", ".drv", ".ocx")):
        return "module"
    if CLASSISH_RE.search(text) or "::" in text:
        return "symbolish"
    if SYMBOLISH_RE.match(text):
        if COMMENTISH_RE.search(text):
            return "commentish"
        return "name"
    return "other"


def is_candidate_label(text: str) -> bool:
    classification = classify(text)
    if classification not in {"name", "symbolish", "commentish"}:
        return False
    if not LABEL_SAFE_RE.fullmatch(text):
        return False
    if sum(ch.isalnum() for ch in text) < max(3, len(text) // 2):
        return False
    if not any(ch.islower() for ch in text):
        return False
    if len(text) > 120:
        return False
    if text.count(" ") > 4:
        return False
    return True


def alf_membership(alf_path: Path, candidates: list[str]) -> set[str]:
    if not alf_path.exists() or not candidates:
        return set()
    alf_data = alf_path.read_bytes()
    present: set[str] = set()
    for text in candidates:
        if text.encode("latin-1", errors="ignore") in alf_data:
            present.add(text)
    return present


def main() -> int:
    args = parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)

    data = args.wpj.read_bytes()
    strings = extract_ascii_strings(data, args.min_len)
    unique_strings = sorted({text for _, text in strings})

    classification_counts: Counter[str] = Counter()
    interesting = [text for text in unique_strings if is_candidate_label(text)]
    interesting = interesting[: args.max_overlap_checks]
    present_in_alf = alf_membership(args.alf, interesting)

    strings_path = args.out_dir / "wpj_strings.csv"
    with strings_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=["offset", "text", "classification", "present_in_alf"]
        )
        writer.writeheader()
        for offset, text in strings:
            classification = classify(text)
            classification_counts[classification] += 1
            writer.writerow(
                {
                    "offset": f"0x{offset:08X}",
                    "text": text,
                    "classification": classification,
                    "present_in_alf": "yes" if text in present_in_alf else "no",
                }
            )

    extra_interesting = [text for text in interesting if text not in present_in_alf]
    extra_path = args.out_dir / "wpj_candidate_labels_not_in_alf.csv"
    with extra_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["text", "classification"])
        writer.writeheader()
        for text in extra_interesting:
            writer.writerow({"text": text, "classification": classify(text)})

    source_paths = sorted(
        {
            text.strip('"')
            for _offset, text in strings
            if "\\" in text and text.lower().strip('"').endswith((".cpp", ".h", ".hpp", ".c"))
        }
    )
    source_path_report = args.out_dir / "wpj_source_paths.csv"
    with source_path_report.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["path"])
        writer.writeheader()
        for path in source_paths:
            writer.writerow({"path": path})

    preliminary_read = (
        "possible_extra_project_labels_or_comments"
        if extra_interesting
        else "no_clean_user_labels_or_comments_detected"
    )
    summary = {
        "wpj": str(args.wpj),
        "alf": str(args.alf),
        "out_dir": str(args.out_dir),
        "file_size": len(data),
        "ascii_string_count": len(strings),
        "unique_ascii_string_count": len(unique_strings),
        "classification_counts": dict(classification_counts),
        "interesting_strings_checked_against_alf": len(interesting),
        "interesting_strings_present_in_alf": len(present_in_alf),
        "interesting_strings_not_seen_in_alf": len(extra_interesting),
        "examples_not_seen_in_alf": extra_interesting[:50],
        "unique_source_paths": len(source_paths),
        "source_path_examples": source_paths[:50],
        "preliminary_read": preliminary_read,
        "outputs": {
            "strings": str(strings_path),
            "candidate_labels_not_in_alf": str(extra_path),
            "source_paths": str(source_path_report),
        },
    }
    (args.out_dir / "wpj_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
