#!/usr/bin/env python3
"""Gate against "dual-use" hand-waving and raw pointer<->int member storage.

"Dual-use" / "dual-purpose" / "reused as X and Y" is never a final explanation for a
struct field in this decomp -- it is a mandatory investigation trigger. The label almost
always hides a wrong receiver/class attribution, a wrong offset from a wrong base/derived
layout, two adjacent fields read as one region, one index domain given two prose
descriptions, or two concrete classes merged into one. Only a field proven (per the eight
criteria in AGENTS.md's type-modeling guardrail) to be a genuine discriminated variant is
legitimate, and even then it must be modelled explicitly (a union / variant payload /
separate record type / discriminator-keyed accessors), never a raw ``int`` plus scattered
casts.

Until a field is resolved it stays raw and is marked ``// UNRESOLVED_FIELD_ATTRIBUTION:``
with both readings and the evidence addresses. This gate makes the escape hatch mechanical:

  * banned terminology in manual source (``dual-use``, ``dual-purpose``, ``dual use``,
    ``dual-slot``, ``reused as``, ``both pointer and int``); rewrite to a real model or to
    an ``UNRESOLVED_FIELD_ATTRIBUTION`` note.
  * raw pointer->int member storage (``reinterpret_cast<int>(...)`` /
    ``reinterpret_cast<unsigned int>(...)``) and int-member->class-pointer casts
    (``reinterpret_cast<T*>(x->fieldNN)`` / ``x.fieldNN``).

This is a baseline-free HARD BAN: the debt was fully eradicated, so ANY offender fails.
There is no baseline file and no update escape hatch -- a new offender is always a source
defect to fix (a real model or an ``UNRESOLVED_FIELD_ATTRIBUTION`` note), never to bless.
Check-only; it never edits files.
"""

from __future__ import annotations

import argparse
import re

from tools.common.file_scan import iter_files
from tools.common.repo import normalize_repo_relative_path, repo_root_from_file

DEFAULT_PATHS = ("include/game", "src/game")

# Banned prose (case-insensitive). "reused as" is deliberately broad: describing one slot as
# "reused as" a second meaning is the exact hand-wave this gate exists to stop.
TERMINOLOGY = re.compile(
    r"\bdual[-\s]?use|\bdual[-\s]?purpose|\bdual[-\s]?slot|\breused as|\bboth pointer and int",
    re.IGNORECASE,
)

# Pointer -> int stored into a raw offset member (fieldNN / field_0xNN). Not every
# reinterpret_cast<int> (passing a pointer as an int *argument* is a separate, accepted
# calling-convention pattern) -- only pointer-as-int written into an unresolved offset slot,
# which is the field-attribution smell this gate targets.
PTR_TO_INT = re.compile(
    r"\bfield(?:_0x)?[0-9A-Fa-f]+\s*=\s*reinterpret_cast<\s*(?:unsigned\s+)?int\s*>"
)
# int member (fieldNN / field_0xNN) -> class pointer.
INT_MEMBER_TO_PTR = re.compile(
    r"reinterpret_cast<[^>]*\*\s*>\(\s*[A-Za-z_]\w*(?:->|\.)field(?:_0x)?[0-9A-Fa-f]+\b"
)

# A field left honestly raw + documented is the sanctioned provisional state, not an offender.
UNRESOLVED_MARK = "UNRESOLVED_FIELD_ATTRIBUTION"


def normalize(text: str) -> str:
    return " ".join(text.split())


# A cast/comment documented under an UNRESOLVED_FIELD_ATTRIBUTION note within this many lines
# is the sanctioned honest-provisional state, not an offender.
UNRESOLVED_WINDOW = 8


def collect_offenders(paths, repo_root) -> set[tuple[str, str]]:
    offenders: set[tuple[str, str]] = set()
    for path in iter_files(paths):
        rel = normalize_repo_relative_path(path, repo_root)
        unresolved_countdown = 0
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            norm = normalize(line)
            if UNRESOLVED_MARK in norm:
                unresolved_countdown = UNRESOLVED_WINDOW
            documented = UNRESOLVED_MARK in norm or unresolved_countdown > 0
            if unresolved_countdown > 0:
                unresolved_countdown -= 1
            if not norm:
                continue
            m = TERMINOLOGY.search(norm)
            if m and not documented:
                offenders.add((rel, f"term:{m.group(0).lower()}:{norm}"))
            if PTR_TO_INT.search(norm) and not documented:
                offenders.add((rel, f"ptr2int:{norm}"))
            if INT_MEMBER_TO_PTR.search(norm) and not documented:
                offenders.add((rel, f"int2ptr:{norm}"))
    return offenders


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--paths", nargs="+", default=list(DEFAULT_PATHS))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = repo_root_from_file(__file__)
    offenders = sorted(collect_offenders(args.paths, repo_root))

    if offenders:
        print("Dual-use gate FAILED (hard ban): 'dual-use' prose or raw pointer<->int member cast.")
        print("A field is not 'dual-use': prove one model (union/record/accessors) or mark it")
        print("// UNRESOLVED_FIELD_ATTRIBUTION: with both readings + evidence addresses.")
        print("This is a hard ban with no baseline: fix the source, do not bless it.")
        for rel, sig in offenders:
            print(f"    - {rel}: {sig}")
        return 1

    print("Dual-use gate passed (hard ban -- zero offenders).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
