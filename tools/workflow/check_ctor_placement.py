"""Report constructors defined out-of-line that the original never emits standalone.

A constructor carrying no ``// FUNCTION`` / ``// SYNTHETIC`` marker has no claimed
address in the original binary. When such a definition sits in a .cpp it cannot be
inlined into subclass constructors or ``CreateObject`` bodies in other translation
units, so VC5 emits a CALL where the original absorbed the body and every caller
mismatches on it.

This is a *report*, not a hard ban. The original had a uniform model -- ordinary
out-of-line definitions compiled at ``/Ob1``, where VC5 emits the standalone body AND
auto-inlines it into callers in the SAME TU. Our one-class-per-file layout (Hard Rule 7)
has no same-TU callers, so the two halves are mutually exclusive for us and each class is
a trade (see docs/toolchain.md and the ctors-dtors-eh skill).

The rule is: does the original have a standalone body for this ctor?

* no address  -> in-class is strictly correct and free (TPanelView: +7 exact)
* address     -> keep it out-of-line so the body pairs, unless the inlined call sites are
                 worth more; then go in-class, keep the marker, and expect the address to
                 stay unpaired (TProductionOrder 0x004b4f00)

Watch for two look-alikes that are real bugs rather than placement: a phantom no-arg ctor
shadowing a default-argument ctor (TArmyMission), and a body annotated "verified empty"
that the caller proves is not (TItemOrder).

Blessing the current set as a baseline keeps it from growing while the backlog is
worked down one evidenced class at a time.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]
BASELINE = REPO / "config" / "baselines" / "ctor_placement_baseline.txt"

# ClassName::ClassName( ... ) at column 0 -- an out-of-line definition.
CTOR = re.compile(r"^([A-Z]\w+)::\1\s*\(")
MARKERS = ("FUNCTION: IMPERIALISM", "SYNTHETIC: IMPERIALISM")


def scan(root: pathlib.Path) -> list[str]:
    findings: list[str] = []
    for path in sorted(root.rglob("*.cpp")):
        lines = path.read_text(encoding="utf-8", errors="replace").split("\n")
        for i, line in enumerate(lines):
            m = CTOR.match(line)
            if not m:
                continue
            # A marker within the preceding 4 lines claims a real address for this body.
            back = "\n".join(lines[max(0, i - 4) : i])
            if any(k in back for k in MARKERS):
                continue
            rel = path.relative_to(REPO).as_posix()
            findings.append(f"{rel}:{m.group(1)}")
    return findings


def load_baseline() -> set[str]:
    if not BASELINE.exists():
        return set()
    return {
        l.strip()
        for l in BASELINE.read_text().splitlines()
        if l.strip() and not l.startswith("#")
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--write-baseline", action="store_true")
    ap.add_argument("--paths", nargs="*", default=["src/game"])
    args = ap.parse_args()

    found: list[str] = []
    for p in args.paths:
        found += scan(REPO / p)
    found_set = set(found)

    if args.write_baseline:
        BASELINE.parent.mkdir(parents=True, exist_ok=True)
        BASELINE.write_text(
            "# Unmarked out-of-line constructors (see tools/workflow/check_ctor_placement.py,\n"
            "# bd nwdn). Each line is a class whose ctor has no claimed address yet still\n"
            "# lives in a .cpp. Shrink this list; do not grow it.\n"
            + "\n".join(sorted(found_set))
            + "\n"
        )
        print(f"ctor-placement baseline written: {len(found_set)} entries")
        return 0

    baseline = load_baseline()
    new = sorted(found_set - baseline)
    fixed = sorted(baseline - found_set)

    if new:
        print("Constructor-placement gate failed: new unmarked out-of-line constructor(s):")
        for n in new:
            print(f"  - {n}")
        print(
            "\nAn unmarked ctor has no claimed address. Read the caller (CreateObject /\n"
            "a derived ctor) first: if the original has NO standalone body, move the\n"
            "definition in-class (free win); if it HAS one, keep it out-of-line unless the\n"
            "inlined sites are worth more. See bd nwdn / the ctors-dtors-eh skill.\n"
            "Do not add it to the baseline to silence this."
        )
        return 1

    if fixed:
        print(f"ctor-placement: {len(fixed)} entry/entries resolved; refresh with")
        print("  just ctor-placement-gate-update")
        for f in fixed:
            print(f"  - {f}")
        return 1

    print(f"Constructor-placement gate passed ({len(found_set)} baselined, 0 new).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
