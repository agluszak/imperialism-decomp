"""Enforce the constructor-placement decision.

THE DECISION
------------
A constructor is defined **in-class in its header if and only if the original binary has
no standalone body for it**. A constructor that owns an address (carries a
``// FUNCTION:`` marker) stays **out-of-line in its .cpp**, so that body pairs.

WHY
---
The original had one uniform model: ordinary out-of-line definitions compiled by VC5 RTM
at ``/Oy /Ob1``. Under ``/Ob1`` VC5 emits the standalone body AND auto-inlines it into
callers living in the SAME TU, and the original interleaved several classes per TU. Our
tree is one class per file (Hard Rule 7), so no caller is ever a same-TU user and the two
halves are mutually exclusive for us:

* out-of-line -> the standalone body pairs; every caller emits a CALL
* in-class    -> callers inline the body; the standalone body is NEVER emitted, and no
                 linker setting recovers it

So when the original has no body there is nothing to lose and in-class is free
(TPanelView: +7 exact). When it does have one, out-of-line keeps a certain pairing.
Details in docs/toolchain.md and the ctors-dtors-eh skill.

WHAT THIS GATE CHECKS (both directions)
---------------------------------------
1. out-of-line in a .cpp with NO marker -> should be in-class. Ratcheted against
   ``config/baselines/ctor_placement_baseline.txt``; that list is a backlog to shrink.
2. in-class in a header WITH a marker -> a deliberate exception to the decision, and must
   be justified in ``config/ctor_placement_exceptions.csv`` with what it bought and cost.

Two look-alikes are real bugs rather than placement, and neither is fixed by moving a
definition: a phantom no-arg ctor shadowing a default-argument ctor (TArmyMission), and a
body annotated "verified empty" that the caller disproves (TItemOrder).
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]
BASELINE = REPO / "config" / "baselines" / "ctor_placement_baseline.txt"
EXCEPTIONS = REPO / "config" / "ctor_placement_exceptions.csv"

# ClassName::ClassName( ... ) at column 0 -- an out-of-line definition.
CTOR = re.compile(r"^([A-Z]\w+)::\1\s*\(")
MARKERS = ("FUNCTION: IMPERIALISM", "SYNTHETIC: IMPERIALISM")

# A // FUNCTION marker immediately followed by an in-class ctor definition (body, not `;`).
INCLASS_MARKED = re.compile(
    r"//\s*FUNCTION: IMPERIALISM (0x[0-9a-fA-F]+)\s*\n\s*([A-Z]\w+)\s*\([^;)]*\)\s*(?::[^;{]*)?\{"
)


def scan_inclass_marked() -> list[tuple[str, str, str]]:
    """In-class ctor definitions that still own an address (address, class, header)."""
    out: list[tuple[str, str, str]] = []
    for path in sorted((REPO / "include" / "game").rglob("*.h")):
        text = path.read_text(encoding="utf-8", errors="replace")
        for m in INCLASS_MARKED.finditer(text):
            cls = m.group(2)
            # the name must be the enclosing class, i.e. a constructor
            if re.search(r"\bclass\s+" + cls + r"\b", text):
                out.append((m.group(1).lower(), cls, path.relative_to(REPO).as_posix()))
    return out


def load_exceptions() -> set[str]:
    if not EXCEPTIONS.exists():
        return set()
    addrs: set[str] = set()
    for line in EXCEPTIONS.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("address|"):
            continue
        addrs.add(line.split("|", 1)[0].strip().lower())
    return addrs


def scan(root: pathlib.Path) -> list[str]:
    findings: list[str] = []
    for path in sorted(root.rglob("*.cpp")):
        lines = path.read_text(encoding="utf-8", errors="replace").split("\n")
        for i, line in enumerate(lines):
            m = CTOR.match(line)
            if not m:
                continue
            # Hard Rule 3: a marker is IMMEDIATELY followed by its declaration, so only
            # the contiguous comment block directly above can claim this body. Scanning a
            # fixed window instead picks up a NEIGHBOUR's marker -- e.g. a destructor's
            # // FUNCTION four lines up -- and silently exempts the constructor.
            claimed = False
            j = i - 1
            while j >= 0:
                stripped = lines[j].strip()
                if not stripped.startswith("//"):
                    break
                if any(k in stripped for k in MARKERS):
                    claimed = True
                    break
                j -= 1
            if claimed:
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

    # Direction 2: an in-class definition that still owns an address breaks the decision
    # unless it is a justified exception.
    exceptions = load_exceptions()
    unjustified = [t for t in scan_inclass_marked() if t[0] not in exceptions]
    if unjustified:
        print(
            "Constructor-placement gate failed: in-class constructor(s) that still own an\n"
            "address, with no entry in config/ctor_placement_exceptions.csv:"
        )
        for addr, cls, hdr in unjustified:
            print(f"  - {cls} {addr}  {hdr}")
        print(
            "\nThe decision is: a ctor is defined in-class IF AND ONLY IF the original has no\n"
            "standalone body for it. This one owns an address, so it belongs out-of-line in\n"
            "its .cpp where that body can pair. Move it back, or -- if you measured that the\n"
            "inlined call sites are worth more than the lost pairing -- add a row recording\n"
            "the gain and the cost."
        )
        return 1

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

    print(
        f"Constructor-placement gate passed "
        f"({len(found_set)} baselined, 0 new; {len(exceptions)} justified in-class exception(s))."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
