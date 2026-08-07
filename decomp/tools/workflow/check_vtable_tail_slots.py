"""Find classes whose modelled vtable stops short of the original's.

`just vtable <Class>` cannot see this defect. It compares our recompiled vtable
against the original slot by slot, but when our class declares fewer virtuals
than the original has slots, only the common prefix is compared -- and a
matching prefix reports "100% match" while the tail goes unmodelled. Any
original slot past our last declared virtual is invisible: methods that belong
in those slots sit in our headers as ordinary non-virtual members, every call to
them compiles to a direct call, and a call site that dispatches the *wrong* slot
looks identical to one that dispatches the right one.

That is not hypothetical. TMinor declared 3 of its own virtuals where the retail
vtable at 0x653c90 has 11 (slots 0x2a-0x34). `just vtable TMinor` reported 100%
throughout -- and, separately, was matching three unrelated dialog classes by
substring rather than TMinor at all. Modelling the missing 8 slots exposed
TMinor::ApplyJoinEmpireMode2FinalizeNationNameState calling
SetNationRowDisplayValueByDiplomacyPredicate (slot 0x2e) where the original
issues CALL [ebx+0xcc] (slot 0x33,
ReassignTileObjectOwnerAndNotifyForSelectedCells): when a minor nation finalized
joining an empire, the tile-object owner reassignment never ran.

The heuristic here: for each `// VTABLE:` annotation, read the original vtable,
take its last real slot, resolve that slot through its ILT thunk, and report the
class when the resulting function is declared in our headers but not as a
virtual. Three details matter, and each produced false positives before it was
handled: the dump runs past a class's table into whatever vtable sits next in
memory (so the extent must stop at the first NULL slot), `virtual` is often on
the line above a wrapped declaration, and the name lookup has to be scoped to
the annotated class's own header or an identically-named member of an unrelated
class matches.

This is a REPORTING aid, not a gate. Its output is a list of candidates to check
by hand, never grounds to edit a class model on its own: confirm the slot's
resolved target, confirm the call sites actually dispatch indirectly, and
re-measure. Marking a method virtual moves every slot declared after it.

Usage:
    uv run python -m tools.workflow.check_vtable_tail_slots [--limit N] [--class NAME]
"""

from __future__ import annotations

import argparse
import csv
import glob
import io
import re
import subprocess

VTABLE_RE = re.compile(r"//\s*VTABLE:\s*IMPERIALISM\s+(0x[0-9a-fA-F]+)")
CLASS_RE = re.compile(r"(?:class|struct)\s+(\w+)")
THUNK_RE = re.compile(r"->\s+[0-9a-f]+\s+(\w+)")


def collect_annotations() -> list[tuple[str, str, str]]:
    """Return (class_name, vtable_addr, header_path) for every // VTABLE: marker."""
    found = []
    for path in sorted(glob.glob("include/**/*.h", recursive=True)):
        lines = open(path, errors="replace").read().split("\n")
        for i, line in enumerate(lines):
            m = VTABLE_RE.match(line.strip())
            if not m:
                continue
            # The class/struct follows the annotation, but explanatory comments are
            # routinely interposed (TMinor.h has six lines between them), so scan a
            # generous window rather than assuming adjacency.
            for j in range(i + 1, min(i + 25, len(lines))):
                c = CLASS_RE.match(lines[j].strip())
                if c:
                    found.append((c.group(1), m.group(1), path))
                    break
    return found


class HeaderIndex:
    """Whether a function name is declared in our headers, and whether as a virtual."""

    def __init__(self) -> None:
        self.text: dict[str, list[str]] = {}
        for path in sorted(glob.glob("include/**/*.h", recursive=True)):
            self.text[path] = open(path, errors="replace").read().split("\n")

    def lookup(self, name: str, header: str | None = None) -> tuple[bool, bool]:
        """Return (declared_in_scope, declared_virtual).

        `header` scopes the search to the annotated class's own header. Without
        it, a name that belongs to an unrelated class matches and produces a
        false positive -- TDiplomacyMgr's last slot resolves to a function named
        IsNationSlotEligibleForEventProcessing, which is a non-virtual TSimMgr
        member; TDlgWindow's resolves to MFC CWnd::GetWindowText. Neither class
        declares the name itself, so neither is the missing-tail-slot defect.
        """
        pattern = re.compile(r"\b" + re.escape(name) + r"\s*\(")
        sources = [self.text[header]] if header and header in self.text else list(self.text.values())
        declared = False
        for lines in sources:
            for i, line in enumerate(lines):
                if not pattern.search(line):
                    continue
                declared = True
                # `virtual` frequently sits on the previous line of a wrapped
                # declaration ("virtual void\n  LongMethodName(...)").
                window = " ".join(lines[max(0, i - 2) : i + 1])
                if "virtual" in window or "override" in window:
                    return True, True
        return declared, False


def original_last_slot(cls: str, addr: str) -> dict | None:
    """Last real slot of the class's own vtable (bounded at the first NULL)."""
    proc = subprocess.run(
        ["just", "ghidra", "vtable-dump", cls, addr],
        capture_output=True,
        text=True,
        timeout=180,
    )
    body = "\n".join(
        l for l in proc.stdout.split("\n") if "," in l and not l.startswith(("uv ", ":", "hint"))
    )
    last = None
    for row in csv.DictReader(io.StringIO(body)):
        entry = row.get("entry_addr", "")
        if not entry or int(entry, 16) == 0:
            break  # end of this class's table; the dump continues into the next one
        last = row
    return last


def resolve(addr: str, fallback: str) -> str:
    """Resolve an ILT jmp thunk to the function it targets."""
    proc = subprocess.run(
        ["just", "ghidra", "listing", addr, hex(int(addr, 16) + 2)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    m = THUNK_RE.search(proc.stdout)
    return m.group(1) if m else fallback


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0, help="only scan the first N annotations")
    ap.add_argument("--class", dest="only", default=None, help="scan a single class")
    args = ap.parse_args()

    annotations = collect_annotations()
    if args.only:
        annotations = [a for a in annotations if a[0] == args.only]
    if args.limit:
        annotations = annotations[: args.limit]
    print(f"scanning {len(annotations)} // VTABLE: annotations", flush=True)

    headers = HeaderIndex()
    suspects = []
    for cls, addr, header in annotations:
        try:
            last = original_last_slot(cls, addr)
        except Exception:
            continue
        if not last:
            continue
        name = resolve(last["entry_addr"], last.get("current_name", ""))
        if not name:
            continue
        declared, is_virtual = headers.lookup(name, header)
        if declared and not is_virtual:
            suspects.append((cls, addr, last["index"], name, header))
            print(f"SUSPECT {cls} {addr} slot {last['index']} -> {name}  [{header}]", flush=True)

    print(f"=== {len(suspects)} candidate(s); verify each by hand before changing a class model")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
