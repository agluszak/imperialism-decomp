#!/usr/bin/env python3
"""Read-only Ghidra body-integrity audit: find functions that own the wrong bytes.

`check-function-extents` catches exactly one shape -- a body whose last instruction is
not a terminator. That misses the failure that cost real work twice: a *punctured* body,
where an inner pseudo-function was demoted to a label and its bytes were never handed
back, so the enclosing function's range has a hole in the middle and the code inside it
is owned by nobody. The curated inventory stays self-consistent, every existing gate
passes, and reccmp silently compares through a keyhole.

This audit looks at the body as a whole and reports:

  body_hole                    the body is split into several ranges: either bytes were
                               carved out of the middle and never returned, or the body
                               claims two far-apart regions. A hole that holds only
                               alignment padding, or an in-body jump table (data the
                               body's own instructions reference), is NOT a violation:
                               Ghidra is right to keep data out of a body, and memmove
                               alone has seven such "holes"
  label_in_hole                a label sits exactly at the start of a hole -- the
                               demote-to-label signature (bd 6q2)
  fallthrough_to_unowned       the body ends on a non-terminator and the next byte is
                               code owned by no function: flow runs off the edge
  truncated_into_function      same, but the next byte belongs to another function --
                               usually a fragment carved out of this one
  contains_other_entry         another function's entry point lies inside this body
  curated_size_mismatch        config/original_entities.csv disagrees with the DB body

The first four are hard violations: they mean bytes are unowned or misowned, which is
never intentional. `--strict` exits non-zero when any hard violation is present, so a DB
mutation or archive update can be gated on it. The last two are advisory -- an entry
inside a body can be a legitimately shared tail, and a curated size can lead the DB
during a repair.

usage:
  body-integrity-audit [--strict] [--limit N] [--kind KIND]
"""

from __future__ import annotations

import argparse
import csv
import sys
from dataclasses import dataclass, field
from pathlib import Path

TERMINATORS = {"RET", "RETF", "JMP", "INT3", "UD2"}
REPO_ROOT = Path(__file__).resolve().parents[2]
INVENTORY = REPO_ROOT / "config" / "original_entities.csv"

HARD_KINDS = (
    "body_hole",
    "label_in_hole",
    "fallthrough_to_unowned",
    "truncated_into_function",
)
ADVISORY_KINDS = ("contains_other_entry", "curated_size_mismatch")
ALL_KINDS = HARD_KINDS + ADVISORY_KINDS


@dataclass(frozen=True)
class FunctionView:
    """Everything the analysis needs about one function, with no Ghidra types."""

    entry: int
    name: str
    # Inclusive byte ranges of the body, in ascending order.
    ranges: tuple[tuple[int, int], ...]
    # Mnemonic of the last instruction inside the body ("" when undisassembled).
    last_mnemonic: str = ""
    # Mnemonic at the first byte past the body; None when that byte is not code.
    boundary_mnemonic: str | None = None
    # Entry of the function owning the byte past the body; None when unowned.
    boundary_owner: int | None = None
    # Entries of other functions whose entry point falls inside this body.
    inner_entries: tuple[int, ...] = ()
    # Label addresses inside this function's span (entry .. end of last range).
    labels: tuple[int, ...] = ()
    # Holes verified benign by the collector: only padding and/or data the body's own
    # instructions reference (an inline switch table). Skipped by analyze().
    benign_holes: tuple[tuple[int, int], ...] = ()
    curated_size: int | None = None


@dataclass
class Violation:
    kind: str
    entry: int
    name: str
    detail: str

    @property
    def hard(self) -> bool:
        return self.kind in HARD_KINDS


@dataclass
class Report:
    violations: list[Violation] = field(default_factory=list)
    checked: int = 0

    @property
    def hard(self) -> list[Violation]:
        return [v for v in self.violations if v.hard]


def body_holes(ranges: tuple[tuple[int, int], ...]) -> list[tuple[int, int]]:
    """Inclusive [start, end] of each gap between consecutive body ranges."""
    ordered = sorted(ranges)
    return [
        (ordered[i][1] + 1, ordered[i + 1][0] - 1)
        for i in range(len(ordered) - 1)
        if ordered[i + 1][0] - ordered[i][1] > 1
    ]


def hole_is_benign(unit_kinds: list[str], data_referenced_from_body: bool) -> bool:
    """Decide one hole from its code units: 'padding' | 'data' | 'code' each.

    Real code in a hole is always a violation -- that is the punctured-body signature.
    Padding alone (alignment nop / int3 / zero fill) is benign. Data is benign only when
    the body's own instructions reference it: that is an inline jump table, which Ghidra
    deliberately keeps out of the body. Unreferenced data stays a violation -- data that
    nothing points at is exactly what a stale definition masking real code looks like
    (the 0x4c49f0 case, 23 bytes of code hidden under a DATA unit).
    """
    if not unit_kinds or any(kind == "code" for kind in unit_kinds):
        return False
    if any(kind == "data" for kind in unit_kinds):
        return data_referenced_from_body
    return True


def body_size(ranges: tuple[tuple[int, int], ...]) -> int:
    return sum(hi - lo + 1 for lo, hi in ranges)


def analyze(function: FunctionView) -> list[Violation]:
    """Every body-integrity violation visible in one function's view."""
    out: list[Violation] = []
    if not function.ranges:
        return out

    holes = body_holes(function.ranges)
    for lo, hi in holes:
        if (lo, hi) in function.benign_holes:
            # Padding or an in-body jump table; a label here (switchdataD_...) is normal.
            continue
        out.append(
            Violation(
                "body_hole",
                function.entry,
                function.name,
                f"body is split; 0x{lo:08x}-0x{hi:08x} ({hi - lo + 1} bytes) sits "
                "outside it — bytes carved out of the middle and never returned, or a "
                "body claiming two far-apart regions",
            )
        )
        if lo in function.labels:
            out.append(
                Violation(
                    "label_in_hole",
                    function.entry,
                    function.name,
                    f"label at 0x{lo:08x} starts a body hole "
                    "(demoted pseudo-function whose bytes were never returned)",
                )
            )

    terminated = function.last_mnemonic.upper() in TERMINATORS
    if not terminated and function.boundary_mnemonic is not None:
        end = function.ranges[-1][1] + 1
        if function.boundary_owner is None:
            out.append(
                Violation(
                    "fallthrough_to_unowned",
                    function.entry,
                    function.name,
                    f"body ends on {function.last_mnemonic} and falls through into "
                    f"unowned code at 0x{end:08x} ({function.boundary_mnemonic})",
                )
            )
        elif function.boundary_owner != function.entry:
            out.append(
                Violation(
                    "truncated_into_function",
                    function.entry,
                    function.name,
                    f"body ends on {function.last_mnemonic}; 0x{end:08x} belongs to "
                    f"0x{function.boundary_owner:08x} ({function.boundary_mnemonic})",
                )
            )

    for inner in function.inner_entries:
        out.append(
            Violation(
                "contains_other_entry",
                function.entry,
                function.name,
                f"function 0x{inner:08x} starts inside this body",
            )
        )

    if function.curated_size is not None:
        actual = body_size(function.ranges)
        if function.curated_size != actual:
            out.append(
                Violation(
                    "curated_size_mismatch",
                    function.entry,
                    function.name,
                    f"inventory says {function.curated_size} bytes, DB body is {actual}",
                )
            )
    return out


def audit(functions: list[FunctionView]) -> Report:
    report = Report(checked=len(functions))
    for function in functions:
        report.violations.extend(analyze(function))
    return report


def curated_sizes() -> dict[int, int]:
    sizes: dict[int, int] = {}
    if not INVENTORY.is_file():
        return sizes
    with INVENTORY.open(encoding="utf-8") as handle:
        for row in csv.DictReader(handle, delimiter="|"):
            if (row.get("type") or "").strip() != "function":
                continue
            size = (row.get("size") or "").strip()
            address = (row.get("address") or "").strip()
            if size.isdigit() and address:
                sizes[int(address, 16)] = int(size)
    return sizes


def collect(program) -> list[FunctionView]:
    """Build FunctionViews from the live program (the only Ghidra-aware step)."""
    listing = program.getListing()
    space = program.getAddressFactory().getDefaultAddressSpace()
    fm = program.getFunctionManager()
    sizes = curated_sizes()

    entry_set = {function.getEntryPoint().getOffset() for function in fm.getFunctions(True)}

    views: list[FunctionView] = []
    for function in fm.getFunctions(True):
        entry = function.getEntryPoint().getOffset()
        body = function.getBody()
        ranges = tuple(
            (r.getMinAddress().getOffset(), r.getMaxAddress().getOffset())
            for r in body.getAddressRanges()
        )
        if not ranges:
            continue
        ordered = tuple(sorted(ranges))
        end = ordered[-1][1] + 1

        last_mnemonic = ""
        cursor = listing.getInstructionAt(space.getAddress(entry))
        while cursor is not None:
            offset = cursor.getAddress().getOffset()
            if offset >= end:
                break
            if body.contains(cursor.getAddress()):
                last_mnemonic = str(cursor.getMnemonicString()).upper()
            cursor = cursor.getNext()

        boundary_addr = space.getAddress(end)
        boundary_insn = listing.getInstructionAt(boundary_addr)
        boundary_owner = fm.getFunctionContaining(boundary_addr)
        inner = tuple(
            other
            for other in entry_set
            if other != entry and any(lo <= other <= hi for lo, hi in ordered)
        )
        # Labels are filled in by _attach_hole_labels: only hole starts need a lookup,
        # and iterating the whole symbol table per function would be far too slow.
        views.append(
            FunctionView(
                entry=entry,
                name=str(function.getName()),
                ranges=ordered,
                last_mnemonic=last_mnemonic,
                boundary_mnemonic=str(boundary_insn.getMnemonicString()).upper()
                if boundary_insn is not None
                else None,
                boundary_owner=boundary_owner.getEntryPoint().getOffset()
                if boundary_owner is not None
                else None,
                inner_entries=inner,
                labels=(),
                curated_size=sizes.get(entry),
            )
        )
    return _attach_hole_labels(program, views)


# x86 alignment filler the compiler emits between basic blocks. Byte VALUES are not
# enough: MSVC pads with multi-byte semantic no-ops (`2E 8B C0` = mov eax,eax with a CS
# prefix, `8D 49 00` = lea ecx,[ecx+0]), which look like "code" one byte at a time.
FILLER_PREFIXES = {0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x66, 0x67}
MOV_SAME_REG_MODRM = {0xC0, 0xC9, 0xD2, 0xDB, 0xE4, 0xED, 0xF6, 0xFF}


def is_filler_bytes(raw: bytes) -> bool:
    """True when `raw` is entirely x86 alignment filler.

    Conservative by construction: anything the matcher does not recognise counts as
    code, which keeps the violation. Recognised forms: nop / int3 / zero fill, optional
    segment or size prefixes, `mov reg,reg` (same register), and zero-displacement
    `lea reg,[reg]` in its disp8, disp32 and ESP/SIB encodings.
    """
    i = 0
    n = len(raw)
    if n == 0:
        return True
    while i < n:
        b = raw[i]
        if b in (0x90, 0xCC, 0x00):
            i += 1
            continue
        if b in FILLER_PREFIXES and i + 1 < n:
            i += 1
            continue
        if b == 0x8B and i + 1 < n and raw[i + 1] in MOV_SAME_REG_MODRM:
            i += 2
            continue
        if b == 0x8D and i + 1 < n:
            modrm = raw[i + 1]
            mod, reg, rm = modrm >> 6, (modrm >> 3) & 7, modrm & 7
            if mod == 1 and rm != 4 and reg == rm and i + 2 < n and raw[i + 2] == 0:
                i += 3
                continue
            if (mod == 1 and rm == 4 and reg == 4 and i + 3 < n
                    and raw[i + 2] == 0x24 and raw[i + 3] == 0):
                i += 4
                continue
            if (mod == 2 and rm != 4 and reg == rm and i + 6 <= n
                    and all(raw[j] == 0 for j in range(i + 2, i + 6))):
                i += 6
                continue
            if (mod == 2 and rm == 4 and reg == 4 and i + 7 <= n
                    and raw[i + 2] == 0x24
                    and all(raw[j] == 0 for j in range(i + 3, i + 7))):
                i += 7
                continue
        return False
    return True


def _hole_unit_kinds(program, space, lo: int, hi: int) -> list[str]:
    """'padding' | 'data' | 'code' per segment of the hole.

    Defined data stays its own segment; everything between data units (instructions and
    undefined bytes alike) is gathered into contiguous byte runs and judged as a whole
    with is_filler_bytes -- multi-byte filler spans several 1-byte undefined units, so
    unit-at-a-time classification cannot see it.
    """
    listing = program.getListing()
    from ghidra.program.model.listing import Data

    kinds: list[str] = []
    pending = bytearray()

    def flush() -> None:
        if pending:
            kinds.append("padding" if is_filler_bytes(bytes(pending)) else "code")
            pending.clear()

    address = space.getAddress(lo)
    end = space.getAddress(hi)
    while address is not None and address.compareTo(end) <= 0:
        unit = listing.getCodeUnitAt(address) or listing.getCodeUnitContaining(address)
        if unit is None:
            flush()
            kinds.append("code")  # unreadable: never benign
            break
        if isinstance(unit, Data) and unit.isDefined():
            flush()
            kinds.append("data")
        else:
            try:
                pending.extend(value & 0xFF for value in unit.getBytes())
            except Exception:
                flush()
                kinds.append("code")
                break
        address = unit.getMaxAddress().next()
    flush()
    return kinds


def _hole_data_referenced_from_body(program, space, ranges, lo: int, hi: int) -> bool:
    """Does any instruction inside the body reference data inside this hole?"""
    listing = program.getListing()
    reference_manager = program.getReferenceManager()
    for data in listing.getDefinedData(space.getAddress(lo), True):
        offset = data.getAddress().getOffset()
        if offset > hi:
            break
        for reference in reference_manager.getReferencesTo(data.getAddress()):
            from_offset = reference.getFromAddress().getOffset()
            if any(range_lo <= from_offset <= range_hi for range_lo, range_hi in ranges):
                return True
    return False


def _attach_hole_labels(program, views: list[FunctionView]) -> list[FunctionView]:
    """Second pass: only hole starts need a label lookup, so ask about those addresses."""
    space = program.getAddressFactory().getDefaultAddressSpace()
    symbols = program.getSymbolTable()
    out: list[FunctionView] = []
    for view in views:
        holes = body_holes(view.ranges)
        if not holes:
            out.append(view)
            continue
        # A symbol at a hole start only means "demoted pseudo-function" when nothing
        # owns that address any more. When a real function starts there, the gap is a
        # neighbour, not an orphan, and fix-function-bounds correctly refuses to absorb
        # it -- reporting those as label_in_hole sent an earlier repair pass chasing
        # eleven non-defects.
        fm = program.getFunctionManager()
        labelled = tuple(
            lo
            for lo, _ in holes
            if symbols.getPrimarySymbol(space.getAddress(lo)) is not None
            and fm.getFunctionAt(space.getAddress(lo)) is None
        )
        benign = tuple(
            (lo, hi)
            for lo, hi in holes
            if hole_is_benign(
                _hole_unit_kinds(program, space, lo, hi),
                _hole_data_referenced_from_body(program, space, view.ranges, lo, hi),
            )
        )
        out.append(
            FunctionView(
                entry=view.entry,
                name=view.name,
                ranges=view.ranges,
                last_mnemonic=view.last_mnemonic,
                boundary_mnemonic=view.boundary_mnemonic,
                boundary_owner=view.boundary_owner,
                inner_entries=view.inner_entries,
                labels=labelled,
                benign_holes=benign,
                curated_size=view.curated_size,
            )
        )
    return out


def format_report(report: Report, *, limit: int = 0, kind: str = "") -> str:
    lines = [f"functions checked: {report.checked}"]
    selected = [v for v in report.violations if not kind or v.kind == kind]
    by_kind: dict[str, int] = {}
    for violation in selected:
        by_kind[violation.kind] = by_kind.get(violation.kind, 0) + 1
    summary = "  ".join(f"{k}={by_kind.get(k, 0)}" for k in ALL_KINDS)
    lines.append(f"violations: {len(selected)}  [{summary}]")
    lines.append("")
    ordered = sorted(selected, key=lambda v: (not v.hard, v.kind, v.entry))
    for violation in ordered[: limit or len(ordered)]:
        mark = "HARD" if violation.hard else "note"
        lines.append(f"[{mark}] {violation.kind} 0x{violation.entry:08x} {violation.name}")
        lines.append(f"    {violation.detail}")
    if limit and len(ordered) > limit:
        lines.append(f"... {len(ordered) - limit} more (raise --limit)")
    return "\n".join(lines)


BASELINE = REPO_ROOT / "config" / "baselines" / "body_integrity_baseline.csv"


def baseline_keys(path: Path) -> set[tuple[int, str]]:
    """(address, kind) pairs a human has already seen. Missing file -> empty."""
    if not path.is_file():
        return set()
    keys: set[tuple[int, str]] = set()
    with path.open(encoding="utf-8") as handle:
        for row in csv.DictReader(handle, delimiter="|"):
            address = (row.get("address") or "").strip()
            kind = (row.get("kind") or "").strip()
            if address and kind:
                keys.add((int(address, 16), kind))
    return keys


def write_baseline(path: Path, report: Report) -> None:
    keys = sorted({(violation.entry, violation.kind) for violation in report.violations
                   if violation.hard})
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        handle.write("address|kind\n")
        for address, kind in keys:
            handle.write(f"{address:08x}|{kind}\n")


def new_violations(report: Report, baseline: set[tuple[int, str]]) -> list[Violation]:
    """Hard violations the baseline has not already accepted."""
    return [violation for violation in report.hard
            if (violation.entry, violation.kind) not in baseline]


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--strict", action="store_true",
                        help="exit 1 when any hard violation is present")
    parser.add_argument("--gate", action="store_true",
                        help="exit 1 only on hard violations absent from the baseline")
    parser.add_argument("--write-baseline", action="store_true",
                        help="record today's hard violations as the accepted baseline")
    parser.add_argument("--limit", type=int, default=0, help="print at most N violations")
    parser.add_argument("--kind", default="", choices=("",) + ALL_KINDS,
                        help="report only this violation kind")
    return parser.parse_args(argv)


def main() -> int:
    args = parse_args()
    from tools.common import ghidra_env

    project = ghidra_env.open_project()
    consumer = None
    program = None
    try:
        consumer, program = ghidra_env.open_program(project)
        report = audit(collect(program))
    finally:
        if program is not None:
            program.release(consumer)
        project.close()

    if args.write_baseline:
        write_baseline(BASELINE, report)
        print(f"wrote {BASELINE.relative_to(REPO_ROOT)} "
              f"({len(baseline_keys(BASELINE))} accepted hard violation(s))")
        return 0

    print(format_report(report, limit=args.limit, kind=args.kind))

    if args.gate:
        accepted = baseline_keys(BASELINE)
        fresh = new_violations(report, accepted)
        if fresh:
            print(f"\nbody-integrity gate FAILED: {len(fresh)} hard violation(s) not in "
                  f"{BASELINE.relative_to(REPO_ROOT)}:", file=sys.stderr)
            for violation in fresh:
                print(f"  {violation.kind} 0x{violation.entry:08x} {violation.name}",
                      file=sys.stderr)
            print("Repair the DB (demote-functions / delete-labels / fix-function-bounds "
                  "--force, one address at a time for --clear-data-holes), never the "
                  "baseline.", file=sys.stderr)
            return 1
        stale = len(accepted) - (len(report.hard) - len(fresh))
        print(f"body-integrity gate passed: {len(report.hard)} hard violation(s), all "
              f"accepted by the baseline"
              + (f"; {stale} baseline row(s) now clean — rerun with --write-baseline"
                 if stale > 0 else ""))
        return 0

    if args.strict and report.hard:
        print(f"\nbody-integrity audit FAILED: {len(report.hard)} hard violation(s). "
              "Repair the DB (demote-functions / delete-labels / fix-function-bounds "
              "--force [--clear-data-holes]), never the curated size.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
