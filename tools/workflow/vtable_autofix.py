#!/usr/bin/env python3
"""Classify `just vtable` failures and apply deterministic repair helpers.

Dry-run is the default. `--write` only runs existing safe repair paths:

* scalar-deleting-destructor spelling canonicalization;
* unreferenced ILT thunk pruning.

Structural vtable-size problems, base-owned mismatches, and referenced ILT
thunks are reported for manual follow-up; they are not edited here.
"""

from __future__ import annotations

import argparse
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from tools.common.pipe_csv import normalize_hex
from tools.common.repo import repo_root_from_file


VTABLE_HEADER_RE = re.compile(
    r"^(?P<class>[A-Za-z_][A-Za-z0-9_]*)::`vftable' : "
    r"orig (?P<orig>0x[0-9a-fA-F]+), recomp (?P<recomp>0x[0-9a-fA-F]+)"
)
LARGER_RE = re.compile(
    r"Recomp vtable is larger than orig vtable for "
    r"(?P<class>[A-Za-z_][A-Za-z0-9_]*)::`vftable'"
)
SLOT_RE = re.compile(r"^vtable(?P<byte>0x[0-9a-fA-F]+)")
MINUS_RE = re.compile(
    r": -\((?P<orig>0x[0-9a-fA-F]+) / "
    r"(?P<recomp>no recomp|0x[0-9a-fA-F]+)\)\s+:\s+(?P<name>.*)$"
)
PLUS_RE = re.compile(
    r": \+\((?P<orig>no orig|0x[0-9a-fA-F]+) / "
    r"(?P<recomp>0x[0-9a-fA-F]+)\)\s+:\s+(?P<name>.*)$"
)


@dataclass(frozen=True)
class VtableFinding:
    class_name: str
    slot_byte: int | None
    side: str
    orig: str
    recomp: str
    name: str

    @property
    def slot_index(self) -> int | None:
        if self.slot_byte is None:
            return None
        return self.slot_byte // 4


@dataclass
class VtableReport:
    classes: list[str] = field(default_factory=list)
    findings: list[VtableFinding] = field(default_factory=list)
    oversized: set[str] = field(default_factory=set)
    found_count: int | None = None
    not_matching_count: int | None = None


@dataclass(frozen=True)
class FixPlan:
    class_name: str
    kind: str
    safe: bool
    summary: str
    command: str | None = None
    addresses: tuple[str, ...] = ()


def parse_vtable_output(text: str) -> VtableReport:
    report = VtableReport()
    current: str | None = None
    slot_byte: int | None = None

    for line in text.splitlines():
        if m := LARGER_RE.search(line):
            report.oversized.add(m.group("class"))
            continue
        if m := VTABLE_HEADER_RE.match(line):
            current = m.group("class")
            report.classes.append(current)
            slot_byte = None
            continue
        if m := SLOT_RE.match(line):
            slot_byte = int(m.group("byte"), 16)
        if current is None:
            if line.startswith("Vtables found:"):
                report.found_count = int(line.split(":", 1)[1].strip().rstrip("."))
            elif line.startswith("Vtables not matching:"):
                report.not_matching_count = int(line.split(":", 1)[1].strip().rstrip("."))
            continue
        if m := MINUS_RE.search(line):
            report.findings.append(
                VtableFinding(
                    current,
                    slot_byte,
                    "orig",
                    m.group("orig"),
                    m.group("recomp"),
                    m.group("name").strip(),
                )
            )
        elif m := PLUS_RE.search(line):
            report.findings.append(
                VtableFinding(
                    current,
                    slot_byte,
                    "recomp",
                    m.group("orig"),
                    m.group("recomp"),
                    m.group("name").strip(),
                )
            )
        if line.startswith("Vtables found:"):
            report.found_count = int(line.split(":", 1)[1].strip().rstrip("."))
        elif line.startswith("Vtables not matching:"):
            report.not_matching_count = int(line.split(":", 1)[1].strip().rstrip("."))
    return report


def run_vtable(repo_root: Path, class_filter: str | None) -> str:
    cmd = ["just", "vtable"]
    if class_filter:
        cmd.append(class_filter)
    cmd.append("-n")
    proc = subprocess.run(cmd, cwd=repo_root, text=True, capture_output=True, check=False)
    return proc.stdout + proc.stderr


def _is_ilt_addr(addr: str) -> bool:
    try:
        value = int(addr, 16)
    except ValueError:
        return False
    return 0x00401000 <= value <= 0x00409FFF


def _ilt_target_is_claimed(repo_root: Path, ilt_addr: str) -> bool:
    """True when the ILT thunk address is claimed by a source marker."""
    from tools.source_model import claimed_addresses

    return int(normalize_hex(ilt_addr), 16) in claimed_addresses(repo_root, "IMPERIALISM")


def plan_for_classes(repo_root: Path, report: VtableReport, classes: list[str]) -> list[FixPlan]:
    plans: list[FixPlan] = []
    seen: set[tuple[str, str, str]] = set()
    findings_by_class: dict[str, list[VtableFinding]] = {
        cls: [f for f in report.findings if f.class_name == cls] for cls in classes
    }

    for cls in classes:
        class_findings = findings_by_class.get(cls, [])
        if any(
            "scalar_deleting_destructor" in f.name or "AndMaybeFree" in f.name
            for f in class_findings
        ):
            key = (cls, "scalar_dtor", "")
            if key not in seen:
                plans.append(
                    FixPlan(
                        cls,
                        "scalar_dtor",
                        True,
                        "canonicalize scalar deleting destructor names/comments",
                        "just correct-scalar-dtors",
                    )
                )
                seen.add(key)

        ilt = [
            f
            for f in class_findings
            if f.side == "orig" and f.orig.startswith("0x") and _is_ilt_addr(f.orig)
        ]
        if ilt:
            referenced = [f for f in ilt if _ilt_target_is_claimed(repo_root, f.orig)]
            unreferenced = [f for f in ilt if f not in referenced]
            if referenced:
                addrs = ", ".join(f"0x{f.orig}" for f in referenced[:6])
                plans.append(
                    FixPlan(
                        cls,
                        "ilt_thunk_referenced",
                        False,
                        f"referenced ILT slot(s) need callsite repoint + symbols row drop ({addrs})",
                        "just repair-thunk-migration <addr>",
                        tuple(f.orig for f in referenced),
                    )
                )
            if unreferenced:
                plans.append(
                    FixPlan(
                        cls,
                        "ilt_thunk",
                        True,
                        f"prune unreferenced ILT thunk rows ({len(unreferenced)} slot(s))",
                        "just prune-ilt-thunks",
                        tuple(f.orig for f in unreferenced),
                    )
                )

        if cls in report.oversized:
            plans.append(
                FixPlan(
                    cls,
                    "oversized_vtable",
                    False,
                    "recompiled vtable is larger than original; inspect declaration/order/base model",
                )
            )
    return plans


def _run_just(repo_root: Path, *args: str) -> int:
    print("$ just " + " ".join(args))
    return subprocess.run(["just", *args], cwd=repo_root, check=False).returncode


def apply_plans(repo_root: Path, plans: list[FixPlan], verify: bool) -> int:
    rc = 0
    if any(p.kind == "scalar_dtor" and p.safe for p in plans):
        rc = rc or _run_just(repo_root, "correct-scalar-dtors")
    if any(p.kind == "ilt_thunk" and p.safe for p in plans):
        rc = rc or _run_just(repo_root, "prune-ilt-thunks")
    if rc != 0 or not verify:
        return rc
    for target in ("build", "detect"):
        rc = rc or _run_just(repo_root, target)
        if rc:
            return rc
    return rc or _run_just(repo_root, "gates")


def print_plans(report: VtableReport, plans: list[FixPlan], write: bool) -> None:
    if report.found_count is not None and report.not_matching_count is not None:
        print(
            f"vtable-autofix: vtables found {report.found_count}, "
            f"not matching {report.not_matching_count}"
        )
    if not plans:
        print("vtable-autofix: no actionable findings.")
        return
    for plan in plans:
        state = "safe" if plan.safe else "manual"
        print(f"{plan.class_name}: [{state}] {plan.kind}: {plan.summary}")
        if plan.addresses:
            print("  addresses: " + ", ".join(plan.addresses[:12]))
        if plan.command:
            prefix = "  run:" if write else "  would run:"
            print(f"{prefix} {plan.command}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("class_filter", nargs="?", help="Class/filter to pass to `just vtable`.")
    parser.add_argument("--all", action="store_true", help="Analyze all classes from vtable output.")
    parser.add_argument("--write", action="store_true", help="Apply safe fixes.")
    parser.add_argument(
        "--verify",
        action="store_true",
        help="After --write, run sync/build/detect/gates.",
    )
    parser.add_argument("--limit", type=int, default=0, help="Analyze at most N classes.")
    parser.add_argument(
        "--max-rounds",
        type=int,
        default=0,
        help="When --write is set, repeat autofix → build "
        "and stop when the aggregate not-matching vtable count stabilizes or rounds "
        "are exhausted. 0 disables the loop (single pass). Implies --all when no "
        "class filter is given.",
    )
    parser.add_argument("--vtable-log", type=Path, help="Use an existing `just vtable -n` log.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.class_filter and not args.all and not args.vtable_log and not args.max_rounds:
        raise SystemExit("pass a class filter, --all, --max-rounds, or --vtable-log")

    repo_root = repo_root_from_file(__file__)
    if args.max_rounds and not args.write:
        raise SystemExit("--max-rounds requires --write")
    if args.max_rounds:
        args.all = True

    max_rounds = args.max_rounds if args.max_rounds else 1
    prev_not_matching: int | None = None
    rc = 0

    for round_idx in range(1, max_rounds + 1):
        if args.max_rounds:
            print(f"vtable-autofix: round {round_idx}/{max_rounds}")

        output = (
            args.vtable_log.read_text(encoding="utf-8", errors="ignore")
            if args.vtable_log and round_idx == 1
            else run_vtable(repo_root, None if args.all or args.max_rounds else args.class_filter)
        )
        report = parse_vtable_output(output)
        classes = report.classes
        if args.class_filter and args.class_filter not in classes:
            classes = [c for c in classes if args.class_filter.lower() in c.lower()]
        if args.limit:
            classes = classes[: args.limit]
        plans = plan_for_classes(repo_root, report, classes)
        print_plans(report, plans, args.write)

        if report.not_matching_count is not None and args.max_rounds:
            delta = (
                ""
                if prev_not_matching is None
                else f" (delta {report.not_matching_count - prev_not_matching:+d})"
            )
            print(
                f"vtable-autofix: not matching {report.not_matching_count}{delta}"
            )
            if (
                prev_not_matching is not None
                and report.not_matching_count == prev_not_matching
            ):
                print("vtable-autofix: count stable; stopping early")
                break
            prev_not_matching = report.not_matching_count

        if not args.write:
            return 0

        rc = apply_plans(repo_root, plans, verify=args.verify or bool(args.max_rounds))
        if args.max_rounds:
            for target in ("build",):
                rc = rc or _run_just(repo_root, target)
                if rc:
                    return rc
        elif rc != 0:
            return rc

    return rc


if __name__ == "__main__":
    raise SystemExit(main())
