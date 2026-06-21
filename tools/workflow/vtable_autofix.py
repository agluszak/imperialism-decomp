#!/usr/bin/env python3
"""Classify `just vtable` failures and apply deterministic repair helpers.

Dry-run is the default. `--write` only runs existing safe repair paths:

* manifest-driven slot claims via marker-only stubs;
* scalar-deleting-destructor spelling canonicalization;
* unreferenced ILT thunk pruning.

Structural vtable-size problems and referenced ILT thunks are reported for manual
follow-up; they are not edited here. Body promotion is intentionally opt-in because
`just vtable` work should pair slots before porting logic.
"""

from __future__ import annotations

import argparse
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from tools.common import class_manifest as cm
from tools.common.pipe_csv import normalize_hex, read_pipe_rows
from tools.common.repo import repo_root_from_file, resolve_repo_path
from tools.workflow.class_codegen import ClassifiedSlot, plan_ownership, plan_symbols
from tools.workflow.gen_class import (
    _definition_head_key,
    _find_block_end,
    _has_immediate_marker_before,
    _is_trivial_unmarked_stub,
    _slot_definition_head,
    classified_from_manifest,
    header_path,
    manifest_path,
    render_generated_block,
    render_generated_decls,
    scalar_dtor_block,
    upsert_block,
    upsert_decls_block,
)


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
ADDR_MARKER_RE = re.compile(
    r"^[ \t]*//\s*(?:"
    r"(?:FUNCTION|STUB)\s*:\s*IMPERIALISM\s+"
    r"|SYNTHETIC:\s*IMPERIALISM\s+"
    r"|GHIDRA_FUNCTION\s+IMPERIALISM\s+"
    r")(?:0x)?([0-9a-fA-F]+)\s*$",
    re.MULTILINE,
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


def _manual_owners(repo_root: Path) -> dict[str, str]:
    path = resolve_repo_path(repo_root, "config/function_ownership.csv")
    if not path.exists():
        return {}
    out: dict[str, str] = {}
    for row in read_pipe_rows(path):
        if (row.get("ownership") or "").strip() != "manual":
            continue
        addr = normalize_hex((row.get("address") or "").strip())
        if addr:
            out[addr] = (row.get("target_cpp") or "").strip()
    return out


def _manifest_owned_slots(repo_root: Path, cls: str) -> tuple[list[ClassifiedSlot], list[str]]:
    path = manifest_path(repo_root, cls)
    if not path.exists():
        return [], []
    target_cpp = f"src/game/{cls}.cpp"
    owners = _manual_owners(repo_root)
    slots = [
        s
        for s in classified_from_manifest(cm.load_manifest(path), repo_root)
        if s.kind in ("override", "new", "scalar_dtor") and s.target_addr
    ]
    collisions = []
    owned = []
    for slot in slots:
        addr = normalize_hex(slot.target_addr)
        owner = owners.get(addr)
        if owner and owner != target_cpp:
            collisions.append(f"0x{int(addr, 16):08x} already owned by {owner}")
            continue
        owned.append(slot)
    return owned, collisions


def _claimable_manifest_slots(repo_root: Path, cls: str) -> tuple[tuple[str, ...], list[str]]:
    slots, collisions = _manifest_owned_slots(repo_root, cls)
    addresses = tuple(f"0x{int(s.target_addr, 16):08x}" for s in slots)
    return addresses, collisions


def _manifest_slot_kinds(repo_root: Path, cls: str) -> dict[int, tuple[str, str | None]]:
    path = manifest_path(repo_root, cls)
    if not path.exists():
        return {}
    manifest = cm.load_manifest(path)
    base = str((manifest.get("generated") or {}).get("base") or "")
    slots = {}
    for slot in (manifest.get("generated") or {}).get("slots") or []:
        slots[cm._as_int(slot.get("byte") or 0) // 4] = (str(slot.get("kind") or ""), base)
    return slots


def _is_ilt_addr(addr: str) -> bool:
    try:
        value = int(addr, 16)
    except ValueError:
        return False
    return 0x00401000 <= value <= 0x00409FFF


def _slot_addr(slot: ClassifiedSlot) -> int:
    return int(normalize_hex(slot.target_addr), 16)


def _stub_block(cls: str, slot: ClassifiedSlot) -> str:
    addr = _slot_addr(slot)
    if slot.kind == "scalar_dtor":
        return scalar_dtor_block(cls, addr) + f"{cls}::~{cls}() {{}}\n\n"
    assert slot.sig is not None
    lines = [f"// FUNCTION: IMPERIALISM 0x{addr:08x}", f"{slot.sig.definition_head(cls)} {{"]
    if slot.sig.ret.strip() not in ("void", ""):
        lines.append("  return 0;")
    lines.append("}")
    return "\n".join(lines) + "\n\n"


def _strip_or_mark_unmarked_stubs(
    cpp_text: str, cls: str, slots: list[ClassifiedSlot]
) -> tuple[str, set[int]]:
    heads: dict[str, ClassifiedSlot] = {}
    for slot in slots:
        head = _slot_definition_head(cls, slot)
        if head:
            heads[_definition_head_key(head)] = slot
    if not heads:
        return cpp_text, set()

    def has_marker_before_definition(pos: int) -> bool:
        if _has_immediate_marker_before(cpp_text, pos):
            return True
        prefix = cpp_text[:pos].rstrip()
        for line in reversed(prefix.splitlines()[-4:]):
            stripped = line.strip()
            if ADDR_MARKER_RE.match(stripped):
                return True
            if stripped.startswith("//"):
                continue
            break
        return False

    pattern = re.compile(
        rf"^[ \t]*(?P<head>[^\n;{{}}]*\b{re.escape(cls)}::"
        rf"(?:~{re.escape(cls)}|[A-Za-z_][A-Za-z0-9_]*)\s*"
        rf"\([^;{{}}]*\)\s*(?:const)?\s*)\{{",
        re.MULTILINE,
    )
    chunks: list[str] = []
    cursor = 0
    marked: set[int] = set()
    for match in pattern.finditer(cpp_text):
        if has_marker_before_definition(match.start()):
            continue
        slot = heads.get(_definition_head_key(match.group("head")))
        if slot is None:
            continue
        end = _find_block_end(cpp_text, match.end() - 1)
        if end is None:
            continue
        remove_end = end
        while remove_end < len(cpp_text) and cpp_text[remove_end] in " \t\r\n":
            remove_end += 1
        block = cpp_text[match.start() : end]
        addr = _slot_addr(slot)
        chunks.append(cpp_text[cursor : match.start()])
        if _is_trivial_unmarked_stub(block):
            cursor = remove_end
            continue
        if slot.kind == "scalar_dtor":
            chunks.append(scalar_dtor_block(cls, addr))
        else:
            chunks.append(f"// FUNCTION: IMPERIALISM 0x{addr:08x}\n")
        chunks.append(block)
        cursor = end
        marked.add(addr)
    if cursor == 0:
        return cpp_text, set()
    chunks.append(cpp_text[cursor:])
    return "".join(chunks), marked


def _merge_marker_stubs(cpp_text: str, cls: str, slots: list[ClassifiedSlot]) -> tuple[str, list[int]]:
    cpp_text, marked = _strip_or_mark_unmarked_stubs(cpp_text, cls, slots)
    matches = list(ADDR_MARKER_RE.finditer(cpp_text))
    preamble = cpp_text[: matches[0].start()] if matches else cpp_text
    existing: dict[int, str] = {}
    for i, match in enumerate(matches):
        start = match.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(cpp_text)
        addr = int(match.group(1), 16)
        existing[addr] = cpp_text[start:end].rstrip() + "\n\n"

    claimed = sorted(marked)
    for slot in sorted(slots, key=_slot_addr):
        addr = _slot_addr(slot)
        block = existing.get(addr)
        if block is not None:
            if slot.kind == "scalar_dtor" and f"{cls}::~{cls}(" not in block:
                existing[addr] = _stub_block(cls, slot)
                claimed.append(addr)
            continue
        existing[addr] = _stub_block(cls, slot)
        claimed.append(addr)

    body = "".join(existing[a] for a in sorted(existing))
    if preamble and not preamble.endswith("\n"):
        preamble += "\n"
    return preamble.rstrip() + "\n\n" + body.rstrip() + "\n", sorted(set(claimed))


def claim_vtable_slots(repo_root: Path, cls: str, write: bool) -> int:
    path = manifest_path(repo_root, cls)
    if not path.exists():
        print(f"vtable-autofix: no manifest {path}")
        return 1
    manifest = cm.load_manifest(path)
    slots, collisions = _manifest_owned_slots(repo_root, cls)
    if collisions:
        print(f"vtable-autofix {cls}: refusing slot claim due to ownership collisions:")
        for collision in collisions:
            print(f"  {collision}")
        return 1

    hpath = header_path(repo_root, cls)
    cpp_path = resolve_repo_path(repo_root, f"src/game/{cls}.cpp")
    if not hpath.exists():
        print(f"vtable-autofix {cls}: missing header {hpath}")
        return 1

    header_text = hpath.read_text(encoding="utf-8")
    new_header, block_changed = upsert_block(header_text, cls, render_generated_block(manifest))
    decls = render_generated_decls(
        manifest,
        [s for s in classified_from_manifest(manifest, repo_root) if s.kind not in ("null", "ilt_thunk")],
    )
    new_header, decls_changed = upsert_decls_block(new_header, cls, decls)

    cpp_text = (
        cpp_path.read_text(encoding="utf-8")
        if cpp_path.exists()
        else f'#include "game/{cls}.h"\n'
    )
    new_cpp, claimed = _merge_marker_stubs(cpp_text, cls, slots)

    sym_plan = plan_symbols(resolve_repo_path(repo_root, "config/symbols.csv"), slots, cls)
    own_plan = plan_ownership(
        resolve_repo_path(repo_root, "config/function_ownership.csv"),
        slots,
        f"src/game/{cls}.cpp",
    )
    if own_plan.collisions:
        print(f"vtable-autofix {cls}: refusing slot claim due to ownership collisions:")
        for collision in own_plan.collisions:
            print(f"  {collision}")
        return 1

    print(f"vtable-autofix {cls}: claim {len(slots)} slot(s)")
    if claimed:
        print("  marker stubs: " + ", ".join(f"0x{a:08x}" for a in claimed))
    print(f"  header {'changed' if (block_changed or decls_changed) else 'up to date'}")
    print(f"  cpp {'changed' if new_cpp != cpp_text else 'up to date'}")
    if sym_plan.new_rows or sym_plan.updated_rows:
        print(f"  symbols rows: +{len(sym_plan.new_rows)} ~{len(sym_plan.updated_rows)}")
    if own_plan.new_rows:
        print(f"  ownership rows: +{len(own_plan.new_rows)}")

    if not write:
        return 0
    if block_changed or decls_changed:
        hpath.write_text(new_header, encoding="utf-8")
    if new_cpp != cpp_text:
        cpp_path.parent.mkdir(parents=True, exist_ok=True)
        cpp_path.write_text(new_cpp, encoding="utf-8")
    if sym_plan.new_rows or sym_plan.updated_rows:
        sym_plan.path.write_text(sym_plan.merged_text())
    if own_plan.new_rows:
        own_plan.path.write_text(own_plan.merged_text())
    return 0


def plan_for_classes(repo_root: Path, report: VtableReport, classes: list[str]) -> list[FixPlan]:
    plans: list[FixPlan] = []
    seen: set[tuple[str, str, str]] = set()
    findings_by_class: dict[str, list[VtableFinding]] = {
        cls: [f for f in report.findings if f.class_name == cls] for cls in classes
    }

    for cls in classes:
        if (repo_root / "config" / "classes" / f"{cls}.yml").exists():
            claimable, collisions = _claimable_manifest_slots(repo_root, cls)
            if claimable:
                plans.append(
                    FixPlan(
                        cls,
                        "slot_promotion",
                        not collisions,
                        f"claim {len(claimable)} manifest-owned vtable slot(s) with marker stubs",
                        f"just vtable-autofix {cls} --write",
                        claimable,
                    )
                )
            elif collisions:
                plans.append(
                    FixPlan(
                        cls,
                        "manual_required",
                        False,
                        "manifest slot claim has ownership collisions",
                    )
                )

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
            plans.append(
                FixPlan(
                    cls,
                    "ilt_thunk",
                    True,
                    f"prune unreferenced ILT thunk rows; referenced rows remain reported ({len(ilt)} slot(s))",
                    "just prune-ilt-thunks",
                    tuple(f.orig for f in ilt),
                )
            )

        slot_kinds = _manifest_slot_kinds(repo_root, cls)
        inherited = []
        for f in class_findings:
            if f.slot_index is None:
                continue
            kind_base = slot_kinds.get(f.slot_index)
            if kind_base and kind_base[0] == "inherited" and kind_base[1]:
                inherited.append((f.slot_index, kind_base[1]))
        if inherited:
            slots = ", ".join(f"0x{idx:x}->{base}" for idx, base in sorted(set(inherited))[:6])
            plans.append(
                FixPlan(
                    cls,
                    "base_owned",
                    False,
                    f"mismatch is inherited; fix nearest owning base first ({slots})",
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


def apply_plans(repo_root: Path, plans: list[FixPlan], verify: bool, promote_bodies: bool) -> int:
    rc = 0
    slot_classes = sorted({p.class_name for p in plans if p.kind == "slot_promotion" and p.safe})
    if any(p.kind == "scalar_dtor" and p.safe for p in plans):
        rc = rc or _run_just(repo_root, "correct-scalar-dtors")
    if any(p.kind == "ilt_thunk" and p.safe for p in plans):
        rc = rc or _run_just(repo_root, "prune-ilt-thunks")
    for cls in slot_classes:
        if promote_bodies:
            rc = rc or _run_just(repo_root, "gen-class", cls, "--write")
        else:
            rc = rc or claim_vtable_slots(repo_root, cls, write=True)
    if rc != 0 or not verify:
        return rc
    for target in ("sync-ownership", "regen-stubs", "build", "detect"):
        rc = rc or _run_just(repo_root, target)
        if rc:
            return rc
    for cls in slot_classes:
        rc = rc or _run_just(repo_root, "vtable", cls)
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
        "--promote-bodies",
        action="store_true",
        help="Opt into gen-class body promotion for manifest slots. Default is marker-only.",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="After --write, run sync/build/detect/vtable/gates.",
    )
    parser.add_argument("--limit", type=int, default=0, help="Analyze at most N classes.")
    parser.add_argument("--vtable-log", type=Path, help="Use an existing `just vtable -n` log.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.class_filter and not args.all and not args.vtable_log:
        raise SystemExit("pass a class filter, --all, or --vtable-log")

    repo_root = repo_root_from_file(__file__)
    output = (
        args.vtable_log.read_text(encoding="utf-8", errors="ignore")
        if args.vtable_log
        else run_vtable(repo_root, None if args.all else args.class_filter)
    )
    report = parse_vtable_output(output)
    classes = report.classes
    if args.class_filter and args.class_filter not in classes:
        # reccmp filters by substring, so keep all matching sections when present.
        classes = [c for c in classes if args.class_filter.lower() in c.lower()]
    if args.limit:
        classes = classes[: args.limit]
    plans = plan_for_classes(repo_root, report, classes)
    print_plans(report, plans, args.write)
    if not args.write:
        return 0
    return apply_plans(repo_root, plans, args.verify, args.promote_bodies)


if __name__ == "__main__":
    raise SystemExit(main())
