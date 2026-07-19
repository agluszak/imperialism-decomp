#!/usr/bin/env python3
"""Vtable ABI audit: detect wrong method declarations even at 100% slot match.

`just vtable` proves slot->address assignment; it says nothing about whether the
C++ *signature* declared for each slot matches the binary's ABI. TMapMaker
demonstrated the failure mode: seven slot declarations had been copied from
unrelated TEventHandler/TView methods occupying the same slot ordinals, while
the vtable diff stayed 100% the whole time.

This audit compares, per concrete virtual slot:

  the CURRENT source declaration   (parsed from the `// FUNCTION:` marker's
                                    definition head — the repo's own pairing
                                    convention, Hard Rule 3)
  against BINARY GROUND TRUTH      (config/vtable_abi_evidence.json, extracted
                                    once from the immutable original binary by
                                    tools.ghidra.vtable_abi_evidence)

Strong evidence rules (from the TMapMaker post-mortem):
  - `RET n` purges exactly 4 bytes per callee-cleaned stack dword: a __thiscall
    member with k stack-arg dwords MUST show `RET 4k` (0 args -> plain RET).
  - k consistent caller pushes + `RET 4k` is conclusive for k explicit args.
  - callers testing AL is evidence of a byte-sized return; consuming full EAX
    is evidence against a `void` declaration.
  - a slot address matching the expected body says NOTHING about argument or
    return correctness.

Verdicts per slot: proven_conflict > strong_warning > strong_support >
provisional > unmodeled / synthetic / null / insufficient.

Reviewed exceptions live in config/vtable_signature_overrides.csv (address|
class|slot|prototype|evidence|confidence): a slot whose source declaration
matches its override prototype is accepted regardless of the automatic
verdict; a slot whose source has DRIFTED from its override is a conflict.

Modes:
  report (default)   human-readable ranked report for the named classes (or all)
  --json             machine-readable findings
  --gate             exit 1 on proven conflicts absent from the ratchet baseline
  --write-baseline   refresh config/baselines/vtable_abi_gate_baseline.csv
  --doc FILE         write the ranked markdown report
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

from tools.common.pipe_csv import read_pipe_rows
from tools.common.repo import repo_root_from_file

EVIDENCE_PATH = "config/vtable_abi_evidence.json"
OVERRIDES_PATH = "config/vtable_signature_overrides.csv"
BASELINE_PATH = "config/baselines/vtable_abi_gate_baseline.csv"

# ------------------------------------------------------------------------- #
# Declaration harvesting (source ground truth for the CURRENT C++ model)
# ------------------------------------------------------------------------- #

_MARKER_RE = re.compile(r"//\s*FUNCTION:\s*IMPERIALISM\s+0x([0-9a-fA-F]{6,8})")
_SYNTHETIC_RE = re.compile(r"//\s*SYNTHETIC:\s*IMPERIALISM\s+0x([0-9a-fA-F]{6,8})")


@dataclass
class Decl:
    """A parsed C++ definition head paired to an address by its marker."""

    addr: int
    file: str
    line: int
    ret: str | None  # None: ctor/dtor (no return type)
    cls: str | None  # None: free function
    name: str
    args: str
    conv: str  # "", "__cdecl", "__fastcall", "__stdcall", "__thiscall"
    origin: str  # "manual" | "generated"

    @property
    def is_member(self) -> bool:
        return self.cls is not None


_CONV_TOKENS = ("__cdecl", "__fastcall", "__stdcall", "__thiscall")


def parse_definition_head(head: str) -> tuple[str | None, str | None, str, str, str] | None:
    """(ret, cls, name, args, conv) from a joined definition head, or None.

    Handles `int TMapMaker::Foo(int a, int b)`, `char __cdecl Bar(void*)`,
    `TShip::TShip()`, `TMapMaker::~TMapMaker()` and multi-line heads (caller
    joins lines). Not a full C++ parser — unparseable heads return None and the
    slot is reported as unmodeled rather than guessed at.
    """
    head = " ".join(head.replace("\n", " ").split())
    # Find the argument list: first '(' balanced to its ')'.
    try:
        open_idx = head.index("(")
    except ValueError:
        return None
    depth = 0
    close_idx = -1
    for i in range(open_idx, len(head)):
        if head[i] == "(":
            depth += 1
        elif head[i] == ")":
            depth -= 1
            if depth == 0:
                close_idx = i
                break
    if close_idx < 0:
        return None
    args = head[open_idx + 1 : close_idx].strip()
    if args == "void":
        args = ""
    before = head[:open_idx].strip()

    conv = ""
    for tok in _CONV_TOKENS:
        if re.search(rf"\b{tok}\b", before):
            conv = tok
            before = re.sub(rf"\b{tok}\b", " ", before)
    before = " ".join(before.split())

    # Split off Class::Name (rightmost token may be qualified).
    m = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*::\s*(~?[A-Za-z_][A-Za-z0-9_]*)$", before)
    if m:
        cls, name = m.group(1), m.group(2)
        ret = before[: m.start()].strip() or None
        return (ret, cls, name, args, conv)
    m = re.search(r"(~?[A-Za-z_][A-Za-z0-9_]*)$", before)
    if not m:
        return None
    name = m.group(1)
    ret = before[: m.start()].strip() or None
    return (ret, None, name, args, conv)


def harvest_declarations(repo_root: Path) -> tuple[dict[int, Decl], set[int]]:
    """address -> Decl for every `// FUNCTION:` marker; plus SYNTHETIC addrs."""
    decls: dict[int, Decl] = {}
    synthetic: set[int] = set()
    roots = [repo_root / "src", repo_root / "include"]
    for root in roots:
        for path in sorted(root.rglob("*.cpp")) + sorted(root.rglob("*.h")):
            rel = str(path.relative_to(repo_root))
            origin = (
                "generated"
                if ("/autogen/" in rel or "/ghidra_autogen/" in rel or rel.startswith("src/autogen"))
                else "manual"
            )
            try:
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for i, line in enumerate(lines):
                sm = _SYNTHETIC_RE.search(line)
                if sm:
                    synthetic.add(int(sm.group(1), 16))
                    continue
                m = _MARKER_RE.search(line)
                if not m:
                    continue
                addr = int(m.group(1), 16)
                # Join following lines until '{' or ';' terminates the head.
                head_parts: list[str] = []
                for j in range(i + 1, min(i + 9, len(lines))):
                    text = lines[j]
                    if text.strip().startswith("//"):
                        continue
                    cut = len(text)
                    for stop in ("{", ";"):
                        k = text.find(stop)
                        if k >= 0:
                            cut = min(cut, k)
                    head_parts.append(text[:cut])
                    if cut < len(text):
                        break
                parsed = parse_definition_head(" ".join(head_parts))
                if parsed is None:
                    continue
                ret, cls, name, args, conv = parsed
                decls[addr] = Decl(
                    addr=addr, file=rel, line=i + 1, ret=ret, cls=cls, name=name,
                    args=args, conv=conv, origin=origin,
                )
    return decls, synthetic


# ------------------------------------------------------------------------- #
# Declared-prototype arithmetic
# ------------------------------------------------------------------------- #

_BYTE_TYPES = {"char", "bool", "signed char", "unsigned char", "undefined1", "byte"}
_FP_TYPES = {"float", "double", "float10"}
_TWO_DWORD = {"double", "__int64", "LONGLONG", "longlong", "ulonglong", "undefined8"}
_KNOWN_ONE_DWORD = {
    "int", "long", "short", "char", "bool", "float", "unsigned", "signed",
    "uint", "ushort", "uchar", "byte", "undefined", "undefined1", "undefined2",
    "undefined4", "size_t", "u32", "s32", "u16", "s16", "u8", "s8",
    "POSITION", "HWND", "HDC", "COLORREF", "UINT", "WPARAM", "LPARAM", "LRESULT",
    "BOOL", "DWORD", "WORD", "BYTE", "LONG", "NationSlot", "RgnHandle",
}


def strip_param_name(part: str) -> str:
    """Drop a trailing identifier (the parameter name) from one arg token."""
    part = part.strip()
    m = re.match(r"^(.*?)([A-Za-z_][A-Za-z0-9_]*)$", part)
    if m and m.group(1).strip() and not m.group(1).rstrip().endswith(("*", "&", "::")):
        # 'int foo' -> 'int'; but 'TZone*' (no name) stays; 'unsigned' alone stays.
        head = m.group(1).strip()
        if head.split()[-1] in ("const", "unsigned", "signed", "struct", "class"):
            return part
        return head
    return part


def arg_stack_dwords(args: str) -> int | None:
    """Stack dwords the declared argument list occupies; None when unknowable
    (varargs, by-value class types, inline function-pointer params)."""
    text = " ".join((args or "").split())
    if text in ("", "void"):
        return 0
    total = 0
    for raw in text.split(","):
        part = raw.strip()
        if part == "...":
            return None
        if "(" in part:
            return None
        base = strip_param_name(part)
        base = base.replace("const", "").replace("struct", "").replace("class", "").strip()
        if "*" in base or "&" in base:
            total += 1
            continue
        tokens = base.split()
        if not tokens:
            return None
        last = tokens[-1]
        if last in _TWO_DWORD:
            total += 2
            continue
        if last in _KNOWN_ONE_DWORD or (len(tokens) > 1 and tokens[0] in ("unsigned", "signed")):
            total += 1
            continue
        # Unknown bare identifier: enum -> 1 dword; by-value class -> unknowable.
        # Enums in this repo are rare and dword-sized; class-by-value would break
        # the count silently, so refuse to guess.
        return None
    return total


_RET_DWORD_TYPES = _KNOWN_ONE_DWORD | {"long", "int"}


def ret_width_class(ret: str | None) -> str:
    """'void'|'byte'|'word'|'dword'|'fp'|'sret'|'unknown' for a declared return.

    'sret': a by-value aggregate return (CPoint, RECT, CString, ...). MSVC
    passes these via a hidden return-slot pointer pushed as an extra stack
    argument, so a __thiscall member returning one purges 4 MORE bytes than its
    visible argument list implies.
    """
    if ret is None:
        return "unknown"  # ctor/dtor
    text = " ".join(ret.replace("const", "").split())
    if text == "void":
        return "void"
    if text in _FP_TYPES:
        return "fp"
    if "*" in text or "&" in text:
        return "dword"
    if text in _BYTE_TYPES:
        return "byte"
    if text in ("short", "unsigned short", "s16", "u16", "ushort", "undefined2", "WORD"):
        return "word"
    if text in ("undefined",):
        return "unknown"
    tokens = text.split()
    if tokens and tokens[-1] not in _RET_DWORD_TYPES and not (
        len(tokens) > 1 and tokens[0] in ("unsigned", "signed")
    ):
        # Unknown bare identifier: a by-value class/struct return (hidden sret
        # pointer). Enums would land here too — rare, and misclassifying an
        # enum as sret only relaxes the arity check by one optional dword.
        return "sret"
    return "dword"


# ------------------------------------------------------------------------- #
# Per-slot classification
# ------------------------------------------------------------------------- #

VERDICT_ORDER = [
    "proven_conflict",
    "strong_warning",
    "strong_support",
    "provisional",
    "insufficient",
]


@dataclass
class Finding:
    cls: str
    index: int
    byte_offset: int
    target: str
    verdict: str
    reasons: list[str] = field(default_factory=list)
    decl: Decl | None = None
    facts: dict | None = None
    overridden: bool = False


def _hist_total(hist: dict[str, int], keys: tuple[str, ...]) -> int:
    return sum(v for k, v in (hist or {}).items() if k in keys)


def _dominant(hist: dict[str, int]) -> tuple[str | None, int, int]:
    """(dominant key, its count, total) of a histogram."""
    total = sum((hist or {}).values())
    if not hist:
        return (None, 0, 0)
    key = max(hist, key=lambda k: hist[k])
    return (key, hist[key], total)


def classify_slot(decl: Decl | None, facts: dict | None, override_proto: str | None) -> Finding:
    """Core rule engine: one slot's declaration vs its binary evidence."""
    f = Finding(cls="", index=-1, byte_offset=-1, target="", verdict="provisional")
    f.decl = decl
    f.facts = facts

    if facts is None:
        f.verdict = "insufficient"
        f.reasons.append("no binary evidence for slot target")
        return f
    if decl is None:
        f.verdict = "provisional"
        f.reasons.append("no source declaration (unported/unmarked slot)")
        return f

    # Reviewed override: source matching the approved prototype is accepted.
    if override_proto is not None:
        if normalize_proto_text(render_decl_proto(decl)) == normalize_proto_text(override_proto):
            f.verdict = "strong_support"
            f.overridden = True
            f.reasons.append("matches reviewed override prototype")
            return f
        f.verdict = "proven_conflict"
        f.reasons.append(
            f"source declaration drifted from reviewed override: {override_proto!r}"
        )
        return f

    conflicts: list[str] = []
    warnings: list[str] = []
    supports: list[str] = []

    dwords = arg_stack_dwords(decl.args)
    ret_kind = facts.get("ret_kind")
    ret_imm = int(facts.get("ret_imm") or 0)
    callers = facts.get("callers") or {}
    ret_class = ret_width_class(decl.ret)
    # A by-value aggregate return adds a hidden sret-pointer stack arg.
    if dwords is not None and ret_class == "sret":
        dwords += 1

    # --- Rule 1: callee-cleaned stack bytes vs declared stack args ---------- #
    callee_cleaned_expected: int | None = None
    if decl.is_member and not decl.conv:  # implicit __thiscall member
        callee_cleaned_expected = None if dwords is None else 4 * dwords
    elif decl.conv in ("__stdcall",):
        callee_cleaned_expected = None if dwords is None else 4 * dwords
    elif decl.conv in ("__cdecl", "__fastcall") or (not decl.is_member and not decl.conv):
        callee_cleaned_expected = 0 if decl.conv == "__cdecl" else None

    if callee_cleaned_expected is not None and ret_kind in ("imm", "plain"):
        actual = ret_imm if ret_kind == "imm" else 0
        if actual != callee_cleaned_expected:
            conflicts.append(
                f"declared {dwords} stack dword(s) -> expected RET "
                f"{callee_cleaned_expected:#x}, binary shows "
                f"{'plain RET' if ret_kind == 'plain' else f'RET {actual:#x}'}"
            )
        else:
            supports.append(
                f"RET evidence matches ({'plain RET' if actual == 0 else f'RET {actual:#x}'}"
                f" == {dwords} stack dword(s))"
            )

    # --- Rule 2: consistent caller pushes vs declared arg count ------------- #
    push_key, push_n, push_total = _dominant(callers.get("push_counts") or {})
    if dwords is not None and push_total >= 2 and push_key is not None and push_n == push_total:
        pushed = int(push_key)
        if pushed != dwords:
            if ret_kind == "imm" and ret_imm == 4 * pushed:
                conflicts.append(
                    f"{push_total} caller site(s) all push {pushed} dword(s) and RET "
                    f"{ret_imm:#x} agrees — declaration has {dwords}"
                )
            else:
                warnings.append(
                    f"{push_total} caller site(s) all push {pushed} dword(s); "
                    f"declaration has {dwords} (push scan is advisory)"
                )
        else:
            supports.append(f"{push_total} caller site(s) push exactly {dwords} dword(s)")

    # --- Rule 3: declared void but return register consumed ----------------- #
    ret_use = callers.get("ret_use") or {}
    consumed = _hist_total(ret_use, ("al", "ax", "eax"))
    if ret_class == "void" and consumed >= 2:
        conflicts.append(
            f"declared void but {consumed} caller site(s) consume the return register "
            f"({ {k: v for k, v in ret_use.items() if k in ('al', 'ax', 'eax')} })"
        )
    if ret_class == "void" and _hist_total(ret_use, ("st0",)) >= 2:
        conflicts.append("declared void but callers consume an FP (ST0) return")

    # --- Rule 4: declared byte return but full EAX consumed ----------------- #
    if ret_class == "byte" and _hist_total(ret_use, ("eax",)) >= 2 and not _hist_total(
        ret_use, ("al", "ax")
    ):
        warnings.append(
            "declared byte-sized return but callers consume full EAX "
            "(pointer/int return more likely)"
        )

    # --- Rule 5: free-function declaration on a `this`-consuming body ------- #
    if not decl.is_member and decl.conv == "__cdecl" and facts.get("ecx") == "ecx_this":
        conflicts.append(
            "declared free __cdecl but the body reads ECX as `this` before writing it"
        )

    f.verdict = (
        "proven_conflict"
        if conflicts
        else "strong_warning"
        if warnings
        else "strong_support"
        if supports
        else "provisional"
    )
    f.reasons = conflicts + warnings + supports
    if f.verdict == "provisional" and not f.reasons:
        f.reasons.append("no decisive evidence available (tail-jmp body / no callers)")
    return f


def render_decl_proto(decl: Decl) -> str:
    owner = f"{decl.cls}::" if decl.cls else ""
    ret = f"{decl.ret} " if decl.ret else ""
    conv = f"{decl.conv} " if decl.conv else ""
    return f"{ret}{conv}{owner}{decl.name}({decl.args})"


def normalize_proto_text(text: str) -> str:
    text = " ".join((text or "").split())
    text = re.sub(r"\s*([(),*&])\s*", r"\1", text)
    return text


# ------------------------------------------------------------------------- #
# Whole-repo audit + ranking
# ------------------------------------------------------------------------- #

_FAKE_FASTCALL_RE = re.compile(r"__fastcall\s*[^;]{0,120}?(dummyEdx|/\*\s*edx\s*\*/)", re.IGNORECASE)
_RAW_VTBL_RE = re.compile(r"vftable\s*\[|->\s*vftable\s*\)|\bVCall_")


def scan_dispatch_smells(repo_root: Path) -> dict[str, dict[str, int]]:
    """file -> counts of fake-fastcall / raw-vtable dispatch patterns (advisory)."""
    out: dict[str, dict[str, int]] = {}
    for path in sorted((repo_root / "src" / "game").rglob("*.cpp")):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        fake = len(_FAKE_FASTCALL_RE.findall(text))
        raw = len(_RAW_VTBL_RE.findall(text))
        if fake or raw:
            out[str(path.relative_to(repo_root))] = {"fake_fastcall": fake, "raw_vtable": raw}
    return out


@dataclass
class ClassReport:
    name: str
    vtable_addr: str
    findings: list[Finding]

    def count(self, verdict: str) -> int:
        return sum(1 for f in self.findings if f.verdict == verdict)

    @property
    def unmodeled(self) -> int:
        return sum(
            1
            for f in self.findings
            if f.verdict == "provisional" and f.decl is None and f.facts is not None
        )

    @property
    def rank_score(self) -> tuple:
        return (
            -self.count("proven_conflict"),
            -self.count("strong_warning"),
            -self.unmodeled,
            self.name,
        )


def load_overrides(path: Path) -> dict[int, dict[str, str]]:
    if not path.exists():
        return {}
    out: dict[int, dict[str, str]] = {}
    for row in read_pipe_rows(path):
        addr_s = (row.get("address") or "").strip().lower().removeprefix("0x")
        if not addr_s:
            continue
        try:
            out[int(addr_s, 16)] = row
        except ValueError:
            continue
    return out


def load_baseline(path: Path) -> set[tuple[int, str]]:
    if not path.exists():
        return set()
    out: set[tuple[int, str]] = set()
    for row in read_pipe_rows(path):
        addr_s = (row.get("address") or "").strip().lower().removeprefix("0x")
        cls = (row.get("class") or "").strip()
        try:
            out.add((int(addr_s, 16), cls))
        except ValueError:
            continue
    return out


def audit_classes(
    evidence: dict,
    decls: dict[int, Decl],
    synthetic: set[int],
    overrides: dict[int, dict[str, str]],
    only: list[str] | None = None,
) -> list[ClassReport]:
    reports: list[ClassReport] = []
    for cls_name in sorted(evidence.get("classes", {})):
        if only and cls_name not in only:
            continue
        cls = evidence["classes"][cls_name]
        findings: list[Finding] = []
        for slot in cls.get("slots", []):
            if slot.get("null"):
                continue
            target = slot.get("target")
            if not target:
                continue
            addr = int(target, 16)
            if addr in synthetic:
                continue  # compiler-generated (scalar dtor etc.) — not hand-declared
            facts = evidence.get("functions", {}).get(target)
            override_row = overrides.get(addr)
            override_proto = (override_row or {}).get("prototype")
            finding = classify_slot(decls.get(addr), facts, override_proto)
            finding.cls = cls_name
            finding.index = slot.get("index", -1)
            finding.byte_offset = slot.get("byte_offset", -1)
            finding.target = target
            findings.append(finding)
        reports.append(
            ClassReport(name=cls_name, vtable_addr=cls.get("vtable_addr", "?"), findings=findings)
        )
    reports.sort(key=lambda r: r.rank_score)
    return reports


# ------------------------------------------------------------------------- #
# Rendering
# ------------------------------------------------------------------------- #


def render_report(
    reports: list[ClassReport],
    smells: dict[str, dict[str, int]],
    verbose: bool,
) -> str:
    lines: list[str] = []
    tot = {v: 0 for v in VERDICT_ORDER}
    for r in reports:
        for f in r.findings:
            tot[f.verdict] = tot.get(f.verdict, 0) + 1
    lines.append(
        "vtable ABI audit: "
        + ", ".join(f"{v}={tot.get(v, 0)}" for v in VERDICT_ORDER)
        + f" across {len(reports)} class(es)"
    )
    lines.append("")
    for r in reports:
        pc, sw = r.count("proven_conflict"), r.count("strong_warning")
        if not verbose and pc == 0 and sw == 0:
            continue
        lines.append(
            f"== {r.name} ({r.vtable_addr}): {pc} proven conflict(s), "
            f"{sw} strong warning(s), {r.count('strong_support')} supported, "
            f"{r.unmodeled} unmodeled slot(s)"
        )
        for f in r.findings:
            if f.verdict not in ("proven_conflict", "strong_warning") and not verbose:
                continue
            decl_txt = render_decl_proto(f.decl) if f.decl else "<no declaration>"
            lines.append(
                f"  [{f.verdict}] slot {f.index} / 0x{f.byte_offset:02x} -> {f.target}"
            )
            lines.append(f"      decl: {decl_txt}")
            if f.facts:
                lines.append(
                    "      binary: ret_kind={ret_kind} ret_imm={ret_imm:#x} ecx={ecx} "
                    "callers={sites}".format(
                        ret_kind=f.facts.get("ret_kind"),
                        ret_imm=int(f.facts.get("ret_imm") or 0),
                        ecx=f.facts.get("ecx"),
                        sites=(f.facts.get("callers") or {}).get("sites", 0),
                    )
                )
            for reason in f.reasons:
                lines.append(f"      - {reason}")
        lines.append("")
    if smells:
        lines.append("dispatch smells (fake-fastcall / raw-vtable casts; advisory):")
        for file, counts in sorted(smells.items()):
            lines.append(
                f"  {file}: fake_fastcall={counts['fake_fastcall']} "
                f"raw_vtable={counts['raw_vtable']}"
            )
    return "\n".join(lines)


def render_doc(reports: list[ClassReport], smells: dict[str, dict[str, int]]) -> str:
    lines = [
        "# Vtable ABI audit (ranked)",
        "",
        "Generated by `just vtable-abi-audit --doc`. Slot-to-address matching",
        "(`just vtable`) can be 100% while C++ signatures are wrong; this report",
        "ranks classes by *proven* ABI contradictions between their current",
        "declarations and the binary's immutable calling-convention evidence",
        "(config/vtable_abi_evidence.json). Names alone are never treated as",
        "errors — `Orphan*`/`VTableSlot*`/`undefined` are investigation",
        "indicators, not proof.",
        "",
        "| rank | class | proven conflicts | strong warnings | unmodeled slots | supported |",
        "|---|---|---|---|---|---|",
    ]
    rank = 0
    for r in reports:
        pc, sw = r.count("proven_conflict"), r.count("strong_warning")
        if pc == 0 and sw == 0 and r.unmodeled == 0:
            continue
        rank += 1
        lines.append(
            f"| {rank} | {r.name} | {pc} | {sw} | {r.unmodeled} | "
            f"{r.count('strong_support')} |"
        )
    lines.append("")
    lines.append("## Proven conflicts")
    lines.append("")
    for r in reports:
        conflicts = [f for f in r.findings if f.verdict == "proven_conflict"]
        if not conflicts:
            continue
        lines.append(f"### {r.name} ({r.vtable_addr})")
        for f in conflicts:
            decl_txt = render_decl_proto(f.decl) if f.decl else "<no declaration>"
            lines.append(f"- slot {f.index} / 0x{f.byte_offset:02x} -> {f.target}: `{decl_txt}`")
            for reason in f.reasons:
                lines.append(f"  - {reason}")
        lines.append("")
    if smells:
        lines.append("## Dispatch smells (advisory)")
        lines.append("")
        for file, counts in sorted(smells.items()):
            lines.append(
                f"- {file}: fake_fastcall={counts['fake_fastcall']} "
                f"raw_vtable={counts['raw_vtable']}"
            )
    return "\n".join(lines) + "\n"


# ------------------------------------------------------------------------- #
# CLI
# ------------------------------------------------------------------------- #


def main() -> int:
    repo_root = repo_root_from_file(__file__)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("classes", nargs="*", help="class names to audit (default: all)")
    parser.add_argument("--evidence", default=EVIDENCE_PATH)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--gate", action="store_true",
                        help="exit 1 on proven conflicts not in the ratchet baseline")
    parser.add_argument("--write-baseline", action="store_true")
    parser.add_argument("--doc", default="", help="write the ranked markdown report here")
    args = parser.parse_args()

    evidence_path = repo_root / args.evidence
    if not evidence_path.exists():
        print(
            f"evidence snapshot missing: {args.evidence} — run `just vtable-abi-extract` "
            "first (needs Ghidra). Gate treats missing evidence as pass (source-only CI)."
        )
        return 0
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    decls, synthetic = harvest_declarations(repo_root)
    overrides = load_overrides(repo_root / OVERRIDES_PATH)
    reports = audit_classes(evidence, decls, synthetic, overrides, args.classes or None)
    smells = scan_dispatch_smells(repo_root)

    if args.json:
        doc = [
            {
                "class": r.name,
                "vtable": r.vtable_addr,
                "findings": [
                    {
                        "slot": f.index,
                        "byte_offset": f.byte_offset,
                        "target": f.target,
                        "verdict": f.verdict,
                        "decl": render_decl_proto(f.decl) if f.decl else None,
                        "decl_file": f.decl.file if f.decl else None,
                        "reasons": f.reasons,
                    }
                    for f in r.findings
                ],
            }
            for r in reports
        ]
        json.dump(doc, sys.stdout, indent=1)
        sys.stdout.write("\n")
    else:
        print(render_report(reports, smells, args.verbose))

    if args.doc:
        (repo_root / args.doc).write_text(render_doc(reports, smells), encoding="utf-8")
        print(f"wrote {args.doc}")

    conflicts = [
        (int(f.target, 16), r.name, f)
        for r in reports
        for f in r.findings
        if f.verdict == "proven_conflict"
    ]

    baseline_path = repo_root / BASELINE_PATH
    if args.write_baseline:
        rows = ["address|class|slot|summary"]
        for addr, cls, f in sorted(conflicts):
            summary = (f.reasons[0] if f.reasons else "").replace("|", "/")
            rows.append(f"0x{addr:08x}|{cls}|0x{f.byte_offset:02x}|{summary}")
        baseline_path.write_text("\n".join(rows) + "\n", encoding="utf-8")
        print(f"wrote baseline: {BASELINE_PATH} ({len(conflicts)} conflict(s))")
        return 0

    if args.gate:
        baseline = load_baseline(baseline_path)
        new = [(a, c, f) for a, c, f in conflicts if (a, c) not in baseline]
        if new:
            print(
                f"\nvtable-abi-gate: {len(new)} NEW proven conflict(s) not in "
                f"{BASELINE_PATH}:"
            )
            for addr, cls, f in new:
                print(f"  {cls} slot 0x{f.byte_offset:02x} -> 0x{addr:08x}: {f.reasons[:1]}")
            print(
                "Fix the declaration (or add a reviewed row to "
                f"{OVERRIDES_PATH}; never silence real evidence)."
            )
            return 1
        print(
            f"vtable-abi-gate: OK ({len(conflicts)} baseline conflict(s) tracked, 0 new)"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
