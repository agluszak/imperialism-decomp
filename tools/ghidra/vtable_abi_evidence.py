#!/usr/bin/env python3
"""Read-only pyghidra extractor: per-slot vtable ABI evidence as JSON.

The evidence half of the vtable ABI audit (`just vtable-abi-audit`). For each
class vtable it walks the slots, resolves ILT thunks to real bodies, and
records *binary ground truth* about every slot target:

  callee side  — RET kind/immediate (callee-cleaned stack bytes), whether ECX
                 is read as `this` before being overwritten, best-effort
                 max stack-argument byte read, size, Ghidra name/cc/prototype
                 (the latter three are advisory hypotheses, never ground truth);
  caller side  — direct call sites (including sites that call through an ILT
                 thunk): explicit PUSH count in the arg-setup region, what set
                 ECX last, caller stack cleanup after the call (ADD ESP / POP
                 ECX idioms), and how the return register is consumed
                 (AL / AX / EAX / ST0 / none).

Raw listing instructions are the ground truth; Ghidra's decompiler-recovered
signatures are recorded as advisory only. The original binary is immutable, so
this evidence never changes once extracted — the committed snapshot
(config/vtable_abi_evidence.json) lets the pure-python audit + gate
(tools.workflow.vtable_abi_audit) run without Ghidra.

Usage (via the query daemon or one-shot):
  uv run python -m tools.ghidra.query vtable-abi-evidence Class=0xVTABLE[:COUNT] ...
  uv run python -m tools.ghidra.query vtable-abi-evidence --from-source [--out FILE]

--from-source discovers every `// VTABLE: IMPERIALISM 0xADDR` annotation in
include/ + src/ and audits all of them (slow: whole-repo extraction).
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from tools.workflow.vtable_extent_rules import extent_decision

MAX_SLOTS = 512
MAX_CALLER_SITES = 12
MAX_BACKWARD_INSNS = 32
MAX_FORWARD_INSNS = 8
MAX_BODY_SCAN_INSNS = 400

_VTABLE_ANNOT_RE = re.compile(r"//\s*VTABLE:\s*IMPERIALISM\s+(0x[0-9a-fA-F]+)")
_CLASS_LINE_RE = re.compile(r"^\s*(?:class|struct)\s+([A-Za-z_][A-Za-z0-9_]*)")

_JCC = (
    "ja", "jae", "jb", "jbe", "jc", "je", "jg", "jge", "jl", "jle", "jmp",
    "jna", "jnae", "jnb", "jnbe", "jnc", "jne", "jng", "jnge", "jnl", "jnle",
    "jno", "jnp", "jns", "jnz", "jo", "jp", "jpe", "jpo", "js", "jz",
)


def discover_annotated_classes(repo_root: Path) -> list[tuple[str, int]]:
    """(class_name, vtable_addr) for every `// VTABLE:` annotation in the tree."""
    out: list[tuple[str, int]] = []
    seen: set[int] = set()
    for base in ("include", "src"):
        for path in sorted((repo_root / base).rglob("*.h")) + sorted(
            (repo_root / base).rglob("*.cpp")
        ):
            try:
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for i, line in enumerate(lines):
                m = _VTABLE_ANNOT_RE.search(line)
                if not m:
                    continue
                addr = int(m.group(1), 16)
                if addr in seen:
                    continue
                for j in range(i + 1, min(i + 4, len(lines))):
                    cm = _CLASS_LINE_RE.match(lines[j])
                    if cm:
                        out.append((cm.group(1), addr))
                        seen.add(addr)
                        break
    return out


def parse_spec(spec: str) -> tuple[str, int, int | None]:
    name, _, rhs = spec.partition("=")
    addr_s, _, count_s = rhs.partition(":")
    return name, int(addr_s, 16), (int(count_s, 0) if count_s else None)


class Extractor:
    def __init__(self, program):
        self.program = program
        self.af = program.getAddressFactory().getDefaultAddressSpace()
        self.fm = program.getFunctionManager()
        self.listing = program.getListing()
        self.mem = program.getMemory()
        self.refmgr = program.getReferenceManager()

    # ------------------------------------------------------------------ #
    # Thunk resolution (same contract as vtable_slots.resolve)
    # ------------------------------------------------------------------ #

    def resolve(self, entry: int) -> int:
        target = entry
        for _ in range(8):
            addr = self.af.getAddress(target)
            fn = self.fm.getFunctionContaining(addr)
            if fn is not None and fn.isThunk():
                tf = fn.getThunkedFunction(True)
                if tf is not None:
                    nxt = int(tf.getEntryPoint().getOffset())
                    if nxt == target:
                        break
                    target = nxt
                    continue
            if fn is not None and int(fn.getEntryPoint().getOffset()) == target:
                break
            ins = self.listing.getInstructionAt(addr)
            if ins is None:
                break
            if ins.getMnemonicString().lower() == "jmp" and len(ins.getFlows()) == 1:
                target = int(ins.getFlows()[0].getOffset())
            else:
                break
        return target

    # ------------------------------------------------------------------ #
    # Callee-side facts
    # ------------------------------------------------------------------ #

    def ret_facts(self, fn) -> tuple[str, int]:
        """('imm'|'plain'|'none', imm_bytes). 'none' = tail-jmp body (no RET)."""
        best = -1
        saw_plain = False
        it = self.listing.getInstructions(fn.getBody(), True)
        while it.hasNext():
            ins = it.next()
            if not ins.getMnemonicString().upper().startswith("RET"):
                continue
            imm = 0
            for i in range(ins.getNumOperands()):
                for obj in ins.getOpObjects(i):
                    try:
                        imm = max(imm, int(obj.getValue()))
                    except AttributeError:
                        continue
            if imm > 0:
                best = max(best, imm)
            else:
                saw_plain = True
        if best >= 0:
            return ("imm", best)
        if saw_plain:
            return ("plain", 0)
        return ("none", 0)

    def ecx_verdict(self, fn) -> str:
        """'ecx_this' | 'no_ecx' | 'empty' (same rules as scan_cdecl_thiscall)."""
        it = self.listing.getInstructions(fn.getBody(), True)
        seen = 0
        while it.hasNext() and seen < 10:
            ins = it.next()
            seen += 1
            inputs = {str(o) for o in ins.getInputObjects()}
            results = {str(o) for o in ins.getResultObjects()}
            mn = ins.getMnemonicString().lower()
            # `push ecx` at entry is the MSVC "reserve one local" idiom, not a read.
            if mn == "push" and "ECX" in str(ins):
                continue
            if any("ECX" in s for s in inputs):
                return "ecx_this"
            if any(s == "ECX" for s in results):
                return "no_ecx"
            if mn in ("call", "ret", "retn"):
                return "no_ecx"
        return "no_ecx" if seen else "empty"

    _ESP_DISP_RE = re.compile(r"\[ESP(?:\s*\+\s*0x([0-9a-fA-F]+))?\]")
    _EBP_DISP_RE = re.compile(r"\[EBP\s*\+\s*0x([0-9a-fA-F]+)\]")

    def max_stack_arg_read(self, fn) -> int | None:
        """Best-effort max argument byte offset read (advisory: linear scan,
        flow-insensitive ESP tracking; None when nothing arg-like was seen)."""
        depth = 0
        ebp_frame = False
        best: int | None = None
        it = self.listing.getInstructions(fn.getBody(), True)
        count = 0
        prev = None
        while it.hasNext() and count < MAX_BODY_SCAN_INSNS:
            ins = it.next()
            count += 1
            text = str(ins)
            mn = ins.getMnemonicString().lower()
            if mn == "push":
                depth += 4
            elif mn == "pop":
                depth = max(0, depth - 4)
            elif mn == "sub" and text.upper().startswith("SUB ESP,"):
                try:
                    depth += int(text.split(",")[1], 16)
                except ValueError:
                    pass
            elif mn == "add" and text.upper().startswith("ADD ESP,"):
                try:
                    depth = max(0, depth - int(text.split(",")[1], 16))
                except ValueError:
                    pass
            if mn == "mov" and text.upper().replace(" ", "").startswith("MOVEBP,ESP"):
                if prev is not None and prev.upper().startswith("PUSH EBP"):
                    ebp_frame = True
            for m in self._ESP_DISP_RE.finditer(text.upper()):
                disp = int(m.group(1), 16) if m.group(1) else 0
                arg_byte = disp - depth - 4  # [esp+depth] is the return address
                if arg_byte >= 0:
                    best = max(best or 0, arg_byte)
            if ebp_frame:
                for m in self._EBP_DISP_RE.finditer(text.upper()):
                    disp = int(m.group(1), 16)
                    if disp >= 8:
                        best = max(best or 0, disp - 8)
            prev = text
        return best

    # ------------------------------------------------------------------ #
    # Caller-side facts
    # ------------------------------------------------------------------ #

    def _call_sites(self, body_entry: int) -> list[int]:
        """Direct CALL sites to the body, including calls through ILT thunks."""
        sites: list[int] = []

        def collect(addr_int: int) -> list[int]:
            got: list[int] = []
            thunks: list[int] = []
            for ref in self.refmgr.getReferencesTo(self.af.getAddress(addr_int)):
                from_addr = ref.getFromAddress()
                ins = self.listing.getInstructionAt(from_addr)
                if ins is None:
                    continue
                mn = ins.getMnemonicString().lower()
                if mn == "call":
                    got.append(int(from_addr.getOffset()))
                elif mn == "jmp":
                    # ILT (or other) jmp thunk: its own callers call *this* body.
                    thunks.append(int(from_addr.getOffset()))
            for t in thunks:
                for ref in self.refmgr.getReferencesTo(self.af.getAddress(t)):
                    ins = self.listing.getInstructionAt(ref.getFromAddress())
                    if ins is not None and ins.getMnemonicString().lower() == "call":
                        got.append(int(ref.getFromAddress().getOffset()))
            return got

        sites = collect(body_entry)
        # de-dup, stable order
        seen: set[int] = set()
        out = []
        for s in sites:
            if s not in seen:
                seen.add(s)
                out.append(s)
        return out

    def _analyze_site(self, site: int) -> dict:
        rec: dict = {"site": f"0x{site:08x}"}
        # --- backward: arg-setup pushes + last ECX write -------------------- #
        pushes = 0
        ecx_source = "none"
        addr = self.af.getAddress(site)
        ins = self.listing.getInstructionAt(addr)
        walked = 0
        cur = ins
        while cur is not None and walked < MAX_BACKWARD_INSNS:
            cur = self.listing.getInstructionBefore(cur.getAddress())
            if cur is None:
                break
            walked += 1
            mn = cur.getMnemonicString().lower()
            text = str(cur).upper()
            if mn == "call" or mn.startswith("ret") or mn in _JCC:
                break
            if mn == "push":
                pushes += 1
                continue
            if ecx_source == "none" and ("ECX," in text.replace(" ", "")):
                head = text.replace(" ", "")
                if head.startswith("MOVECX,DWORDPTR[0X"):
                    ecx_source = "global"
                elif head.startswith("MOVECX,DWORDPTR["):
                    ecx_source = "field"
                elif head.startswith("MOVECX,E") or head.startswith("MOVECX,["):
                    ecx_source = "reg"
                elif head.startswith("LEAECX,"):
                    ecx_source = "stack"
                else:
                    ecx_source = "other"
        rec["pushes"] = pushes
        rec["ecx_source"] = ecx_source
        # --- forward: cleanup + return-register consumption ----------------- #
        cleanup = 0
        ret_use = "none"
        cur = ins
        steps = 0
        first = True
        while cur is not None and steps < MAX_FORWARD_INSNS:
            cur = cur.getNext()
            if cur is None:
                break
            steps += 1
            mn = cur.getMnemonicString().lower()
            text = str(cur).upper().replace(" ", "")
            if first and mn == "add" and text.startswith("ADDESP,"):
                try:
                    cleanup = int(text.split(",")[1], 16)
                except ValueError:
                    pass
                first = False
                continue
            if first and mn == "pop" and text in ("POPECX", "POPEDX"):
                cleanup += 4
                continue  # consecutive pop-cleanup idiom; stay in "first" mode
            first = False
            inputs = {str(o) for o in cur.getInputObjects()}
            results = {str(o) for o in cur.getResultObjects()}
            if mn.startswith("f") and ret_use == "none":
                ret_use = "st0"
                break
            if any(s == "AL" for s in inputs):
                ret_use = "al"
                break
            if any(s == "AX" for s in inputs):
                ret_use = "ax"
                break
            if any(s == "EAX" for s in inputs):
                ret_use = "eax"
                break
            if any(s in ("EAX", "AX", "AL") for s in results):
                break  # overwritten before use
            if mn == "call" or mn in _JCC or mn.startswith("ret"):
                break
        rec["cleanup"] = cleanup
        rec["ret_use"] = ret_use
        return rec

    def caller_facts(self, body_entry: int) -> dict:
        sites = self._call_sites(body_entry)
        out: dict = {"sites": len(sites)}
        push_counts: dict[str, int] = {}
        cleanup_bytes: dict[str, int] = {}
        ret_use: dict[str, int] = {}
        ecx_sources: dict[str, int] = {}
        examples: list[str] = []
        for s in sites[:MAX_CALLER_SITES]:
            rec = self._analyze_site(s)
            push_counts[str(rec["pushes"])] = push_counts.get(str(rec["pushes"]), 0) + 1
            cleanup_bytes[str(rec["cleanup"])] = cleanup_bytes.get(str(rec["cleanup"]), 0) + 1
            ret_use[rec["ret_use"]] = ret_use.get(rec["ret_use"], 0) + 1
            ecx_sources[rec["ecx_source"]] = ecx_sources.get(rec["ecx_source"], 0) + 1
            examples.append(rec["site"])
        out["analyzed"] = min(len(sites), MAX_CALLER_SITES)
        out["push_counts"] = push_counts
        out["cleanup_bytes"] = cleanup_bytes
        out["ret_use"] = ret_use
        out["ecx_sources"] = ecx_sources
        out["examples"] = examples[:6]
        return out

    # ------------------------------------------------------------------ #
    # Per-class walk
    # ------------------------------------------------------------------ #

    def class_slots(self, name: str, vtable: int, count: int | None) -> dict:
        slots: list[dict] = []
        limit = count if count is not None else MAX_SLOTS
        null_run_seen = False
        for i in range(limit):
            try:
                entry = self.mem.getInt(self.af.getAddress(vtable + 4 * i)) & 0xFFFFFFFF
            except Exception:
                break
            if entry == 0:
                rec = {"index": i, "byte_offset": i * 4, "null": True}
                resolved_name = None
                is_null = True
            else:
                target = self.resolve(entry)
                fn = self.fm.getFunctionContaining(self.af.getAddress(target))
                resolved_name = fn.getName() if fn is not None else None
                is_null = False
                rec = {
                    "index": i,
                    "byte_offset": i * 4,
                    "null": False,
                    "entry": f"0x{entry:08x}",
                    "target": f"0x{target:08x}",
                    "unresolved_thunk": bool(fn is not None and fn.isThunk()),
                }
            if count is None:
                decision = extent_decision(i, is_null, resolved_name, null_run_seen)
                if decision.stop:
                    print(
                        f"[vtable-abi-evidence] {name}: auto-extent stopped at slot "
                        f"0x{i * 4:02x} ({decision.reason}); pass :COUNT to override.",
                        file=sys.stderr,
                    )
                    break
            null_run_seen = null_run_seen or is_null
            slots.append(rec)
        return {"vtable_addr": f"0x{vtable:08x}", "slots": slots}

    def function_facts(self, target: int) -> dict | None:
        fn = self.fm.getFunctionContaining(self.af.getAddress(target))
        if fn is None:
            return None
        ret_kind, ret_imm = self.ret_facts(fn)
        return {
            "name": fn.getName(),
            "size": int(fn.getBody().getNumAddresses()),
            "cc": fn.getCallingConventionName(),
            "ghidra_params": int(fn.getParameterCount()),
            "ghidra_proto": fn.getSignature(True).getPrototypeString(),
            "ret_kind": ret_kind,
            "ret_imm": ret_imm,
            "ecx": self.ecx_verdict(fn),
            "max_stack_arg_read": self.max_stack_arg_read(fn),
            "callers": self.caller_facts(int(fn.getEntryPoint().getOffset())),
        }


def run(program, argv: list[str]) -> int:
    out_path: str | None = None
    from_source = False
    specs: list[str] = []
    it = iter(argv)
    for a in it:
        if a == "--out":
            out_path = next(it, None)
        elif a == "--from-source":
            from_source = True
        elif a.startswith("-"):
            print(f"unknown flag {a}", file=sys.stderr)
            return 2
        else:
            specs.append(a)

    targets: list[tuple[str, int, int | None]] = [parse_spec(s) for s in specs]
    if from_source:
        from tools.common.repo import repo_root_from_file

        repo_root = repo_root_from_file(__file__)
        have = {addr for _, addr, _ in targets}
        for name, addr in discover_annotated_classes(repo_root):
            if addr not in have:
                targets.append((name, addr, None))
    if not targets:
        print(
            "usage: vtable-abi-evidence [--from-source] [--out FILE] "
            "Class=0xVTABLE[:COUNT] ...",
            file=sys.stderr,
        )
        return 2

    ex = Extractor(program)
    classes: dict = {}
    functions: dict = {}
    for name, vtable, count in targets:
        cls = ex.class_slots(name, vtable, count)
        classes[name] = cls
        for slot in cls["slots"]:
            if slot.get("null") or slot.get("unresolved_thunk"):
                continue
            tgt = slot["target"]
            if tgt in functions:
                continue
            facts = ex.function_facts(int(tgt, 16))
            if facts is not None:
                functions[tgt] = facts
        print(f"[vtable-abi-evidence] {name}: {len(cls['slots'])} slots", file=sys.stderr)

    doc = {
        "comment": "Immutable per-address ABI evidence extracted from the original "
        "binary's raw listing by tools.ghidra.vtable_abi_evidence. Regenerate with "
        "`just vtable-abi-extract`.",
        "classes": classes,
        "functions": functions,
    }
    text = json.dumps(doc, indent=1, sort_keys=True)
    if out_path:
        Path(out_path).write_text(text + "\n", encoding="utf-8")
        print(f"[vtable-abi-evidence] wrote {out_path}", file=sys.stderr)
    else:
        sys.stdout.write(text + "\n")
    return 0


def main() -> int:
    from tools.common import ghidra_env

    project = ghidra_env.open_project()
    consumer = None
    program = None
    try:
        consumer, program = ghidra_env.open_program(project)
        return run(program, sys.argv[1:])
    finally:
        if program is not None:
            program.release(consumer)
        project.close()


if __name__ == "__main__":
    raise SystemExit(main())
