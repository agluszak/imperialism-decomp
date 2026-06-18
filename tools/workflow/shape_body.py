#!/usr/bin/env python3
"""Shape a raw Ghidra autogen block into a promote-ready ``// FUNCTION:`` block.

Body promotion (``emit_class_slots``) used to copy the Ghidra decompile verbatim,
keeping the wrong signature (explicit ``this``, ``__thiscall``, the Ghidra name) and
unresolved thunk-call names. This module applies the *safe* slice of the manual
decomp-loop shape pass — the rewrites that are provably correct without judgement:

  1. Canonical signature from the recovered slot's declared method
     (``ClassifiedSlot.sig`` → ``definition_head``): real name (matching the virtual
     declaration / parent override), no explicit ``this``, no ``__thiscall``/``__cdecl``.
  2. Lift Ghidra's unbound ``in_stack_0000000N`` thiscall stack args onto the
     declared parameter names when the counts line up.
  3. Resolve jmp-thunk / alias call names in the body to the real symbol.

It deliberately does NOT rewrite vtable dispatch into virtual calls, strip MSVC
EH-frame scaffolding, or clean ``unaff_`` register artifacts — those are the
judgement-bearing parts of the decomp loop and faking them risks rule-violating
source. Instead it detects them and prepends a ``// TODO(shape):`` checklist so the
human porter sees exactly what remains. The raw (thunk-resolved) body is kept as the
porting starting point, so a freshly promoted body may not compile until shaped.
"""

from __future__ import annotations

import re

from tools.common.thunk_names import ThunkResolver
from tools.workflow import class_codegen as bc

# Body constructs that must stay a manual decision, mapped to a short label for the
# TODO(shape) checklist. Order matters (most specific first for EH frame).
_HAZARDS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"unaff_FS_OFFSET"), "FS_OFFSET EH frame (model as RAII/real EH)"),
    (re.compile(r"\bvftable\b|->vftable|\.vftable"), "raw vtable dispatch (use a real virtual call)"),
    (re.compile(r"\bunaff_[A-Za-z0-9_]+"), "unaff_ register read (recover the real source)"),
    (re.compile(r"\bextraout_[A-Za-z0-9_]+"), "extraout_ register (recover the real value)"),
    (re.compile(r"\bin_(?:E|R)[A-Z]{2}\b"), "uninitialized register read"),
    (re.compile(r"&?\bLAB_[0-9a-fA-F]{6,}"), "code-label ref (switch/EH artifact)"),
]

_IN_STACK = re.compile(r"\bin_stack_([0-9a-fA-F]{8})\b")


def _split_preamble(block: str) -> str:
    """Drop the leading ``// GHIDRA_*`` comment lines and blank lines."""
    lines = block.splitlines()
    i = 0
    while i < len(lines) and (
        lines[i].strip() == "" or lines[i].lstrip().startswith("// GHIDRA_")
    ):
        i += 1
    return "\n".join(lines[i:])


def _param_names(args: str) -> list[str]:
    """Extract parameter names from a signature arg string (best-effort, flat)."""
    args = args.strip()
    if not args or args == "void":
        return []
    names: list[str] = []
    for part in args.split(","):
        idents = re.findall(r"[A-Za-z_]\w*", part)
        if idents:
            names.append(idents[-1])
    return names


def _lift_in_stack(body: str, sig: bc.Signature) -> tuple[str, bool]:
    """Lift ``in_stack_*`` onto declared param names. Returns (body, lifted_all).

    Ghidra models each unbound thiscall stack arg as a local variable: a bare
    ``<type> in_stack_NNNN;`` declaration plus uses. Promoting it to a real
    parameter means dropping that local declaration and renaming the uses, so we
    don't end up with a parameter shadowed by a same-named local.
    """
    found = sorted(set(_IN_STACK.findall(body)), key=lambda h: int(h, 16))
    if not found:
        return body, True
    params = _param_names(sig.args)
    if len(params) != len(found):
        return body, False  # ambiguous — leave for the human, flag instead
    for h in found:
        decl_re = re.compile(
            rf"^[ \t]*[A-Za-z_][\w \t\*]*\bin_stack_{h}\b[ \t]*;[ \t]*\n", re.MULTILINE
        )
        body = decl_re.sub("", body, count=1)
    mapping = {f"in_stack_{h}": params[i] for i, h in enumerate(found)}
    return _IN_STACK.sub(lambda m: mapping[m.group(0)], body), True


def _detect_hazards(body: str, lifted_all: bool) -> list[str]:
    flags: list[str] = []
    for pattern, label in _HAZARDS:
        if pattern.search(body):
            flags.append(label)
    if not lifted_all:
        flags.append("hidden stack params (in_stack_*) — couldn't map to declared args")
    return flags


def shape_body(
    block: str,
    slot: bc.ClassifiedSlot,
    cls: str,
    resolver: ThunkResolver | None = None,
) -> str:
    """Return a shaped ``// FUNCTION:`` block for ``slot`` from its autogen ``block``.

    Falls back to a bare marker rewrite when the slot has no recovered signature.
    """
    addr = int(slot.target_addr or "0", 16)
    marker = f"// FUNCTION: IMPERIALISM 0x{addr:08x}"

    if slot.sig is None:
        # No recovered signature — keep the raw body under a corrected marker.
        from tools.workflow.emit_class_slots import autogen_to_manual_block

        return autogen_to_manual_block(block, addr)

    code = _split_preamble(block)
    brace = code.find("{")
    if brace == -1:
        # No body to shape (e.g. a forward decl); emit the canonical declaration.
        return f"{marker}\n{slot.sig.definition_head(cls)} {{}}\n"

    body = code[brace:]
    if resolver is not None:
        body = resolver.resolve(body)
    body, lifted_all = _lift_in_stack(body, slot.sig)
    flags = _detect_hazards(body, lifted_all)

    out = [marker]
    if flags:
        out.append("// TODO(shape): " + "; ".join(flags))
    out.append(f"{slot.sig.definition_head(cls)} {body.rstrip()}")
    return "\n".join(out) + "\n"
