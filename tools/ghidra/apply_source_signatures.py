#!/usr/bin/env python3
"""Project source-model signatures into Ghidra (the MSVC500 PDB can't — see PR #91).

`cvdump -t` extracts ZERO type records from the MSVC500 recomp PDB, so
reccmp-ghidra-import can transfer names/return types but never parameter lists.
The authoritative signature source is therefore the source model
(`tools.source_model`, which parses the C++ declaration head into a prototype).

This tool projects those prototypes onto source-owned functions that still carry
unbound `in_stack_*` reads, and — crucially — VERIFIES each by re-decompile.
Verification is the classifier; every function ends in exactly one bucket:

  - **converged** — the re-decompile has NO in_stack left. Kept.
  - **params_bound_residual** — every originally-flagged offset is now bound (the
    parameters are correct) but a residual in_stack remains at a *different* offset
    (a sub-dword read inside a bound param slot, or a spurious local). The correct
    binding is KEPT (reverting it would restore a weaker signature) and the residual
    is logged, so the queue still accounts for the function.
  - **dynamic_storage_insufficient** — an originally-flagged offset is still unbound
    (packed sub-dword args, sret, wrong boundary). Reverted to the exact prior
    signature and queued: a signature that didn't help is worse than an honest
    classification.
  - **sret / unknown_cc / unresolved / unparsable** — queued before any edit.

  - **missing_function / decompile_failed / unparsable / sret / unresolved** —
    queued before or instead of an edit; the first three are distinct states, not
    conflated (a `None` decompile ≠ an empty in_stack set ≠ a missing DB function).

A guessed signature is never left in place. Each projection runs in its OWN Ghidra
transaction: accept → commit, reject → **rollback** (the exact-restore mechanism —
no hand-rebuilt signature, so a "reverted" function is byte-for-byte its prior
self, and a partial/errored edit cannot leak). `--strict` fails only on the
"could-not-verify / errored" reasons (`_HARD_FAIL_REASONS`).

CAVEAT — in_stack clearing is NECESSARY, not SUFFICIENT. That a projection made
the flagged offsets disappear proves the frame changed to bind them; it does NOT
prove the convention, member/static classification, parameter count/types, or
return are semantically correct — a wrong signature can bind the same offsets by
laying out a different frame. In particular the entity-kind (=> convention)
classification is punctuation-based and cannot see `static`/namespace facts absent
from the out-of-class definition head (see parse_prototype). A structural,
compiler-backed convergence check (source vs DB logical signature + ABI storage)
is the follow-up; today `in_stack` is a projection trigger + a weak verifier.

  just apply-source-signatures            # dry-run: report what would change
  just apply-source-signatures --apply    # project + verify (per-function tx)
  just source-signature-audit --strict    # read-only convergence gate

Applies a COMPLETE signature via `replaceParameters(DYNAMIC_STORAGE_FORMAL_PARAMS)`
after setting the calling convention (Ghidra auto-generates `this`). Never infers
a parameter from `in_stack_*`; every parameter comes from the C++ declaration.
Writes the queue to build-msvc500/evidence/source_signature_queue.csv.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

from tools.clang_ast_index import load_compact_index
from tools.common import ghidra_env
from tools.common.repo import repo_root_from_file
from tools.source_model import build_model

_DEFAULT_DECL_INDEX = "build-msvc500/generated/decl_index.json"

# Per-function decompile timeout (seconds). Kept at 20 so the projected set matches
# the committed DB: a handful of giant init functions exceed it and are reported as
# `decompile_failed:before` (skipped, as they were pre-projection). Raising it to
# project them is a DB-CHANGING follow-up, not part of this no-DB-change pass.
_DECOMPILE_BUDGET_S = 20

_CC_RE = re.compile(r"\b(__cdecl|__stdcall|__thiscall|__fastcall)\b")
_PRIMITIVES = {
    "void": "void", "bool": "bool", "char": "char",
    "uchar": "byte", "unsignedchar": "byte", "byte": "byte",
    "short": "short", "ushort": "ushort", "unsignedshort": "ushort",
    "int": "int", "uint": "uint", "unsignedint": "uint", "unsigned": "uint",
    "long": "int", "ulong": "uint", "unsignedlong": "uint",
    "float": "float", "double": "double",
    "wchar_t": "wchar_t", "__int64": "longlong", "int64": "longlong",
}
# Pointer-sized MFC/Win32 typedefs Ghidra's DTM may not carry as named types.
# Modelled as a generic pointer: pointee is irrelevant to stack-frame layout.
_POINTER_ALIASES = {
    "position", "lpvoid", "lpcvoid", "hwnd", "hdc", "hbitmap", "hicon",
    "hcursor", "hmenu", "hinstance", "hmodule", "hgdiobj", "hpen", "hbrush",
    "hpalette", "hfont", "hrgn", "handle", "hkey", "hglobal", "hlocal",
    # string pointers and a few more pointer-sized typedefs the DB lacks as names
    "lpctstr", "lptstr", "lpcstr", "lpstr", "lpcwstr", "lpwstr",
    "rgnhandle",       # Mac/GDI region handle (opaque pointer)
    "lpcreatestruct", "lpcreatestructa", "lprect", "lppoint", "lpsize", "lpmsg",
    "tsortedlistcomparefunc", "tlistcomparefunc",  # function-pointer typedefs
    "farproc", "wndproc", "dlgproc", "hookproc", "timerproc",
}


def _decompiler(program):
    from ghidra.app.decompiler import DecompInterface, DecompileOptions

    ifc = DecompInterface()
    ifc.setOptions(DecompileOptions())
    ifc.setSimplificationStyle("decompile")
    ifc.openProgram(program)
    return ifc


def _in_stack_offsets(hf) -> set[int]:
    out = set()
    if hf is None:
        return out
    it = hf.getLocalSymbolMap().getSymbols()
    while it.hasNext():
        s = it.next()
        if "in_stack_" not in s.getName() or s.isParameter():
            continue
        st = s.getStorage()
        if st.isStackStorage() and st.getStackOffset() > 0:
            out.add(st.getStackOffset())
    return out


def _decompile_in_stack(ifc, fn, monitor) -> set[int] | None:
    """Positive-offset in_stack set for `fn`, or None if the decompile FAILED.

    None (decompile did not complete) is distinct from an empty set (decompiled
    cleanly, no in_stack) — the caller must not conflate them.
    """
    res = ifc.decompileFunction(fn, _DECOMPILE_BUDGET_S, monitor)
    if not res.decompileCompleted():
        return None
    return _in_stack_offsets(res.getHighFunction())


_PLACEHOLDER_RET_RE = re.compile(r"^undefined[1-8]?$")
_DECL_QUALIFIER_RE = re.compile(r"\b(?:public|protected|private)\s*:|\b(?:virtual|static|inline)\b")


def _is_placeholder_return(ret_str: str) -> bool:
    """True for Ghidra placeholder return types (`undefined`, `undefined4`, …).

    Source declaring one of these is a leaked Ghidra guess, not an authoritative
    return type — keep whatever the DB already inferred.
    """
    return bool(_PLACEHOLDER_RET_RE.match(ret_str.replace(" ", "").lower()))


def parse_prototype(proto: str):
    """(cc_or_None, return_str, [param_type_str,...], entity_kind) from a decl head.

    Returns None if the prototype cannot be parsed cleanly (queued upstream).
    `entity_kind` is a best-effort classification used to default the calling
    convention when source carries no explicit one:

      constructor / destructor / instance_method -> __thiscall
      static_method / free_function              -> __cdecl

    LIMITATION (tracked for the structured source-model work): the out-of-class
    definition head this parser sees does not repeat the `static` keyword, and a
    bare `Ns::fn` is indistinguishable from `Class::method` without a declaration
    index. So a static member function, or a namespace-qualified free function,
    whose marker prototype lacks an explicit `static`/convention is classified
    `instance_method` (=> __thiscall) here. `static` IS honoured when the
    prototype carries it (e.g. an MFC reviewed identity). A wrong convention that
    still happens to bind the flagged offsets is exactly why in_stack clearing is
    NOT sufficient proof of correctness — see the module docstring.
    """
    proto = proto.strip()
    has_static = bool(re.search(r"\bstatic\b", proto))
    # Strip MSVC declaration qualifiers that are not part of the type
    # (access specifiers, virtual/static/inline). MFC reviewed prototypes carry
    # these, e.g. "public: virtual void __thiscall CDocTemplate::InitialUpdateFrame".
    proto = _DECL_QUALIFIER_RE.sub(" ", proto)
    m = _CC_RE.search(proto)
    cc = m.group(1) if m else None
    if cc:
        proto = proto.replace(cc, " ")
    # Take the FIRST balanced paren group after the name as the arg list — NOT the
    # last. For a constructor with a member-initializer list
    # (`TFoo::TFoo(args) : TBase(...), field(0)`) the last `)` closes the init list,
    # not the args; balanced matching stops at the real arg list's close and ignores
    # everything after it (init list, trailing `const`, `{`). Nested parens in a
    # function-pointer parameter are handled by the depth counter.
    open_i = proto.find("(")
    if open_i < 0:
        return None
    depth, close_i = 0, -1
    for i in range(open_i, len(proto)):
        if proto[i] == "(":
            depth += 1
        elif proto[i] == ")":
            depth -= 1
            if depth == 0:
                close_i = i
                break
    if close_i < 0:
        return None
    head = proto[:open_i].strip()          # "RetType Class::method" (or "Class::ctor")
    argstr = proto[open_i + 1:close_i].strip()
    # Return type = head minus the trailing qualified-name (Class::method).
    tokens = head.rsplit("::", 1)
    is_qualified = len(tokens) == 2
    entity_kind = "free_function"
    if is_qualified:
        # tokens[0] = "RetType... Class"; the class name is its last space token,
        # the return type is everything before that.
        left_parts = tokens[0].split()
        cls = left_parts[-1] if left_parts else ""
        ret = " ".join(left_parts[:-1]).strip()
        meth = tokens[1].strip()
        # For ctors/dtors there is no return type -> void.
        is_dtor = meth.startswith("~")
        is_ctor = meth == cls
        if not ret or is_ctor or is_dtor:
            ret = "void"
        if is_dtor:
            entity_kind = "destructor"
        elif is_ctor:
            entity_kind = "constructor"
        elif has_static:
            entity_kind = "static_method"
        else:
            entity_kind = "instance_method"
    else:
        name_m = re.search(r"[A-Za-z_][A-Za-z0-9_]*\s*$", head)
        ret = head[:name_m.start()].strip() if name_m else "void"
        if not ret:
            ret = "void"
        entity_kind = "static_method" if has_static else "free_function"
    if argstr in ("", "void"):
        params: list[str] = []
    else:
        params = _split_params(argstr)
        if params is None:
            return None
    return cc, ret, params, entity_kind


def default_convention(entity_kind: str) -> str:
    """The MSVC x86 convention implied by a source declaration lacking one."""
    if entity_kind in ("constructor", "destructor", "instance_method"):
        return "__thiscall"
    return "__cdecl"  # static_method, free_function, namespace_function


def resolve_entity_kind(decl_index, qualified_name: str, n_params: int,
                        fallback: str) -> str:
    """Authoritative entity kind from the Clang AST index, else the fallback.

    The index (from `tools.clang_ast_index`) knows the facts a definition head
    cannot show — `static` and class-vs-namespace scope. Match by qualified name;
    for overloads (several decls share a name) disambiguate on parameter count,
    preferring an exact arity match. Returns `fallback` (the punctuation guess)
    when the name is absent — true of free functions defined only in a .cpp, where
    the punctuation answer is already correct.
    """
    if not decl_index:
        return fallback
    decls = decl_index.get(qualified_name)
    if not decls:
        return fallback
    if len(decls) == 1:
        return decls[0].kind
    exact = [d for d in decls if len(d.params) == n_params]
    if len(exact) == 1:
        return exact[0].kind
    # Ambiguous overload set — if they all agree on kind, use it; else fall back.
    kinds = {d.kind for d in (exact or decls)}
    return next(iter(kinds)) if len(kinds) == 1 else fallback


def _split_params(argstr: str) -> list[str] | None:
    """Split a param list on top-level commas; return each param's TYPE string."""
    parts, depth, cur = [], 0, ""
    for ch in argstr:
        if ch in "<([":
            depth += 1
        elif ch in ">)]":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        parts.append(cur)
    types = []
    for p in parts:
        t = _param_type_only(p.strip())
        if t is None:
            return None
        types.append(t)
    return types


_TYPE_KEYWORDS = {
    "unsigned", "signed", "long", "short", "int", "char", "float", "double",
    "void", "bool", "wchar_t", "__int64", "__int32", "__int16", "__int8",
}
# Keywords that need a following noun to form a type — a token after one of these
# completes the type (it is NOT a parameter name): "class CPoint", "unsigned int".
_NEEDS_NOUN = {"unsigned", "signed", "class", "struct", "union", "enum",
               "const", "volatile"}


def _param_type_only(param: str) -> str | None:
    """Strip the parameter NAME, keep the type.

    Disambiguates `short nPictureId` (name -> drop) from `class CPoint` /
    `unsigned int` / `struct tagPOINT` (no name; the trailing word completes the
    type). A trailing identifier is a NAME only when it is not itself a type
    keyword and the word before it is not a noun-needing keyword.
    """
    param = param.strip()
    if not param:
        return None
    if param.endswith(("*", "&", ">")):
        return param  # pointer/ref/template tail -> whole token is the type
    m = re.search(r"[A-Za-z_][A-Za-z0-9_]*$", param)
    if not m:
        return param
    last = m.group(0)
    if last in _TYPE_KEYWORDS:
        return param  # e.g. "unsigned int" — trailing token is part of the type
    head = param[:m.start()].rstrip()
    if not head:
        return param  # only one token — it is the type ("int", "CPoint")
    prev = head.split()[-1].rstrip("*&")
    if prev in _NEEDS_NOUN:
        return param  # "class CPoint" / "struct tagPOINT" — completes the type
    return head       # trailing identifier is the parameter name; drop it


class TypeResolver:
    def __init__(self, program):
        self.dtm = program.getDataTypeManager()
        from ghidra.program.model.data import (
            BooleanDataType, ByteDataType, CharDataType, DoubleDataType,
            FloatDataType, IntegerDataType, LongLongDataType, ShortDataType,
            UnsignedIntegerDataType, UnsignedShortDataType, VoidDataType,
            WideCharDataType,
        )
        self._prim = {
            "void": VoidDataType(), "bool": BooleanDataType(), "char": CharDataType(),
            "byte": ByteDataType(), "short": ShortDataType(), "ushort": UnsignedShortDataType(),
            "int": IntegerDataType(), "uint": UnsignedIntegerDataType(),
            "float": FloatDataType(), "double": DoubleDataType(),
            "wchar_t": WideCharDataType(), "longlong": LongLongDataType(),
        }
        # name -> DataType cache for named lookups, plus a same-simple-name count so
        # we can flag ambiguous resolutions (two datatypes from different categories
        # sharing a name — a lossy pick, not a semantic match).
        self._named: dict[str, object] = {}
        self._name_count: dict[str, int] = {}
        for dt in self.dtm.getAllDataTypes():
            nm = dt.getName()
            self._named.setdefault(nm, dt)
            self._name_count[nm] = self._name_count.get(nm, 0) + 1

    def resolve(self, text: str):
        """DataType for the C++ type string, or None (see resolve_quality)."""
        return self.resolve_quality(text)[0]

    def resolve_quality(self, text: str):
        """Return (DataType|None, quality). Quality grades how trustworthy the pick is:

          exact                  — a primitive or a uniquely-named datatype match
          canonical_alias        — a known MFC/Win32 typedef modelled as its ABI shape
          generic_pointer_fallback — unresolved pointee typed as void* (ABI-size only)
          ambiguous_simple_name  — several datatypes share the simple name; first wins
          unresolved             — a non-pointer type we cannot size at all (None dt)

        A pointer's pointee is irrelevant to stack-frame layout, so an unresolved
        *pointer* still binds at the right slot/size — good enough for ABI storage
        convergence, but only `exact`/`canonical_alias` count as *semantic*
        convergence.
        """
        text = text.replace("const", " ").replace("volatile", " ")
        text = re.sub(r"\b(class|struct|union|enum)\b", " ", text).strip()
        ptr = 0
        while text.endswith("*") or text.endswith("&"):
            ptr += 1
            text = text[:-1].strip()
        key = text.replace(" ", "").lower()
        quality = "exact"
        if key in _POINTER_ALIASES:
            base = self._prim["void"]
            ptr += 1
            quality = "canonical_alias"
        elif key in _PRIMITIVES:
            base = self._prim.get(_PRIMITIVES[key])
        else:
            base = self._named.get(text)
            if base is not None and self._name_count.get(text, 1) > 1:
                quality = "ambiguous_simple_name"
            if base is None:
                if ptr > 0:
                    base = self._prim["void"]  # generic pointer to unknown pointee
                    quality = "generic_pointer_fallback"
                else:
                    return None, "unresolved"
        for _ in range(ptr):
            base = self.dtm.getPointer(base)
        return base, quality


# Queue reasons that mean "the tool or the data is broken" — a hard failure under
# --strict. Everything else is a classified, EXPLAINED state, not a failure:
#   - missing_function     — the address has no standalone DB function (inlined/folded)
#   - decompile_failed:*   — the decompiler timed out (giant init functions exceed the
#                            per-function budget); a pre-existing limitation, not a
#                            projection error. Reported, and the DB is untouched
#                            (before-failure) or rolled back (after-failure).
#   - sret / unresolved / dynamic_storage_insufficient / params_bound_residual — the
#                            honest structural queue.
_HARD_FAIL_REASONS = ("unparsable_prototype", "apply_error")


def _classify_projection(before, after):
    """Decide the outcome of a projection from the before/after in_stack sets.

    Returns (commit: bool, reason: str|None). `commit` True keeps the DB edit;
    False triggers a transaction ROLLBACK (the exact restore). `reason` is the
    queue reason (None only for a clean converge). `after is None` means the
    verifying decompile FAILED — we must not keep an unverifiable signature.
    """
    if after is None:
        return False, "decompile_failed:after"
    original_still = sorted(before & after)
    if original_still:
        # Projection did not bind the offsets it was meant to — DYNAMIC_STORAGE-
        # insoluble (packed sub-dword args, sret, wrong boundary). Reject.
        return False, "dynamic_storage_insufficient:" + ",".join(hex(o) for o in original_still)
    if after:
        # Flagged offsets bound (params correct) but a residual remains at a
        # DIFFERENT offset (sub-dword read inside a bound slot, or a spurious
        # local). Keep the correct binding, log the residual.
        return True, "params_bound_residual:" + ",".join(hex(o) for o in sorted(after))
    return True, None  # fully converged


def run(program, args, model):
    from ghidra.program.model.listing import Function, ParameterImpl
    from ghidra.program.model.symbol import SourceType

    import pyghidra

    fm = program.getFunctionManager()
    af = program.getAddressFactory().getDefaultAddressSpace()
    ifc = _decompiler(program)
    monitor = pyghidra.task_monitor()
    resolver = TypeResolver(program)

    decl_index = getattr(args, "_decl_index", None)

    addrs = [int(a, 16) for a in args.addrs] if args.addrs else None

    converged, queued, applied = [], [], 0

    # Candidate set: source markers (FUNCTION) and reviewed library identities
    # (LIBRARY) with a prototype. A missing DB function is recorded distinctly.
    targets = []
    for addr, claim in sorted(model.functions.items()):
        if claim.kind not in ("FUNCTION", "LIBRARY"):
            continue
        if not claim.prototype:
            continue
        if addrs is not None and addr not in addrs:
            continue
        fn = fm.getFunctionAt(af.getAddress(addr))
        if fn is None:
            queued.append((addr, claim.name, "missing_function", claim.prototype))
            continue
        targets.append((addr, claim, fn))

    for addr, claim, fn in targets:
        before = _decompile_in_stack(ifc, fn, monitor)
        if before is None:
            # Decompile failed BEFORE we touched anything — cannot assess. Distinct
            # from an empty set (a genuinely clean function, which we skip).
            queued.append((addr, claim.name, "decompile_failed:before", claim.prototype))
            continue
        if not before:
            continue  # no in_stack — genuinely fine, nothing to project
        parsed = parse_prototype(claim.prototype)
        if parsed is None:
            queued.append((addr, claim.name, "unparsable_prototype", claim.prototype))
            continue
        cc, ret_str, param_strs, entity_kind = parsed
        # Source is authoritative for the convention; when the declaration omits
        # one the C++ ABI fixes it from the entity kind. Prefer the Clang AST index
        # (it knows static/namespace facts a definition head can't show) over the
        # punctuation guess (see resolve_entity_kind / default_convention).
        if not cc:
            entity_kind = resolve_entity_kind(
                decl_index, claim.name, len(param_strs), entity_kind)
            cc = default_convention(entity_kind)
        # A leaked `undefined` return is a Ghidra placeholder, not authoritative —
        # keep the DB's inferred return (ret_dt=None) and project only the params.
        if _is_placeholder_return(ret_str):
            ret_dt = None
        else:
            ret_dt = resolver.resolve(ret_str)
            if ret_dt is None:
                queued.append((addr, claim.name, f"unresolved_return:{ret_str}", claim.prototype))
                continue
            if ret_dt.getLength() > 4 and "*" not in ret_str:
                queued.append((addr, claim.name, "sret_by_value_return", claim.prototype))
                continue
        param_dts = []
        bad = None
        for t in param_strs:
            dt = resolver.resolve(t)
            if dt is None:
                bad = t
                break
            param_dts.append(dt)
        if bad is not None:
            queued.append((addr, claim.name, f"unresolved_param:{bad}", claim.prototype))
            continue

        if not args.apply:
            converged.append((addr, claim.name, "would_project", len(param_dts)))
            continue

        # Per-function transaction: commit on accept, ROLLBACK on reject. Ghidra's
        # transaction rollback IS the exact-restore mechanism — no hand-rebuilt
        # signature, so a function classified "reverted" is byte-for-byte its prior
        # self, including custom storage, and a partial/failed edit cannot leak.
        ftx = program.startTransaction(f"project 0x{addr:08x}")
        commit = False
        reason = None
        try:
            if ret_dt is not None:
                fn.setReturnType(ret_dt, SourceType.USER_DEFINED)
            fn.setCallingConvention(cc)
            impls = [ParameterImpl(f"a{i}", dt, program) for i, dt in enumerate(param_dts)]
            fn.replaceParameters(
                Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, True,
                SourceType.USER_DEFINED, *impls)
            ifc.flushCache()
            after = _decompile_in_stack(ifc, fn, monitor)
            commit, reason = _classify_projection(before, after)
        except Exception as exc:  # noqa: BLE001
            commit, reason = False, f"apply_error:{type(exc).__name__}"
        finally:
            program.endTransaction(ftx, commit)  # commit=False => exact DB rollback

        if commit and reason is None:
            converged.append((addr, claim.name, "projected", len(param_dts)))
            applied += 1
        elif commit:  # params_bound_residual — kept, but logged
            applied += 1
            queued.append((addr, claim.name, reason, claim.prototype))
        else:
            queued.append((addr, claim.name, reason, claim.prototype))

    if args.apply:
        program.save("apply source signatures", pyghidra.task_monitor())

    return converged, queued, applied


def _db_logical(fn):
    """(cc, n_explicit_params, has_this, [param_abi_sizes]) for a DB function.

    `this` and other auto-params (e.g. sret `__return_storage_ptr`) are excluded
    from the explicit count; `has_this` is true when the convention is __thiscall
    or an auto `this` param is present.
    """
    cc = fn.getCallingConventionName() or ""
    explicit, sizes, has_this = 0, [], cc == "__thiscall"
    for p in fn.getParameters():
        if p.isAutoParameter():
            if p.getName() == "this":
                has_this = True
            continue
        explicit += 1
        dt = p.getDataType()
        sizes.append(dt.getLength() if dt else 0)
    return cc, explicit, has_this, sizes


def structural_audit(program, model, args):
    """Read-only: compare every claim's EXPECTED logical signature (source model +
    Clang AST index) against the DB's ACTUAL signature, and classify the gap.

    Unlike the projector this is source-driven, not in_stack-triggered: it visits
    every FUNCTION/LIBRARY claim, so it surfaces functions the DB never resolved
    (cc=unknown / 0 params) that produce no in_stack and are therefore invisible to
    the projector. Logical convergence (convention, this-presence, arity) and ABI
    storage (param sizes) are reported separately, along with the worst type
    resolution quality on the row.
    """
    fm = program.getFunctionManager()
    af = program.getAddressFactory().getDefaultAddressSpace()
    resolver = TypeResolver(program)
    decl_index = getattr(args, "_decl_index", None)

    _QUALITY_RANK = {"exact": 0, "canonical_alias": 1, "generic_pointer_fallback": 2,
                     "ambiguous_simple_name": 3, "unresolved": 4}
    rows = []
    for addr, claim in sorted(model.functions.items()):
        if claim.kind not in ("FUNCTION", "LIBRARY") or not claim.prototype:
            continue
        fn = fm.getFunctionAt(af.getAddress(addr))
        if fn is None:
            rows.append((addr, claim.name, "missing_function", "", ""))
            continue
        parsed = parse_prototype(claim.prototype)
        if parsed is None:
            rows.append((addr, claim.name, "unparsable_prototype", "", ""))
            continue
        cc, ret_str, param_strs, punct_kind = parsed
        entity_kind = resolve_entity_kind(decl_index, claim.name, len(param_strs), punct_kind)
        exp_cc = cc or default_convention(entity_kind)
        exp_this = entity_kind in ("constructor", "destructor", "instance_method")
        exp_n = len(param_strs)
        worst = "exact"
        for t in param_strs:
            _dt, q = resolver.resolve_quality(t)
            if _QUALITY_RANK[q] > _QUALITY_RANK[worst]:
                worst = q

        db_cc, db_n, db_this, _sizes = _db_logical(fn)
        # Classify the LOGICAL gap (worst-first).
        if db_cc in ("", "unknown", "default") or (db_n == 0 and exp_n > 0):
            cat = "db_signature_incomplete"
        elif db_cc != exp_cc:
            cat = "convention_mismatch"
        elif db_this != exp_this:
            cat = "this_presence_mismatch"
        elif db_n != exp_n:
            cat = "param_count_mismatch"
        else:
            cat = "converged"
        detail = f"exp[{exp_cc},this={exp_this},n={exp_n}] db[{db_cc},this={db_this},n={db_n}]"
        rows.append((addr, claim.name, cat, worst, detail))
    return rows


def _write_audit(rows, out_path):
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    lines = ["address|name|category|type_resolution|detail"]
    for addr, name, cat, q, detail in sorted(rows):
        lines.append(f"0x{addr:08x}|{name}|{cat}|{q}|{detail}")
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_queue(queued, out_path):
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    lines = ["address|name|reason|prototype"]
    for addr, name, reason, proto in sorted(queued):
        lines.append(f"0x{addr:08x}|{name}|{reason}|{proto}".replace("\n", " "))
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_divergent(program, args, model):
    """Source-DRIVEN projection: apply source signatures to claims whose DB
    signature is incomplete/short, independent of whether they show `in_stack`.

    Candidate set (the safe, high-value subset of the structural audit):
      - db_signature_incomplete — DB `cc=unknown` or 0 params, source has a real
        signature (Ghidra never resolved it; invisible to the in_stack projector);
      - param_count_mismatch with source arity > DB arity and matching convention
        (DB is missing trailing parameters).
    Excluded here (delicate / handled elsewhere): DB over-declared (source arity <
    DB, likely an MFC override), and convention_mismatch (bridges / ambiguity).

    Acceptance is STRICTER than the in_stack path — these functions had no in_stack
    to clear, so `in_stack` clearing proves nothing. Commit only on FULL
    convergence: the re-decompile has NO in_stack (the source signature did not
    introduce a frame the binary contradicts) AND the resulting DB logical
    signature structurally matches expected (convention + arity + this). Anything
    else rolls back (transaction abort = exact restore) and is queued.
    """
    from ghidra.program.model.listing import Function, ParameterImpl
    from ghidra.program.model.symbol import SourceType
    import pyghidra

    fm = program.getFunctionManager()
    af = program.getAddressFactory().getDefaultAddressSpace()
    ifc = _decompiler(program)
    monitor = pyghidra.task_monitor()
    resolver = TypeResolver(program)
    decl_index = getattr(args, "_decl_index", None)
    addrs = [int(a, 16) for a in args.addrs] if args.addrs else None

    projected, queued = [], []
    for addr, claim in sorted(model.functions.items()):
        if claim.kind not in ("FUNCTION", "LIBRARY") or not claim.prototype:
            continue
        if addrs is not None and addr not in addrs:
            continue
        fn = fm.getFunctionAt(af.getAddress(addr))
        if fn is None:
            continue
        parsed = parse_prototype(claim.prototype)
        if parsed is None:
            continue
        cc, ret_str, param_strs, punct_kind = parsed
        entity_kind = resolve_entity_kind(decl_index, claim.name, len(param_strs), punct_kind)
        exp_cc = cc or default_convention(entity_kind)
        exp_this = entity_kind in ("constructor", "destructor", "instance_method")
        exp_n = len(param_strs)

        db_cc, db_n, db_this, _ = _db_logical(fn)
        incomplete = db_cc in ("", "unknown", "default") or (db_n == 0 and exp_n > 0)
        short = (db_cc == exp_cc and db_this == exp_this and exp_n > db_n)
        if not (incomplete or short):
            continue  # not a broad-projection candidate
        if exp_n == 0 and not incomplete:
            continue

        # Resolve every parameter type; a non-pointer we cannot size => queue.
        param_dts, bad = [], None
        for t in param_strs:
            dt = resolver.resolve(t)
            if dt is None:
                bad = t
                break
            param_dts.append(dt)
        if bad is not None:
            queued.append((addr, claim.name, f"unresolved_param:{bad}", claim.prototype))
            continue
        ret_dt = None if _is_placeholder_return(ret_str) else resolver.resolve(ret_str)
        if ret_dt is not None and ret_dt.getLength() > 4 and "*" not in ret_str:
            queued.append((addr, claim.name, "sret_by_value_return", claim.prototype))
            continue

        if not args.apply:
            projected.append((addr, claim.name, "would_project", exp_n))
            continue

        # No pre-decompile needed: the acceptance is "after is fully clean", not a
        # before/after in_stack diff (these candidates had no in_stack to clear).
        ftx = program.startTransaction(f"project-divergent 0x{addr:08x}")
        commit, reason = False, None
        try:
            if ret_dt is not None:
                fn.setReturnType(ret_dt, SourceType.USER_DEFINED)
            fn.setCallingConvention(exp_cc)
            impls = [ParameterImpl(f"a{i}", dt, program) for i, dt in enumerate(param_dts)]
            fn.replaceParameters(
                Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, True,
                SourceType.USER_DEFINED, *impls)
            ifc.flushCache()
            after = _decompile_in_stack(ifc, fn, monitor)
            n_cc, n_n, n_this, _ = _db_logical(fn)
            if after is None:
                reason = "decompile_failed:after"
            elif after:
                reason = "introduced_in_stack:" + ",".join(hex(o) for o in sorted(after))
            elif n_cc == exp_cc and n_n == exp_n and n_this == exp_this:
                commit = True
            else:
                reason = f"structural_mismatch:db[{n_cc},this={n_this},n={n_n}]"
        except Exception as exc:  # noqa: BLE001
            reason = f"apply_error:{type(exc).__name__}"
        finally:
            program.endTransaction(ftx, commit)

        if commit:
            projected.append((addr, claim.name, "projected", exp_n))
        else:
            queued.append((addr, claim.name, reason, claim.prototype))

    if args.apply:
        program.save("project divergent signatures", pyghidra.task_monitor())
    return projected, queued


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--apply", action="store_true", help="Project + verify (default: dry-run).")
    p.add_argument("--strict", action="store_true", help="Exit nonzero if any non-queued source row is non-converged.")
    p.add_argument("--addrs", nargs="+", help="Restrict to these addresses (hex).")
    p.add_argument("--queue-out", default="build-msvc500/evidence/source_signature_queue.csv")
    p.add_argument("--structural-audit", action="store_true",
                   help="READ-ONLY: compare every claim's expected signature (source + "
                        "index) to the DB and classify the gap. No projection, no DB write.")
    p.add_argument("--project-divergent", action="store_true",
                   help="Source-DRIVEN projection: apply source signatures to claims the DB "
                        "left incomplete/short (not just in_stack ones). Commit on FULL "
                        "convergence only. Combine with --apply to write; MUTATES the DB.")
    p.add_argument("--audit-out", default="build-msvc500/evidence/signature_convergence.csv")
    p.add_argument("--decl-index", default=_DEFAULT_DECL_INDEX,
                   help="Clang-AST declaration index for authoritative entity kinds "
                        "(generate with `just clang-decl-index`). Punctuation fallback if absent.")
    args = p.parse_args()

    repo_root = repo_root_from_file(__file__, levels_up=2)
    model = build_model(repo_root, "IMPERIALISM")

    index_path = Path(args.decl_index)
    if not index_path.is_absolute():
        index_path = repo_root / index_path
    if index_path.exists():
        args._decl_index = load_compact_index(index_path)
        print(f"decl index: {len(args._decl_index)} names from {index_path}")
    else:
        args._decl_index = None
        print(f"decl index: {index_path} absent — punctuation entity-kind fallback")

    if args.structural_audit:
        project = ghidra_env.open_project()
        consumer = program = None
        try:
            consumer, program = ghidra_env.open_program(project, writable=False)
            rows = structural_audit(program, model, args)
        finally:
            if program is not None:
                program.release(consumer)
            project.close()
        _write_audit(rows, args.audit_out)
        cats: dict = {}
        quals: dict = {}
        for _a, _n, cat, q, _d in rows:
            cats[cat] = cats.get(cat, 0) + 1
            if q:
                quals[q] = quals.get(q, 0) + 1
        print(f"[STRUCTURAL AUDIT] {len(rows)} claims -> {args.audit_out}")
        print("  by category: " + ", ".join(f"{k}={v}" for k, v in sorted(cats.items())))
        print("  worst type resolution: " + ", ".join(f"{k}={v}" for k, v in sorted(quals.items())))
        return 0

    if args.project_divergent:
        project = ghidra_env.open_project()
        consumer = program = None
        try:
            consumer, program = ghidra_env.open_program(project, writable=bool(args.apply))
            projected, queued = run_divergent(program, args, model)
        finally:
            if program is not None:
                program.release(consumer)
            project.close()
        _write_queue(queued, args.queue_out)
        reasons: dict = {}
        for _a, _n, r, _p in queued:
            reasons[r.split(":", 1)[0]] = reasons.get(r.split(":", 1)[0], 0) + 1
        mode = "APPLIED" if args.apply else "DRY RUN"
        print(f"[{mode}] source-driven projection: projected={len(projected)} queued={len(queued)}")
        print(f"  queue -> {args.queue_out}")
        print("  queued by reason: " + ", ".join(f"{k}={v}" for k, v in sorted(reasons.items())))
        if args.strict:
            hard = [q for q in queued if q[2].split(":", 1)[0] in _HARD_FAIL_REASONS]
            if hard:
                print(f"strict: {len(hard)} hard failure(s)")
                return 1
        return 0

    project = ghidra_env.open_project()
    consumer = program = None
    try:
        consumer, program = ghidra_env.open_program(project, writable=bool(args.apply))
        converged, queued, applied = run(program, args, model)
    finally:
        if program is not None:
            program.release(consumer)
        project.close()

    _write_queue(queued, args.queue_out)

    reasons: dict[str, int] = {}
    for _a, _n, r, _p in queued:
        reasons[r.split(":", 1)[0]] = reasons.get(r.split(":", 1)[0], 0) + 1
    mode = "APPLIED" if args.apply else "DRY RUN"
    print(f"[{mode}] source-owned in_stack functions: "
          f"converged={len(converged)} queued={len(queued)} (applied={applied})")
    print(f"  queue -> {out}")
    print("  queued by reason: " + ", ".join(f"{k}={v}" for k, v in sorted(reasons.items())))
    if args.strict and queued:
        # Strict gate: only the "could not verify / errored" reasons fail
        # (_HARD_FAIL_REASONS). The classified structural sub-categories (sret,
        # packed, unresolved, params_bound_residual, missing_function) are the
        # honest queue, not failures.
        hard = [q for q in queued if q[2].split(":", 1)[0] in _HARD_FAIL_REASONS]
        if hard:
            print(f"strict: {len(hard)} unexplained projection failure(s):")
            for a, n, r, _ in hard[:10]:
                print(f"    - 0x{a:08x} {n}: {r}")
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
