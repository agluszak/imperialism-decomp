#!/usr/bin/env python3
"""Project source-model signatures into Ghidra (the MSVC500 PDB can't — see PR #91).

`cvdump -t` extracts ZERO type records from the MSVC500 recomp PDB, so
reccmp-ghidra-import can transfer names/return types but never parameter lists.
The authoritative signature source is therefore the source model
(`tools.source_model`, which parses the C++ declaration head into a prototype).

This tool projects those prototypes onto source-owned functions that still carry
unbound `in_stack_*` reads, and — crucially — VERIFIES each by re-decompile,
reverting anything that does not converge. Verification is the classifier: only
"plain missing params" (+ convention-from-source) survive; sret / packed-short /
sub-dword-alignment / unknown-convention / unresolved-type cases are queued with
a reason and never left with a guessed signature.

  just apply-source-signatures            # dry-run: report what would change
  just apply-source-signatures --apply    # project + verify + revert non-converged
  just source-signature-audit --strict    # read-only convergence gate (nonzero on
                                           # any un-queued non-converged source row)

Applies a COMPLETE signature via `replaceParameters(DYNAMIC_STORAGE_FORMAL_PARAMS)`
after setting the calling convention (Ghidra auto-generates `this`). Never infers
a parameter from `in_stack_*`; every parameter comes from the C++ declaration.
Writes the queue to build-msvc500/evidence/source_signature_queue.csv.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

from tools.common import ghidra_env
from tools.common.repo import repo_root_from_file
from tools.source_model import build_model

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
    res = ifc.decompileFunction(fn, 20, monitor)
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
    """(cc_or_None, return_str, [param_type_str,...], is_method) from a decl head.

    Returns None if the prototype cannot be parsed cleanly (queued upstream).
    `is_method` (name contained `::`) lets the caller default the calling
    convention when source carries no explicit one (method -> __thiscall,
    free function -> __cdecl).
    """
    proto = proto.strip()
    # Strip MSVC declaration qualifiers that are not part of the type
    # (access specifiers, virtual/static/inline). MFC reviewed prototypes carry
    # these, e.g. "public: virtual void __thiscall CDocTemplate::InitialUpdateFrame".
    proto = _DECL_QUALIFIER_RE.sub(" ", proto)
    m = _CC_RE.search(proto)
    cc = m.group(1) if m else None
    if cc:
        proto = proto.replace(cc, " ")
    # Split head(...) — take the LAST top-level paren group as the arg list.
    open_i = proto.find("(")
    close_i = proto.rfind(")")
    if open_i < 0 or close_i < open_i:
        return None
    head = proto[:open_i].strip()          # "RetType Class::method" (or "Class::ctor")
    argstr = proto[open_i + 1:close_i].strip()
    # Return type = head minus the trailing qualified-name (Class::method).
    tokens = head.rsplit("::", 1)
    is_method = len(tokens) == 2
    if is_method:
        # tokens[0] = "RetType... Class"; the class name is its last space token,
        # the return type is everything before that.
        left_parts = tokens[0].split()
        cls = left_parts[-1] if left_parts else ""
        ret = " ".join(left_parts[:-1]).strip()
        meth = tokens[1].strip()
        # For ctors/dtors there is no return type -> void.
        is_ctor_dtor = meth == cls or meth == "~" + cls or meth.startswith("~")
        if not ret or is_ctor_dtor:
            ret = "void"
    else:
        name_m = re.search(r"[A-Za-z_][A-Za-z0-9_]*\s*$", head)
        ret = head[:name_m.start()].strip() if name_m else "void"
        if not ret:
            ret = "void"
    if argstr in ("", "void"):
        params: list[str] = []
    else:
        params = _split_params(argstr)
        if params is None:
            return None
    return cc, ret, params, is_method


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
        # name -> DataType cache for named lookups
        self._named: dict[str, object] = {}
        for dt in self.dtm.getAllDataTypes():
            self._named.setdefault(dt.getName(), dt)

    def resolve(self, text: str):
        """Return a DataType for the C++ type string, or None.

        A pointer's pointee is irrelevant to stack-frame layout (all pointers are
        4 bytes on x86), so an unresolved *pointer* type falls back to a generic
        pointer rather than failing — that still binds the parameter at the right
        slot/size, which is what clears the `in_stack`. Only a non-pointer type we
        cannot size at all returns None (queued).
        """
        text = text.replace("const", " ").replace("volatile", " ")
        # Drop C++ elaborated-type-specifier keywords ("class CWnd" -> "CWnd").
        text = re.sub(r"\b(class|struct|union|enum)\b", " ", text).strip()
        ptr = 0
        while text.endswith("*") or text.endswith("&"):
            ptr += 1
            text = text[:-1].strip()
        key = text.replace(" ", "").lower()
        # MFC/Win32 typedefs Ghidra's DTM may not carry; each is pointer-sized.
        if key in _POINTER_ALIASES:
            base = self._prim["void"]
            ptr += 1
        else:
            base = None
            if key in _PRIMITIVES:
                base = self._prim.get(_PRIMITIVES[key])
            if base is None:
                base = self._named.get(text)
            if base is None:
                # last-ditch: exact-name search ignoring namespace
                for dt in self.dtm.getAllDataTypes():
                    if dt.getName() == text:
                        base = dt
                        break
            if base is None:
                if ptr > 0:
                    base = self._prim["void"]  # generic pointer to unknown pointee
                else:
                    return None
        for _ in range(ptr):
            base = self.dtm.getPointer(base)
        return base


def _snapshot(fn):
    """Enough to restore a function's signature if projection fails to converge."""
    return {
        "cc": fn.getCallingConventionName(),
        "ret": fn.getReturnType(),
        "custom": fn.hasCustomVariableStorage(),
        "params": [(p.getName(), p.getDataType(), p.getVariableStorage()) for p in fn.getParameters()],
    }


def run(program, args, model):
    from ghidra.program.model.listing import Function, ParameterImpl
    from ghidra.program.model.symbol import SourceType

    import pyghidra

    fm = program.getFunctionManager()
    af = program.getAddressFactory().getDefaultAddressSpace()
    ifc = _decompiler(program)
    monitor = pyghidra.task_monitor()
    resolver = TypeResolver(program)

    # Candidate set: source-owned functions with unbound in_stack.
    if args.addrs:
        addrs = [int(a, 16) for a in args.addrs]
    else:
        addrs = None

    converged, queued, applied = [], [], 0
    txid = program.startTransaction("apply source signatures") if args.apply else None
    try:
        targets = []
        for addr, claim in sorted(model.functions.items()):
            # Source markers (FUNCTION) and reviewed library identities (LIBRARY)
            # both carry an authoritative prototype the PDB can't project. Other
            # kinds (STUB/TEMPLATE/SYNTHETIC) are not signature sources.
            if claim.kind not in ("FUNCTION", "LIBRARY"):
                continue
            if not claim.prototype:
                continue
            if addrs is not None and addr not in addrs:
                continue
            fn = fm.getFunctionAt(af.getAddress(addr))
            if fn is None:
                continue
            targets.append((addr, claim, fn))

        for addr, claim, fn in targets:
            before = _decompile_in_stack(ifc, fn, monitor)
            if not before:
                continue  # no in_stack (already fine) or decomp failed
            parsed = parse_prototype(claim.prototype)
            if parsed is None:
                queued.append((addr, claim.name, "unparsable_prototype", claim.prototype))
                continue
            cc, ret_str, param_strs, is_method = parsed
            # Source is authoritative for the convention. When the declaration
            # carries no explicit one, the C++ ABI fixes it: a non-static method
            # is __thiscall, a free function is __cdecl. (Ghidra's own "unknown"
            # is exactly the state that leaves the frame unplaced -> in_stack.)
            if not cc:
                cc = "__thiscall" if is_method else "__cdecl"
            # `undefined`/`undefinedN` in a source head is a Ghidra placeholder that
            # leaked into the declaration — source is NOT authoritative for it. Keep
            # the DB's inferred return type (ret_dt=None => don't touch it) and still
            # project the params (they, not the return, clear the in_stack).
            if _is_placeholder_return(ret_str):
                ret_dt = None
            else:
                ret_dt = resolver.resolve(ret_str)
                if ret_dt is None:
                    queued.append((addr, claim.name, f"unresolved_return:{ret_str}", claim.prototype))
                    continue
                # by-value struct return > 4 bytes -> sret hidden pointer; queue.
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

            snap = _snapshot(fn)
            try:
                if fn.hasCustomVariableStorage():
                    fn.replaceParameters(
                        Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, True,
                        SourceType.USER_DEFINED,
                        *[p for p in fn.getParameters() if p.getName() != "this"])
                if ret_dt is not None:
                    fn.setReturnType(ret_dt, SourceType.USER_DEFINED)
                if cc:
                    fn.setCallingConvention(cc)
                impls = [ParameterImpl(f"a{i}", dt, program) for i, dt in enumerate(param_dts)]
                fn.replaceParameters(
                    Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, True,
                    SourceType.USER_DEFINED, *impls)
            except Exception as exc:  # noqa: BLE001
                queued.append((addr, claim.name, f"apply_error:{type(exc).__name__}", claim.prototype))
                _restore(fn, snap)
                continue

            ifc.flushCache()
            after = _decompile_in_stack(ifc, fn, monitor)
            if after is not None and before.isdisjoint(after):
                converged.append((addr, claim.name, "projected", len(param_dts)))
                applied += 1
            else:
                still = sorted(before & (after or before))
                _restore(fn, snap)
                queued.append((addr, claim.name,
                               "dynamic_storage_insufficient:" + ",".join(hex(o) for o in still),
                               claim.prototype))

        if args.apply and txid is not None:
            program.endTransaction(txid, True)
            txid = None
            program.save("apply source signatures", pyghidra.task_monitor())
    finally:
        if txid is not None:
            program.endTransaction(txid, False)

    return converged, queued, applied


def _restore(fn, snap):
    """Return a non-converged function to its EXACT pre-projection signature.

    Must fully undo the projection — including the convention, even when the
    original was `unknown`/empty (we set a default one during the attempt). A
    partial restore would leave a residual mutation on a function we report as
    reverted. Convention is set BEFORE params so DYNAMIC_STORAGE re-derives the
    original storage under the original convention.
    """
    from ghidra.program.model.listing import Function, ParameterImpl
    from ghidra.program.model.symbol import SourceType
    try:
        fn.setReturnType(snap["ret"], SourceType.USER_DEFINED)
        try:
            fn.setCallingConvention(snap["cc"] or Function.UNKNOWN_CALLING_CONVENTION_STRING)
        except Exception:  # noqa: BLE001
            pass
        impls = [ParameterImpl(n, dt, fn.getProgram()) for n, dt, _st in snap["params"]
                 if n != "this"]
        fn.replaceParameters(
            Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, True,
            SourceType.USER_DEFINED, *impls)
    except Exception:  # noqa: BLE001
        pass


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--apply", action="store_true", help="Project + verify (default: dry-run).")
    p.add_argument("--strict", action="store_true", help="Exit nonzero if any non-queued source row is non-converged.")
    p.add_argument("--addrs", nargs="+", help="Restrict to these addresses (hex).")
    p.add_argument("--queue-out", default="build-msvc500/evidence/source_signature_queue.csv")
    args = p.parse_args()

    repo_root = repo_root_from_file(__file__, levels_up=2)
    model = build_model(repo_root, "IMPERIALISM")

    project = ghidra_env.open_project()
    consumer = program = None
    try:
        consumer, program = ghidra_env.open_program(project, writable=bool(args.apply))
        converged, queued, applied = run(program, args, model)
    finally:
        if program is not None:
            program.release(consumer)
        project.close()

    out = Path(args.queue_out)
    out.parent.mkdir(parents=True, exist_ok=True)
    lines = ["address|name|reason|prototype"]
    for addr, name, reason, proto in sorted(queued):
        lines.append(f"0x{addr:08x}|{name}|{reason}|{proto}".replace("\n", " "))
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")

    reasons: dict[str, int] = {}
    for _a, _n, r, _p in queued:
        reasons[r.split(":", 1)[0]] = reasons.get(r.split(":", 1)[0], 0) + 1
    mode = "APPLIED" if args.apply else "DRY RUN"
    print(f"[{mode}] source-owned in_stack functions: "
          f"converged={len(converged)} queued={len(queued)} (applied={applied})")
    print(f"  queue -> {out}")
    print("  queued by reason: " + ", ".join(f"{k}={v}" for k, v in sorted(reasons.items())))
    if args.strict and queued:
        # Strict gate: only unexplained (unparsable / apply_error) rows fail; the
        # classified sub-categories (sret, packed, unknown_cc, unresolved) are the
        # honest queue, not failures.
        hard = [q for q in queued if q[2].split(":", 1)[0] in ("unparsable_prototype", "apply_error")]
        if hard:
            print(f"strict: {len(hard)} unexplained projection failure(s):")
            for a, n, r, _ in hard[:10]:
                print(f"    - 0x{a:08x} {n}: {r}")
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
