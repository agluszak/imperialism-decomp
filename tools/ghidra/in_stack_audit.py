#!/usr/bin/env python3
"""Read-only audit of Ghidra ``in_stack_*`` locals — evidence, NOT a param oracle.

An ``in_stack_0000000N`` is a read from a positive stack offset that the current
function model does not bind to a formal parameter. That is *evidence*, and it
has several possible causes — a genuinely missing parameter, but also a wrong
calling convention, a wrong function boundary, wrong stack-purge/RET metadata,
varargs, or stale decompiler state. It is not proof of a parameter.

The retired mutating fixer (``fix-in-stack-params --apply``) was unsound: it
treated every such slot as a proven USER_DEFINED parameter and appended it via
``Function.addParameter(ParameterImpl(None, dtype, offset, program))``. For a
function without custom variable storage, Ghidra IGNORES the supplied stack
offset and lets the calling convention place the parameter wherever it likes —
so the flagged slot never binds, and the next pass appends yet another parameter.
That, plus never flushing the decompiler cache between edits, produced the
spurious 261->151->136->127->112 "convergence" (an artifact, not real recovery).
Those appended parameters are unsound and were reverted from the DB.

This tool only *reports*. For every affected function it emits the evidence
needed to CLASSIFY (not blindly patch) the slot:

  address | qualified name | ownership (source/library/unported) | calling
  convention | custom-storage? | stack purge | current formal params + storage |
  each in_stack offset/size/type | source-model prototype (when known)

Buckets and the durable fix per bucket:
  - **source-owned** — the real prototype lives in the C++ declaration; fix it
    there and let ``ghidra-apply-source-full`` (PDB import) carry it into the DB.
    A direct DB patch is wrong: the next PDB import overwrites it.
  - **library** — prototype comes from the reviewed identity / PDB, not invention.
  - **unported, clean ABI evidence** — repair the *complete* Ghidra prototype via
    ``updateFunction(DYNAMIC_STORAGE_FORMAL_PARAMS)`` (calling convention allocates
    ordinary params), not by appending one variable. Verify by re-decompiling.
  - **unported, suspect** — varargs / unknown convention / purge-inconsistent /
    likely-wrong boundary: repair *that fact*, do not invent parameters.

Output: a summary + ``build-msvc500/evidence/in_stack_audit.csv``.

  uv run python -m tools.ghidra.in_stack_audit [--addr 0x..] [--limit N]
"""

from __future__ import annotations

import argparse
from pathlib import Path

from tools.common import ghidra_env
from tools.common.repo import repo_root_from_file
from tools.source_model import build_model


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Audit Ghidra in_stack_* locals (read-only).")
    p.add_argument("--addr", help="Only audit the function at this address (hex).")
    p.add_argument("--limit", type=int, default=0, help="Cap functions scanned (0 = all).")
    p.add_argument("--out", default="build-msvc500/evidence/in_stack_audit.csv")
    return p.parse_args()


def _make_decompiler(program):
    from ghidra.app.decompiler import DecompInterface, DecompileOptions

    ifc = DecompInterface()
    ifc.setOptions(DecompileOptions())
    ifc.setSimplificationStyle("decompile")
    if not ifc.openProgram(program):
        raise RuntimeError(f"openProgram failed: {ifc.getLastMessage()}")
    return ifc


def _in_stack_locals(hf):
    """[(offset, size, type_name)] for positive-offset in_stack_* non-param locals."""
    out = []
    it = hf.getLocalSymbolMap().getSymbols()
    while it.hasNext():
        sym = it.next()
        if "in_stack_" not in sym.getName() or sym.isParameter():
            continue
        st = sym.getStorage()
        if not st.isStackStorage():
            continue
        off = st.getStackOffset()
        if off <= 0:
            continue
        dt = sym.getDataType()
        out.append((off, dt.getLength() if dt else 0, dt.getName() if dt else "?"))
    return sorted(out)


def _classify(owned_kind, cc, is_varargs):
    if owned_kind == "source":
        return "source_owned"
    if owned_kind == "library":
        return "library"
    if is_varargs:
        return "unported_varargs"
    if not cc or cc in ("unknown", "default"):
        return "unported_unknown_cc"
    if cc.startswith("__cdecl"):
        return "unported_cdecl"
    return "unported_callee_cleaned"


def run(program, args, model) -> list[dict]:
    fm = program.getFunctionManager()
    af = program.getAddressFactory().getDefaultAddressSpace()
    ifc = _make_decompiler(program)
    import pyghidra

    monitor = pyghidra.task_monitor()

    if args.addr:
        fn = fm.getFunctionContaining(af.getAddress(int(args.addr, 16)))
        funcs = [fn] if fn is not None else []
    else:
        funcs = fm.getFunctions(True)

    rows: list[dict] = []
    scanned = 0
    for fn in funcs:
        if fn is None or fn.isThunk() or fn.isExternal():
            continue
        if args.limit and scanned >= args.limit:
            break
        scanned += 1
        res = ifc.decompileFunction(fn, 20, monitor)
        if not res.decompileCompleted():
            continue
        if "in_stack_" not in res.getDecompiledFunction().getC():
            continue
        hf = res.getHighFunction()
        if hf is None:
            continue
        in_stack = _in_stack_locals(hf)
        if not in_stack:
            continue

        addr = int(fn.getEntryPoint().getOffset())
        claim = model.functions.get(addr)
        if claim is None:
            owned_kind = "unported"
        elif claim.kind == "LIBRARY":
            owned_kind = "library"
        else:
            owned_kind = "source"
        cc = fn.getCallingConventionName() or ""
        params = [
            (p.getName(),
             p.getVariableStorage().getStackOffset()
             if p.getVariableStorage().isStackStorage() else "reg")
            for p in fn.getParameters()
        ]
        rows.append({
            "address": "0x{:08x}".format(addr),
            "name": fn.getName(True),
            "ownership": owned_kind,
            "cc": cc,
            "custom_storage": fn.hasCustomVariableStorage(),
            "stack_purge": fn.getStackPurgeSize(),
            "varargs": fn.hasVarArgs(),
            "nparams": len(params),
            "params": ";".join(f"{n}@{o}" for n, o in params),
            "in_stack": ";".join(f"0x{o:x}:{sz}:{t}" for o, sz, t in in_stack),
            "source_proto": claim.prototype if claim else "",
            "bucket": _classify(owned_kind, cc, fn.hasVarArgs()),
        })
    return rows


def main() -> int:
    args = parse_args()
    repo_root = repo_root_from_file(__file__, levels_up=2)
    model = build_model(repo_root, "IMPERIALISM")

    project = ghidra_env.open_project()
    consumer = program = None
    try:
        consumer, program = ghidra_env.open_program(project, writable=False)
        rows = run(program, args, model)
    finally:
        if program is not None:
            program.release(consumer)
        project.close()

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    fields = ["address", "name", "ownership", "cc", "custom_storage", "stack_purge",
              "varargs", "nparams", "params", "in_stack", "source_proto", "bucket"]
    lines = ["|".join(fields)]
    for r in rows:
        lines.append("|".join(str(r[f]).replace("|", " ") for f in fields))
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")

    buckets: dict[str, int] = {}
    owners: dict[str, int] = {}
    for r in rows:
        buckets[r["bucket"]] = buckets.get(r["bucket"], 0) + 1
        owners[r["ownership"]] = owners.get(r["ownership"], 0) + 1
    print(f"in_stack audit: {len(rows)} function(s) with unbound positive-stack reads")
    print(f"  wrote {out}")
    print("  by ownership: " + ", ".join(f"{k}={v}" for k, v in sorted(owners.items())))
    print("  by bucket:    " + ", ".join(f"{k}={v}" for k, v in sorted(buckets.items())))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
