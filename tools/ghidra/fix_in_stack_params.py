#!/usr/bin/env python3
"""One-time Ghidra pass: bind Ghidra's ``in_stack_*`` stack args as real parameters.

When Ghidra can't account for a stack read above the return address it surfaces it
as an ``in_stack_0000000N`` local instead of a parameter — so the autogen export
carries undeclared ``in_stack_*`` reads that don't compile and obscure the real
signature. For every such function this adds the unbound stack locations to the DB
function as real parameters (at their exact ``Stack[0xN]`` storage, with the type the
decompiler inferred), so a re-decompile names them ``param_N`` instead of
``in_stack_*``. (``commitParamsToDatabase`` alone does not help: the decompiler keeps
these as non-parameter locals, so the committed prototype never includes them.) After
a single ``--apply`` run + ``just sync-ghidra`` + autogen regen, ``in_stack_*`` is gone
everywhere — the proper fix, vs. text-patching each promoted body.

Read-only by default (reports the count); ``--apply`` opens the program writable and
saves. ``--addr 0x..`` targets one function; ``--limit N`` caps how many functions
are scanned (decompiled) for a quick trial.

Usage:
  uv run python -m tools.ghidra.fix_in_stack_params [--apply] [--addr 0x..] [--limit N]
"""

from __future__ import annotations

import argparse

import pyghidra

from tools.common import ghidra_env

_IN_STACK = "in_stack_"


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Commit Ghidra in_stack_* stack args as real params.")
    p.add_argument("--apply", action="store_true", help="Write changes to the Ghidra DB (default: dry-run).")
    p.add_argument("--addr", help="Only process the function at this address (hex).")
    p.add_argument("--limit", type=int, default=0, help="Cap how many functions are scanned (0 = all).")
    p.add_argument("--quiet", action="store_true", help="Don't list each fixed function.")
    return p.parse_args()


def _make_decompiler(program):
    from ghidra.app.decompiler import DecompInterface, DecompileOptions

    ifc = DecompInterface()
    ifc.setOptions(DecompileOptions())
    ifc.setSimplificationStyle("decompile")
    if not ifc.openProgram(program):
        raise RuntimeError(f"openProgram failed: {ifc.getLastMessage()}")
    return ifc


def _in_stack_symbols(hf):
    """Return [(stack_offset, dataType, name)] for the function's in_stack_* locals."""
    out = []
    sym_iter = hf.getLocalSymbolMap().getSymbols()
    while sym_iter.hasNext():
        sym = sym_iter.next()
        if "in_stack_" not in sym.getName() or sym.isParameter():
            continue
        storage = sym.getStorage()
        if not storage.isStackStorage():
            continue
        offset = storage.getStackOffset()
        if offset <= 0:  # params live above the return address (positive offsets)
            continue
        out.append((offset, sym.getDataType(), sym.getName()))
    return out


def _promote_in_stack_params(fn, hf, program) -> int:
    """Add the function's in_stack_* stack locations as real parameters. Returns count.

    Uses ``ParameterImpl`` with explicit stack storage so the auto ``this`` (ECX) and
    any existing parameters are preserved while the unbound stack slots become formal
    parameters at their recovered offsets/types (sorted by stack offset = call order).
    """
    from ghidra.program.model.listing import ParameterImpl
    from ghidra.program.model.symbol import SourceType

    syms = sorted(_in_stack_symbols(hf), key=lambda t: t[0])
    for offset, dtype, _ in syms:
        fn.addParameter(ParameterImpl(None, dtype, offset, program), SourceType.USER_DEFINED)
    return len(syms)


def run(program, args) -> dict:
    fm = program.getFunctionManager()
    af = program.getAddressFactory().getDefaultAddressSpace()
    ifc = _make_decompiler(program)
    monitor = pyghidra.task_monitor()

    if args.addr:
        addr = af.getAddress(int(args.addr, 16))
        fn = fm.getFunctionContaining(addr)
        funcs = [fn] if fn is not None else []
    else:
        funcs = fm.getFunctions(True)

    scanned = fixed = no_decomp = 0
    changed: list[str] = []
    for fn in funcs:
        if fn is None or fn.isThunk() or fn.isExternal():
            continue
        if args.limit and scanned >= args.limit:
            break
        scanned += 1
        res = ifc.decompileFunction(fn, 30, monitor)
        if not res.decompileCompleted():
            no_decomp += 1
            continue
        if _IN_STACK not in res.getDecompiledFunction().getC():
            continue
        hf = res.getHighFunction()
        if hf is None:
            continue
        n = len(_in_stack_symbols(hf))
        if n == 0:
            continue  # in_stack only appeared in a comment / non-stack context
        if args.apply:
            n = _promote_in_stack_params(fn, hf, program)
        fixed += 1
        if not args.quiet:
            changed.append(
                f"  0x{int(fn.getEntryPoint().getOffset()):08x}  {fn.getName()}  (+{n} param)"
            )

    return {"scanned": scanned, "fixed": fixed, "no_decomp": no_decomp, "changed": changed}


def main() -> int:
    args = parse_args()
    project = ghidra_env.open_project()
    consumer = None
    program = None
    txid = None
    try:
        consumer, program = ghidra_env.open_program(project, writable=bool(args.apply))
        if args.apply:
            txid = program.startTransaction("commit in_stack_* params")
        result = run(program, args)
        if args.apply:
            program.endTransaction(txid, True)
            txid = None
            program.save("commit in_stack_* params", pyghidra.task_monitor())

        mode = "APPLIED" if args.apply else "DRY RUN"
        for line in result["changed"][:5000]:
            print(line)
        print(
            f"\n[{mode}] scanned={result['scanned']} with_in_stack={result['fixed']} "
            f"decomp_failed={result['no_decomp']}"
        )
        if not args.apply:
            print("Re-run with --apply to commit the stack params, then `just sync-ghidra`.")
        return 0
    finally:
        if txid is not None:
            program.endTransaction(txid, False)
        if program is not None:
            program.release(consumer)
        project.close()


if __name__ == "__main__":
    raise SystemExit(main())
