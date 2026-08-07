#!/usr/bin/env python3
"""Clear custom PACKED parameter storage that the function's own stack purge contradicts.

``project-packed-signatures`` models sub-dword arguments tight-packed in one slot
(``CUSTOM_STORAGE``), because MSVC500 really does that for some frames. When it is applied to a
frame that is *not* packed, the result is storage that disagrees with the binary: the parameters
are recorded overlapping the wrong offsets while ``RET n`` says each one had its own dword slot.

The damage is quiet. Nothing fails to build, ``func-sig`` still prints a plausible prototype, and
the only visible symptom is downstream: the decompiler renders a dword read of the first slot as
``piece(a1, a0)`` -- splicing two parameters together -- so anything comparing call contracts
against that function sees an argument the recompiled side cannot produce. That is what
``just semantic-gate`` reports as a ``call_contract`` mismatch on the *caller*.

The check here is arithmetic and does not need a listing: with dword-aligned formal parameters,
the purge is ``4 * len(params)`` for ``__stdcall``/``__thiscall``-with-purge. If the recorded
purge equals that and the storage is packed tighter, the packing is wrong -- the binary is the
authority, and it already told us how many slots it popped.

Clearing custom storage and re-applying ``DYNAMIC_STORAGE_FORMAL_PARAMS`` lets the calling
convention place them, which is the correct model for an unpacked frame.

  just fix-packed-storage --addrs 0x559a70 [--apply]

Dry-run by default. After ``--apply``, run ``just export-project`` (the ledger:
docs/ghidra-db-mutations.md).
"""

from __future__ import annotations

import argparse
from typing import Sequence

from tools.common import ghidra_env


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--addrs", nargs="+", required=True, help="Function entry points (hex).")
    parser.add_argument("--apply", action="store_true", help="Write the DB (default: dry run).")
    return parser.parse_args(argv)


def packed_conflict(function) -> str | None:
    """Describe the conflict when custom storage is tighter than the purge allows."""
    if not function.hasCustomVariableStorage():
        return None
    parameters = list(function.getParameters())
    if not parameters:
        return None
    purge = function.getStackPurgeSize()
    if purge <= 0:
        return None
    # Only stack parameters count toward the purge; a `this` in ECX does not.
    stack_parameters = [
        p for p in parameters if p.getVariableStorage().isStackStorage()
    ]
    if not stack_parameters:
        return None
    expected = 4 * len(stack_parameters)
    if purge != expected:
        return None
    offsets = [p.getVariableStorage().getStackOffset() for p in stack_parameters]
    first = min(offsets)
    aligned = [first + 4 * index for index in range(len(stack_parameters))]
    if sorted(offsets) == aligned:
        return None
    return (
        f"purge {purge} == 4 * {len(stack_parameters)} stack parameter(s), so each had its own "
        f"dword slot, but storage is at {sorted(offsets)} instead of {aligned}"
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    project = ghidra_env.open_project()
    consumer = program = None
    changed = 0
    try:
        consumer, program = ghidra_env.open_program(project, writable=args.apply)
        manager = program.getFunctionManager()
        space = program.getAddressFactory().getDefaultAddressSpace()
        from ghidra.program.model.symbol import SourceType
        from ghidra.program.model.listing import Function

        for text in args.addrs:
            address = space.getAddress(int(text, 16))
            function = manager.getFunctionAt(address)
            if function is None:
                print(f"{text}: no function at that address")
                continue
            conflict = packed_conflict(function)
            if conflict is None:
                print(f"{text} {function.getName()}: storage is consistent with the purge")
                continue
            print(f"{text} {function.getName()}: {conflict}")
            if not args.apply:
                continue
            transaction = program.startTransaction("clear packed parameter storage")
            try:
                # Overload order is (convention, return, updateType, force, source, params...).
                function.updateFunction(
                    function.getCallingConventionName(),
                    function.getReturn(),
                    Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                    True,
                    SourceType.USER_DEFINED,
                    list(function.getParameters()),
                )
            finally:
                program.endTransaction(transaction, True)
            after = [
                (p.getName(), p.getVariableStorage().getStackOffset())
                for p in function.getParameters()
                if p.getVariableStorage().isStackStorage()
            ]
            print(f"  re-allocated: {after}")
            changed += 1
        if args.apply and changed:
            program.save("clear packed parameter storage", None)
    finally:
        if program is not None:
            program.release(consumer)
        project.close()
    if args.apply and changed:
        print(f"{changed} function(s) updated; run `just export-project` to persist")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
