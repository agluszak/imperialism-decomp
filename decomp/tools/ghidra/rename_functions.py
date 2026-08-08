#!/usr/bin/env python3
"""Rename existing Ghidra function entries without changing their boundaries.

This is the surgical counterpart to ``apply_source`` for entries whose canonical
source name is not a legal Ghidra identifier (notably VC5 compiler-generated
names containing spaces/backticks).  Dry-run by default; pass ``--apply`` to
write and save the project.

usage:
  rename_functions 0xADDR=LegalGhidraName [0xADDR=Name ...] [--apply]
"""

from __future__ import annotations

import argparse
import re

from tools.common import ghidra_env


LEGAL_NAME = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$@?]*$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("renames", nargs="+", metavar="0xADDR=NAME")
    parser.add_argument(
        "--apply", action="store_true", help="Rename and save (default: dry-run)."
    )
    return parser.parse_args()


def parse_rename(text: str) -> tuple[int, str]:
    address_text, separator, name = text.partition("=")
    if not separator or not name or not LEGAL_NAME.fullmatch(name):
        raise ValueError(f"expected 0xADDR=LegalGhidraName, got {text!r}")
    return int(address_text, 16), name


def main() -> int:
    args = parse_args()
    try:
        renames = [parse_rename(text) for text in args.renames]
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    import pyghidra

    project = ghidra_env.open_project()
    from ghidra.program.model.symbol import SourceType
    consumer, program = ghidra_env.open_program(project, writable=args.apply)
    try:
        address_space = program.getAddressFactory().getDefaultAddressSpace()
        function_manager = program.getFunctionManager()
        plan = []
        missing = []
        for address, name in renames:
            function = function_manager.getFunctionAt(address_space.getAddress(address))
            if function is None:
                print(f"0x{address:08x}: no function at entry")
                missing.append(address)
                continue
            old_name = function.getName()
            if old_name == name:
                print(f"0x{address:08x}: already {name}")
                continue
            print(f"0x{address:08x}: would rename {old_name} -> {name}")
            plan.append((function, name))

        if missing:
            return 1
        if not args.apply:
            print("dry-run; pass --apply to rename + save")
            return 0
        if not plan:
            return 0

        transaction = program.startTransaction("rename function entries")
        try:
            for function, name in plan:
                function.setName(name, SourceType.USER_DEFINED)
        finally:
            program.endTransaction(transaction, True)
        program.getDomainFile().save(pyghidra.task_monitor())
        print(f"renamed {len(plan)} function(s); saved program — run `just export-project`")
        return 0
    finally:
        program.release(consumer)
        project.close()


if __name__ == "__main__":
    raise SystemExit(main())
