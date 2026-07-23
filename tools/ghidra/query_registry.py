#!/usr/bin/env python3
"""Registry of read-only Ghidra query commands shared by the one-shot client and
the persistent daemon.

Each command is a `run(program, argv) -> int` function that prints to stdout and
never opens or closes the project/program itself — the caller owns the handles.
That contract is what lets the daemon keep one JVM + program open across queries
(the ~60-90s pyghidra startup is the dominant cost of every one-shot invocation).

Add a command by giving its module a `run(program, argv)` and listing it here.
"""

from __future__ import annotations

import sys
from collections.abc import Callable

from tools.ghidra import (
    data_function_pointers,
    decompile_one,
    portprep,
    field_xrefs,
    func_sig,
    function_slice,
    jumptable,
    linear_disasm,
    listing_one,
    original_module_map,
    raw_disasm,
    read_data,
    search_whole_binary,
    string_refs_oracle,
    vtable_abi_evidence,
    vtable_dump,
    xrefs_to,
)

COMMANDS: dict[str, Callable] = {
    "data-function-pointers": data_function_pointers.run,
    "listing": listing_one.run,
    "original-modules": original_module_map.run,
    "portprep": portprep.run,
    "xrefs": xrefs_to.run,
    "search": search_whole_binary.run,
    "linear-disasm": linear_disasm.run,
    "raw-disasm": raw_disasm.run,
    "jumptable": jumptable.run,
    "decompile": decompile_one.run,
    "vtable-abi-evidence": vtable_abi_evidence.run,
    "vtable-dump": vtable_dump.run,
    "read-data": read_data.run,
    "function-slice": function_slice.run,
    "func-sig": func_sig.run,
    "field-xrefs": field_xrefs.run,
    "string-oracle": string_refs_oracle.run,
}


def usage_line() -> str:
    return f"commands: {', '.join(sorted(COMMANDS))}"


def command_help(cmd: str) -> str:
    """The command module's docstring (run() functions never parse --help)."""
    doc = sys.modules[COMMANDS[cmd].__module__].__doc__ or ""
    return doc.strip()
