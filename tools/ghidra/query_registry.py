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

from collections.abc import Callable

from tools.ghidra import (
    decompile_one,
    jumptable,
    linear_disasm,
    listing_one,
    raw_disasm,
    search_whole_binary,
    vtable_dump,
    xrefs_to,
)

COMMANDS: dict[str, Callable] = {
    "listing": listing_one.run,
    "xrefs": xrefs_to.run,
    "search": search_whole_binary.run,
    "linear-disasm": linear_disasm.run,
    "raw-disasm": raw_disasm.run,
    "jumptable": jumptable.run,
    "decompile": decompile_one.run,
    "vtable-dump": vtable_dump.run,
}


def usage_line() -> str:
    return f"commands: {', '.join(sorted(COMMANDS))}"
