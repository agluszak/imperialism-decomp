#!/usr/bin/env python3
"""Unported functions that reference string literals — they largely name themselves.

Iterates every defined string in the binary, maps its references to containing
functions, and reports functions with no manual owner (per
config/function_ownership.csv) together with the strings they reference. A
function that is the ONLY referencer of a distinctive literal ("Cannot load
tariff table %d") is a self-naming port target; the strings also make good
`// STRING:` annotations once ported.

usage: string-oracle [--min-len N] [--max-refs N] [--limit N] [--all]
  --min-len   minimum string length to consider (default 5)
  --max-refs  only count strings referenced by at most N functions (default 2;
              widely-shared literals like "" carry no naming signal)
  --limit     max functions to print (default 100)
  --all       include functions that already have a manual owner
"""

from __future__ import annotations

import sys

from tools.common import ghidra_env
from tools.common.repo import repo_root_from_file
from tools.common.symbols import ownership_by_address


def manual_owned_addrs(repo_root) -> set[int]:
    return {
        addr
        for addr, ownership in ownership_by_address(repo_root).items()
        if ownership in ("manual", "library")
    }


def opt(argv: list[str], flag: str, default: int) -> int:
    if flag in argv:
        return int(argv[argv.index(flag) + 1])
    return default


def defined_strings(program, min_len: int):
    """Yield (address_int, python_string) for every defined string datum."""
    it = program.getListing().getDefinedData(True)
    while it.hasNext():
        data = it.next()
        dt_name = data.getDataType().getName().lower()
        if "string" not in dt_name and "unicode" not in dt_name:
            continue
        try:
            value = data.getValue()
        except Exception:  # noqa: BLE001 - Ghidra data decode is best-effort
            continue
        if value is None:
            continue
        text = str(value)
        if len(text) < min_len:
            continue
        yield int(str(data.getAddress()), 16), text


def run(program, argv: list[str]) -> int:
    min_len = opt(argv, "--min-len", 5)
    max_refs = opt(argv, "--max-refs", 2)
    limit = opt(argv, "--limit", 100)
    include_owned = "--all" in argv

    repo_root = repo_root_from_file(__file__)
    owned = manual_owned_addrs(repo_root)

    rm = program.getReferenceManager()
    fm = program.getFunctionManager()
    af = program.getAddressFactory().getDefaultAddressSpace()

    by_fn: dict[int, list[str]] = {}
    fn_names: dict[int, str] = {}
    fn_sizes: dict[int, int] = {}
    for addr_int, text in defined_strings(program, min_len):
        refs = list(rm.getReferencesTo(af.getAddress(addr_int)))
        holders: set[int] = set()
        for ref in refs:
            fn = fm.getFunctionContaining(ref.getFromAddress())
            if fn is not None:
                holders.add(int(str(fn.getEntryPoint()), 16))
        if not holders or len(holders) > max_refs:
            continue
        uniq = "!" if len(holders) == 1 else ""
        for entry in holders:
            if entry not in fn_names:
                fn = fm.getFunctionContaining(af.getAddress(entry))
                fn_names[entry] = fn.getName(True)
                fn_sizes[entry] = fn.getBody().getNumAddresses()
            preview = text[:60].replace("\n", "\\n").replace("|", "\\x7c")
            by_fn.setdefault(entry, []).append(f'{uniq}"{preview}"')

    rows = [
        (entry, strings)
        for entry, strings in by_fn.items()
        if include_owned or entry not in owned
    ]
    # Unique-string holders first, then bigger functions (more port value).
    rows.sort(key=lambda kv: (-sum(s.startswith("!") for s in kv[1]), -fn_sizes[kv[0]]))

    print(f"{len(rows)} candidate functions "
          f"(min-len={min_len}, max-refs={max_refs}, owned included={include_owned})")
    print("address|size|name|strings ('!' = sole referencer)")
    for entry, strings in rows[:limit]:
        print(f"0x{entry:08x}|{fn_sizes[entry]}|{fn_names[entry]}|{' '.join(strings[:6])}")
    if len(rows) > limit:
        print(f"... {len(rows) - limit} more (raise --limit)")
    return 0


def main() -> int:
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
