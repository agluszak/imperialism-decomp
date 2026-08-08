#!/usr/bin/env python3
"""Recover the ORIGINAL module (source-file) layout of Imperialism.exe.

The retail binary embeds its assert-macro path strings ("D:\\Ambit\\Cross\\UMap.cpp"
etc. — 49 distinct .cpp modules). Each path string's code references are assert
callsites *inside that module*, and the 1997 linker laid modules out contiguously
in link order, so the referencing-function addresses sample each module's .text
extent. Empirically the sampled extents are strictly ordered with zero overlaps,
which makes the table below a faithful module segmentation of the binary.

Output (pipe-CSV on stdout):

  module|n_samples|sample_lo|sample_hi|extent_hi_exclusive

``sample_lo``/``sample_hi`` are hard evidence (real assert callsites).
``extent_hi_exclusive`` is the next module's ``sample_lo`` — everything in
[sample_lo, extent_hi_exclusive) belongs to this module unless the true boundary
falls in the unsampled tail [sample_hi, extent_hi_exclusive), so treat addresses
in that tail as "this module, tail-uncertain". Header paths (.h) are excluded:
their asserts inline into *other* modules and would scatter the segmentation.

usage: original-modules [--samples]
  --samples   additionally print every sample row: sample|module|func_addr
"""

from __future__ import annotations

import re

MODULE_PATH_RE = re.compile(r"^[A-Za-z]:\\+Ambit\\+.*\.cpp$", re.IGNORECASE)


def module_name(path: str) -> str:
    tail = path.replace("\\\\", "\\").split("\\Ambit\\", 1)[-1]
    return tail.replace("\\", "/")


def defined_module_strings(program):
    """Yield (address_int, module_name) for every assert-path string datum."""
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
        if MODULE_PATH_RE.match(text):
            yield data.getAddress(), module_name(text)


def run(program, argv: list[str]) -> int:
    want_samples = "--samples" in argv
    listing = program.getListing()
    refman = program.getReferenceManager()

    samples: dict[str, set[int]] = {}
    for addr, mod in defined_module_strings(program):
        for ref in refman.getReferencesTo(addr):
            func = listing.getFunctionContaining(ref.getFromAddress())
            if func is None:
                continue
            entry = int(str(func.getEntryPoint()), 16)
            samples.setdefault(mod, set()).add(entry)

    rows = sorted(
        (min(funcs), max(funcs), len(funcs), mod) for mod, funcs in samples.items()
    )
    overlaps = sum(1 for i in range(1, len(rows)) if rows[i][0] < rows[i - 1][1])
    print(f"# {len(rows)} modules from assert-path evidence; {overlaps} extent overlap(s)")
    print("module|n_samples|sample_lo|sample_hi|extent_hi_exclusive")
    for i, (lo, hi, n, mod) in enumerate(rows):
        nxt = rows[i + 1][0] if i + 1 < len(rows) else 0
        nxt_txt = f"0x{nxt:08x}" if nxt else ""
        print(f"{mod}|{n}|0x{lo:08x}|0x{hi:08x}|{nxt_txt}")

    if want_samples:
        for lo, hi, n, mod in rows:
            for entry in sorted(samples[mod]):
                print(f"sample|{mod}|0x{entry:08x}")
    return 0
