#!/usr/bin/env python3
"""Run the template-emission compiler matrix (docs/toolchain.md) and inventory
which MFC template COMDATs each cell emits.

Compiles experiments/template_emission/{owner,user}.cpp inside the
imperialism-msvc500 container across the axes runnable with the vendored VC5 RTM
toolchain -- /Ob0 vs /Ob1 vs /Ob2, same-TU vs split-TU users, implicit vs
explicit owner mem-init, empty vs non-empty owner dtor, direct AddTail vs a
non-inline wrapper -- then parses each .obj's COFF symbol table host-side and
reports the COMDAT inventory (template-decorated symbols per TU).

The VS97 service-pack compiler axis needs alternate toolchain binaries that are
not vendored; when they are, add cells with a different image tag here.

usage:
  just template-emission-matrix            # run all cells, print report
  just template-emission-matrix --cells ob1_split ob2_split
"""

from __future__ import annotations

import argparse
import struct
import subprocess
import sys
from pathlib import Path

from tools.common.repo import repo_root_from_file

REPO_ROOT = repo_root_from_file(__file__)
OUT_ROOT = REPO_ROOT / "build-msvc500" / "template_emission"
IMAGE = "imperialism-msvc500"

# cell name -> extra cl flags (the /D axes select variants inside probe sources).
CELLS: dict[str, list[str]] = {
    "ob0_split": ["/Ob0"],
    "ob1_split": ["/Ob1"],
    "ob2_split": ["/Ob2"],
    "ob1_same_tu": ["/Ob1", "/DPROBE_SAME_TU"],
    "ob1_split_wrapper": ["/Ob1", "/DPROBE_USE_WRAPPER"],
    "ob1_split_explicit_init": ["/Ob1", "/DPROBE_EXPLICIT_INIT"],
    "ob1_split_nonempty_dtor": ["/Ob1", "/DPROBE_NONEMPTY_DTOR"],
}

IMAGE_SCN_LNK_COMDAT = 0x00001000


def parse_coff_comdat_symbols(obj_path: Path) -> list[str]:
    """External symbol names defined in COMDAT sections of a COFF object."""
    data = obj_path.read_bytes()
    machine, nsections, _ts, symtab_ptr, nsymbols, optsize, _flags = struct.unpack_from(
        "<HHIIIHH", data, 0)
    if machine not in (0x14C,):  # i386
        raise ValueError(f"{obj_path}: unexpected machine {machine:#x}")
    sec_off = 20 + optsize
    comdat_sections: set[int] = set()
    for i in range(nsections):
        off = sec_off + 40 * i
        characteristics = struct.unpack_from("<I", data, off + 36)[0]
        if characteristics & IMAGE_SCN_LNK_COMDAT:
            comdat_sections.add(i + 1)  # 1-based section numbers

    strtab_off = symtab_ptr + 18 * nsymbols

    def sym_name(entry_off: int) -> str:
        raw = data[entry_off:entry_off + 8]
        if raw[:4] == b"\x00\x00\x00\x00":
            str_off = struct.unpack_from("<I", raw, 4)[0]
            end = data.find(b"\x00", strtab_off + str_off)
            return data[strtab_off + str_off:end].decode("ascii", "replace")
        return raw.rstrip(b"\x00").decode("ascii", "replace")

    names: list[str] = []
    i = 0
    while i < nsymbols:
        off = symtab_ptr + 18 * i
        section, _value_type, storage_class, naux = struct.unpack_from(
            "<hHBB", data, off + 8 + 4)
        # layout: name[8] value[4] section[2] type[2] class[1] aux[1]
        section = struct.unpack_from("<h", data, off + 12)[0]
        storage_class = data[off + 16]
        naux = data[off + 17]
        if storage_class == 2 and section in comdat_sections:  # IMAGE_SYM_CLASS_EXTERNAL
            names.append(sym_name(off))
        i += 1 + naux
    return names


def run_cell(cell: str, flags: list[str]) -> None:
    OUT_ROOT.mkdir(parents=True, exist_ok=True)
    cmd = [
        "docker", "run", "--rm", "--network", "none",
        "-v", f"{REPO_ROOT}:/imperialism",
        "-v", f"{OUT_ROOT}:/build",
        "--entrypoint", "python3", IMAGE,
        "/imperialism/experiments/template_emission/container_compile.py",
        cell, *flags,
    ]
    subprocess.run(cmd, check=True, cwd=REPO_ROOT,
                   stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)


def summarize(name: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for tu in ("owner", "user"):
        obj = OUT_ROOT / name / f"{tu}.obj"
        if not obj.is_file():
            out[tu] = ["<missing .obj>"]
            continue
        template_syms = sorted(
            s for s in parse_coff_comdat_symbols(obj) if "?$CList@" in s)
        out[tu] = template_syms
    return out


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cells", nargs="*", default=list(CELLS))
    parser.add_argument("--no-run", action="store_true",
                        help="Inventory existing .objs without recompiling.")
    args = parser.parse_args()

    for cell in args.cells:
        if cell not in CELLS:
            print(f"unknown cell {cell!r}; known: {', '.join(CELLS)}", file=sys.stderr)
            return 2
        if not args.no_run:
            print(f"[compile] {cell}: cl {' '.join(CELLS[cell])}")
            run_cell(cell, CELLS[cell])

    print("\nTemplate COMDAT inventory (CList-decorated externals per TU):")
    baseline: dict[str, set[str]] | None = None
    for cell in args.cells:
        inv = summarize(cell)
        print(f"\n=== {cell} ({' '.join(CELLS[cell])}) ===")
        for tu, syms in inv.items():
            print(f"  {tu}.obj: {len(syms)} template COMDATs")
            for s in syms:
                print(f"    {s}")
        if baseline is None:
            baseline = {tu: set(syms) for tu, syms in inv.items()}
        else:
            for tu, syms in inv.items():
                added = set(syms) - baseline.get(tu, set())
                removed = baseline.get(tu, set()) - set(syms)
                if added:
                    print(f"  {tu}.obj vs {args.cells[0]}: +{len(added)} "
                          f"({', '.join(sorted(added)[:4])}...)"
                          if len(added) > 4 else
                          f"  {tu}.obj vs {args.cells[0]}: +{sorted(added)}")
                if removed:
                    print(f"  {tu}.obj vs {args.cells[0]}: -{sorted(removed)[:6]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
