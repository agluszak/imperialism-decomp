#!/usr/bin/env python3
"""
Inventory MSVC500 toolchain payload and build curated FID input lists.

Outputs:
  - manifest markdown summary
  - full lib list
  - phase1 prioritized lib list
  - phase2 remaining lib list
  - non-x86 / alternate-arch lib list

Usage:
  .venv/bin/python new_scripts/inventory_msvc500_toolchain.py \
    --toolchain-root msvc500-master \
    --out-dir tmp_decomp
"""

from __future__ import annotations

import argparse
import re
from collections import Counter, defaultdict
from pathlib import Path


ALT_ARCH_MARKERS = (
    "/alpha/",
    "/mips/",
    "/ppc/",
    "/mppc/",
    "/m68k/",
    "/l.chs/",
    "/l.cht/",
    "/l.deu/",
    "/l.esp/",
    "/l.fra/",
    "/l.ita/",
    "/l.jpn/",
    "/l.kor/",
)

PHASE1_NAME_PATTERNS = [
    re.compile(r"^libc(?:mt|mtd|)$", re.I),
    re.compile(r"^libcp(?:mt|mtd|)$", re.I),
    re.compile(r"^oldnames$", re.I),
    re.compile(r"^msvcrt(?:d|)$", re.I),
    re.compile(r"^msvcirt$", re.I),
    re.compile(r"^mfc42(?:d|u|ud|)$", re.I),
    re.compile(r"^nafx(?:cw|cwd|)$", re.I),
    re.compile(r"^uafxc(?:w|wd)$", re.I),
    re.compile(r"^mfcs42(?:d|u|ud|)$", re.I),
]


def is_alt_arch(path: Path) -> bool:
    s = str(path).replace("\\", "/").lower()
    return any(m in s for m in ALT_ARCH_MARKERS)


def lib_stem(path: Path) -> str:
    return path.stem.lower()


def is_phase1_name(stem: str) -> bool:
    return any(pat.match(stem) for pat in PHASE1_NAME_PATTERNS)


def categorize(path: Path, root: Path) -> str:
    rel = path.relative_to(root).as_posix().lower()
    if rel.startswith("mfc/lib/"):
        return "mfc_lib"
    if rel.startswith("atl/"):
        return "atl"
    if rel.startswith("lib/"):
        return "crt_sdk_lib"
    if rel.startswith("vc/"):
        return "vc"
    if rel.startswith("include/"):
        return "sdk_include"
    if rel.startswith("mfc/include/"):
        return "mfc_include"
    if rel.startswith("mfc/src/"):
        return "mfc_src"
    if rel.startswith("redist/"):
        return "redist"
    if rel.startswith("bin/"):
        return "bin"
    return "other"


def write_lines(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--toolchain-root",
        default="msvc500-master",
        help="Path to msvc500 toolchain root",
    )
    ap.add_argument(
        "--out-dir",
        default="tmp_decomp",
        help="Directory for generated inventory outputs",
    )
    args = ap.parse_args()

    root = Path(args.toolchain_root).resolve()
    out_dir = Path(args.out_dir).resolve()
    if not root.exists():
        raise SystemExit(f"missing toolchain root: {root}")

    all_files = [p for p in root.rglob("*") if p.is_file()]
    libs = sorted([p for p in all_files if p.suffix.lower() == ".lib"])
    dlls = sorted([p for p in all_files if p.suffix.lower() == ".dll"])
    headers = sorted([p for p in all_files if p.suffix.lower() == ".h"])
    cpps = sorted([p for p in all_files if p.suffix.lower() in (".c", ".cpp", ".cxx")])

    cat_counts = Counter()
    for p in all_files:
        cat_counts[categorize(p, root)] += 1

    lib_by_cat: dict[str, list[Path]] = defaultdict(list)
    for lib in libs:
        lib_by_cat[categorize(lib, root)].append(lib)

    phase1: list[Path] = []
    phase2: list[Path] = []
    alt_arch: list[Path] = []

    for lib in libs:
        if is_alt_arch(lib):
            alt_arch.append(lib)
            continue
        if is_phase1_name(lib_stem(lib)):
            phase1.append(lib)
        else:
            phase2.append(lib)

    full_lib_lines = [str(p.relative_to(root)) for p in libs]
    phase1_lines = [str(p.relative_to(root)) for p in phase1]
    phase2_lines = [str(p.relative_to(root)) for p in phase2]
    alt_arch_lines = [str(p.relative_to(root)) for p in alt_arch]

    manifest_lines: list[str] = []
    manifest_lines.append("# MSVC500 Toolchain Inventory")
    manifest_lines.append("")
    manifest_lines.append(f"- Toolchain root: `{root}`")
    manifest_lines.append(f"- Total files: `{len(all_files)}`")
    manifest_lines.append(f"- `.lib` files: `{len(libs)}`")
    manifest_lines.append(f"- `.dll` files: `{len(dlls)}`")
    manifest_lines.append(f"- Header files (`.h`): `{len(headers)}`")
    manifest_lines.append(f"- Source files (`.c/.cpp/.cxx`): `{len(cpps)}`")
    manifest_lines.append("")
    manifest_lines.append("## Category Counts")
    for k in sorted(cat_counts):
        manifest_lines.append(f"- `{k}`: `{cat_counts[k]}`")
    manifest_lines.append("")
    manifest_lines.append("## Library Counts")
    for k in sorted(lib_by_cat):
        manifest_lines.append(f"- `{k}`: `{len(lib_by_cat[k])}`")
    manifest_lines.append("")
    manifest_lines.append("## FID Input Sets")
    manifest_lines.append(f"- Phase1 prioritized libs: `{len(phase1)}`")
    manifest_lines.append(f"- Phase2 remaining libs: `{len(phase2)}`")
    manifest_lines.append(f"- Alt-arch filtered libs: `{len(alt_arch)}`")
    manifest_lines.append("")
    manifest_lines.append("## Phase1 Preview (first 40)")
    for rel in phase1_lines[:40]:
        manifest_lines.append(f"- `{rel}`")
    manifest_lines.append("")
    manifest_lines.append("## Alt-Arch Preview (first 30)")
    for rel in alt_arch_lines[:30]:
        manifest_lines.append(f"- `{rel}`")

    write_lines(out_dir / "msvc500_toolchain_manifest.md", manifest_lines)
    write_lines(out_dir / "msvc500_all_libs.txt", full_lib_lines)
    write_lines(out_dir / "msvc500_fid_phase1_libs.txt", phase1_lines)
    write_lines(out_dir / "msvc500_fid_phase2_libs.txt", phase2_lines)
    write_lines(out_dir / "msvc500_fid_alt_arch_libs.txt", alt_arch_lines)

    print(f"[done] root={root}")
    print(
        f"[counts] files={len(all_files)} libs={len(libs)} dlls={len(dlls)} "
        f"headers={len(headers)} sources={len(cpps)}"
    )
    print(
        f"[fid_sets] phase1={len(phase1)} phase2={len(phase2)} alt_arch={len(alt_arch)}"
    )
    print(f"[out] {out_dir / 'msvc500_toolchain_manifest.md'}")
    print(f"[out] {out_dir / 'msvc500_fid_phase1_libs.txt'}")
    print(f"[out] {out_dir / 'msvc500_fid_phase2_libs.txt'}")
    print(f"[out] {out_dir / 'msvc500_fid_alt_arch_libs.txt'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
