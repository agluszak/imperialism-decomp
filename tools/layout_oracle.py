#!/usr/bin/env python3
"""MSVC500 layout oracle: physical record layouts as BUILD EVIDENCE from VC5 itself.

Host Clang must never be the layout authority — the physical truth is whatever the
actual MSVC500 toolchain lays out. This module generates a TU from the record
model (`tools.class_model`), compiles it with the SAME container/toolchain/flags
as the game (`imperialism-msvc500`, default /Zp8 packing, /GX /GR-), runs the
resulting console exe under the container's Wine, and parses its output into
layout facts:

    RECORD|<qualified>|<sizeof>
    BASE|<qualified>|<base>|<offset>
    FIELD|<qualified>|<field>|<offset>|<size>

Offsets are measured by the compiled program itself (`&((T*)16)->f - 16` /
derived->base pointer conversion), so every number is compiler output, not
hand-written metadata and not a host-clang guess.

Skipped by construction (recorded in the JSON as `skipped`):
  - bitfields and reference members (cannot take their address);
  - virtual bases (static derived->base conversion needs a real object).

  uv run python -m tools.layout_oracle --out build-msvc500/generated/layout_oracle.json
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import tempfile
from pathlib import Path

from tools.class_model import load_record_model

_DOCKER_IMAGE = "imperialism-msvc500:latest"
# Layout-relevant flags mirror the game's CMake baseline: /GX (EH), /GR- (no RTTI);
# packing stays the VC5 default /Zp8 exactly as the real build.
_CL_FLAGS = ["/nologo", "/GX", "/GR-"]


def _sanitize(qn: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "_", qn)


def generate_oracle_tu(model: dict, repo_root: Path) -> tuple[str, dict]:
    """Return (cpp_source, skipped) for the layout-oracle TU.

    `skipped` maps qualified_name -> [reason strings] for members the oracle cannot
    measure; the apply pass must treat those as layout gaps, not zero-offset facts.
    """
    headers = sorted(p.name for p in (repo_root / "include" / "game").glob("*.h"))
    lines = [
        "// GENERATED layout oracle — compiled by the real MSVC500 container.",
        "// Access is widened so private/protected members stay addressable; MSVC",
        "// lays out strictly in declaration order, so this does not change layout.",
        "#define private public",
        "#define protected public",
        "#include <stdio.h>",
    ]
    # Include via the SAME `game/...` spelling the codebase itself uses: VC5's
    # `#pragma once` dedupes by include spelling, so reaching a header both as
    # "TFoo.h" and "game/TFoo.h" would redefine every type in it (C2011 storm).
    lines += [f'#include "game/{h}"' for h in headers]
    lines.append("")

    skipped: dict = {}
    dumpers: list[str] = []
    for qn, rec in sorted(model.items()):
        fn = f"dump_{_sanitize(qn)}"
        body = [f"static void {fn}(void) {{"]
        body.append(f'    printf("RECORD|{qn}|%u\\n", (unsigned)sizeof({qn}));')
        for b in rec.bases:
            if b.is_virtual:
                skipped.setdefault(qn, []).append(f"virtual_base:{b.type}")
                continue
            body.append(
                f'    printf("BASE|{qn}|{b.type}|%u\\n", '
                f"(unsigned)((char*)({b.type}*)({qn}*)16 - (char*)16));")
        for f in rec.fields:
            if f.is_bitfield:
                skipped.setdefault(qn, []).append(f"bitfield:{f.name}")
                continue
            if "&" in f.type:
                skipped.setdefault(qn, []).append(f"reference:{f.name}")
                continue
            if re.search(r"\[0?\]", f.type):
                # Zero-length / unsized trailing array: sizeof is ill-formed (C2070)
                # but the offset is still measurable; record size 0.
                body.append(
                    f'    printf("FIELD|{qn}|{f.name}|%u|0\\n", '
                    f"(unsigned)((char*)&(({qn}*)16)->{f.name} - (char*)16));")
                continue
            body.append(
                f'    printf("FIELD|{qn}|{f.name}|%u|%u\\n", '
                f"(unsigned)((char*)&(({qn}*)16)->{f.name} - (char*)16), "
                f"(unsigned)sizeof((({qn}*)16)->{f.name}));")
        body.append("}")
        dumpers.append(fn)
        lines.extend(body)

    # External (non-game) base classes — MFC etc.: the oracle compiles against the
    # real VC5 MFC headers, so sizeof(base) there is build evidence for the base
    # subobject extent inside derived game records. Sizes only; MFC internals stay
    # library-owned.
    ext_bases = sorted({b.type for r in model.values() for b in r.bases
                        if b.type not in model and not b.is_virtual})
    if ext_bases:
        lines.append("static void dump_external_bases(void) {")
        for eb in ext_bases:
            lines.append(f'    printf("EXTBASE|{eb}|%u\\n", (unsigned)sizeof({eb}));')
        lines.append("}")
        dumpers.append("dump_external_bases")

    # Keep each caller small — VC5 copes better with many small functions than one
    # giant main().
    lines.append("")
    group = 100
    for gi in range(0, len(dumpers), group):
        lines.append(f"static void dump_group_{gi // group}(void) {{")
        lines += [f"    {d}();" for d in dumpers[gi:gi + group]]
        lines.append("}")
    lines.append("int main(void) {")
    lines += [f"    dump_group_{gi // group}();" for gi in range(0, len(dumpers), group)]
    lines.append("    return 0;")
    lines.append("}")
    return "\n".join(lines) + "\n", skipped


def run_oracle(cpp: str, repo_root: Path, keep_dir: Path | None = None) -> str:
    """Compile+run the oracle TU in the MSVC500 container; return raw stdout."""
    work = keep_dir or Path(tempfile.mkdtemp(prefix="layout_oracle_"))
    work.mkdir(parents=True, exist_ok=True)
    (work / "oracle.cpp").write_text(cpp, encoding="utf-8")
    flags = " ".join(_CL_FLAGS)
    script = (
        f"wine C:/msvc/bin/CL.EXE {flags} "
        "/I 'Z:\\\\imperialism\\\\include' "
        "oracle.cpp > cl.log 2>&1; "
        "status=$?; tail -25 cl.log >&2; "
        "if [ ! -f oracle.exe ]; then echo ORACLE_COMPILE_FAILED >&2; exit 1; fi; "
        "wine ./oracle.exe 2>/dev/null"
    )
    cmd = [
        "docker", "run", "--rm", "--network", "none",
        "--entrypoint", "/bin/sh",
        # Same include order as the real game build (entrypoint.py): the DirectX 5
        # SDK precedes the toolchain so its dplay.h wins; IDirectPlay2 etc. resolve.
        "-e", r"INCLUDE=C:\dxsdk\include;C:\msvc\include;C:\msvc\mfc\include;C:\msvc\atl\include",
        "-e", r"LIB=C:\msvc\lib;C:\msvc\mfc\lib",
        "-e", r"WINEPATH=C:\msvc\bin;C:\msvc\redist",
        "-v", f"{repo_root}:/imperialism:ro",
        "-v", f"{work}:/work", "-w", "/work",
        _DOCKER_IMAGE, "-c", script,
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if "ORACLE_COMPILE_FAILED" in proc.stderr or proc.returncode != 0 and not proc.stdout:
        raise RuntimeError(
            f"layout oracle compile/run failed (rc={proc.returncode}):\n{proc.stderr[-4000:]}")
    return proc.stdout


def parse_oracle_output(raw: str) -> tuple[dict, dict]:
    """stdout -> ({qualified: {size, bases:{type:off}, fields:{name:{offset,size}}}},
    {external_base: size})."""
    out: dict = {}
    ext: dict = {}
    for line in raw.splitlines():
        # pipe-split-ok: parsing the oracle exe's own stdout protocol, not a config table
        parts = line.strip().split("|")
        if parts[0] == "RECORD" and len(parts) == 3:
            out.setdefault(parts[1], {"size": None, "bases": {}, "fields": {}})
            out[parts[1]]["size"] = int(parts[2])
        elif parts[0] == "BASE" and len(parts) == 4:
            out.setdefault(parts[1], {"size": None, "bases": {}, "fields": {}})
            out[parts[1]]["bases"][parts[2]] = int(parts[3])
        elif parts[0] == "FIELD" and len(parts) == 5:
            out.setdefault(parts[1], {"size": None, "bases": {}, "fields": {}})
            out[parts[1]]["fields"][parts[2]] = {"offset": int(parts[3]), "size": int(parts[4])}
        elif parts[0] == "EXTBASE" and len(parts) == 3:
            ext[parts[1]] = int(parts[2])
    return out, ext


def main() -> int:
    from tools.common.repo import repo_root_from_file

    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--model", default="build-msvc500/generated/record_model.json")
    p.add_argument("--out", default="build-msvc500/generated/layout_oracle.json")
    p.add_argument("--emit-only", metavar="CPP",
                   help="Only write the generated TU to this path; no compile.")
    p.add_argument("--keep-work", metavar="DIR",
                   help="Keep the compile work dir (oracle.cpp, cl.log, exe) here.")
    args = p.parse_args()

    repo_root = repo_root_from_file(__file__, levels_up=1)
    model = load_record_model(repo_root / args.model)
    cpp, skipped = generate_oracle_tu(model, repo_root)

    if args.emit_only:
        Path(args.emit_only).write_text(cpp, encoding="utf-8")
        print(f"oracle TU -> {args.emit_only} ({len(model)} records; "
              f"{sum(len(v) for v in skipped.values())} skipped members)")
        return 0

    raw = run_oracle(cpp, repo_root, keep_dir=Path(args.keep_work) if args.keep_work else None)
    layout, ext_bases = parse_oracle_output(raw)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"layouts": layout, "external_bases": ext_bases,
                               "skipped": skipped},
                              indent=1, sort_keys=True) + "\n", encoding="utf-8")

    n_fields = sum(len(v["fields"]) for v in layout.values())
    missing = sorted(set(model) - set(layout))
    print(f"layout oracle: {len(layout)}/{len(model)} records, {n_fields} field offsets, "
          f"{len(ext_bases)} external base sizes -> {out}")
    if missing:
        print(f"  MISSING from oracle output ({len(missing)}): {missing[:10]}{'...' if len(missing) > 10 else ''}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
