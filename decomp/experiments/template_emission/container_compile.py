#!/usr/bin/env python3
"""In-container compile step for the template-emission matrix.

Runs inside the imperialism-msvc500 image (invoked with --entrypoint python3 by
tools.workflow.template_emission_matrix). Mirrors /entrypoint.py's wine
environment setup, then compiles the probe TUs compile-only (/c) with the flags
passed on argv, dropping .obj files into /build for host-side COFF inventory.

usage (inside container):
  python3 container_compile.py <cell-name> <extra cl flags...>
"""

import os
import subprocess
import sys


def run(cmd):
    subprocess.run(cmd, check=True)


def configure_wine_env():
    reg_sets = [
        ("PATH", r"C:\msvc\bin;C:\msvc\redist;C:\cmake\bin;C:\windows\system32"),
        ("INCLUDE",
         r"C:\dxsdk\include;C:\msvc\include;C:\msvc\mfc\include;C:\msvc\atl\include"),
        ("LIB", r"C:\msvc\lib;C:\msvc\mfc\lib;C:\dxsdk\lib"),
        ("TMP", r"Z:\build"),
        ("TEMP", r"Z:\build"),
    ]
    for key, value in reg_sets:
        run(["wine", "reg", "ADD", r"HKCU\Environment", "/v", key,
             "/t", "REG_SZ", "/d", value, "/f"])


def main():
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    cell = sys.argv[1]
    extra_flags = sys.argv[2:]
    configure_wine_env()
    src = r"Z:\imperialism\experiments\template_emission"
    out_dir = os.path.join("/build", cell)
    os.makedirs(out_dir, exist_ok=True)
    base = ["wine", r"C:\msvc\bin\cl.exe", "/nologo", "/c", "/W3", "/GX",
            "/O2", "/Oy", "/DWIN32", "/D_WINDOWS"] + extra_flags
    for tu in ("owner", "user"):
        run(base + [f"/FoZ:\\build\\{cell}\\{tu}.obj", f"{src}\\{tu}.cpp"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
