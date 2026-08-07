#!/usr/bin/env python3
"""Configure/build the lint compiler (clang + MinGW-w64 i686) inside Docker.

This is a *lint-only* build: it compiles the same sources as the MSVC500 build
with strong modern diagnostics to catch errors (missing `override`, narrowing,
bad vtable signatures) early. It is never used for reccmp matching.
"""

from __future__ import annotations

import os
import shlex
import subprocess
import sys


def run(cmd: list[str]) -> None:
    print("+", " ".join(cmd), flush=True)
    subprocess.run(cmd, check=True)


def main() -> int:
    source_dir = "/imperialism"
    build_dir = "/build"
    toolchain = os.path.join(source_dir, "cmake", "clang-mingw-i686.cmake")
    extra_flags = shlex.split(os.getenv("CMAKE_FLAGS", ""))

    try:
        run(
            [
                "cmake",
                "-S",
                source_dir,
                "-B",
                build_dir,
                "-G",
                "Ninja",
                "-DCMAKE_TOOLCHAIN_FILE=" + toolchain,
                *extra_flags,
            ]
        )
        # Keep going after errors: a linter should report every file's
        # diagnostics in one pass, not stop at the first failure.
        run(["cmake", "--build", build_dir, "--", "-k", "0"])
        return 0
    except subprocess.CalledProcessError as exc:
        print(
            "ERROR: command failed with exit code {}".format(exc.returncode),
            file=sys.stderr,
        )
        return exc.returncode


if __name__ == "__main__":
    raise SystemExit(main())
