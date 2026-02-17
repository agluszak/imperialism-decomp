#!/usr/bin/env python3
"""Configure/build helper for MSVC500 inside Docker + Wine."""

from __future__ import annotations

import os
import shlex
import subprocess
import sys


def run(cmd: list[str]) -> None:
    subprocess.run(cmd, check=True)


def configure_wine_env() -> None:
    # Registry-backed environment variables keep invocation simple in CI/scripts.
    reg_sets = [
        (
            "PATH",
            r"C:\msvc\bin;C:\cmake\bin;C:\windows\system32",
        ),
        (
            "INCLUDE",
            r"C:\msvc\include;C:\msvc\mfc\include;C:\msvc\atl\include",
        ),
        (
            "LIB",
            r"C:\msvc\lib;C:\msvc\mfc\lib",
        ),
        ("TMP", r"Z:\build"),
        ("TEMP", r"Z:\build"),
    ]
    for key, value in reg_sets:
        run(
            [
                "wine",
                "reg",
                "ADD",
                r"HKCU\Environment",
                "/v",
                key,
                "/t",
                "REG_SZ",
                "/d",
                value,
                "/f",
            ]
        )


def main() -> int:
    try:
        configure_wine_env()

        generator = os.getenv("CMAKE_GENERATOR", "NMake Makefiles")
        cmake_flags = shlex.split(os.getenv("CMAKE_FLAGS", ""))

        cmake_exe = r"C:\cmake\bin\cmake.exe"
        source_dir = r"Z:\imperialism"
        build_dir = r"Z:\build"

        configure_cmd = [
            "wine",
            cmake_exe,
            "-S",
            source_dir,
            "-B",
            build_dir,
            "-G",
            generator,
            *cmake_flags,
        ]
        print("Configure command:", " ".join(configure_cmd))
        run(configure_cmd)

        build_cmd = ["wine", cmake_exe, "--build", build_dir]
        print("Build command:", " ".join(build_cmd))
        run(build_cmd)
        return 0
    except subprocess.CalledProcessError as exc:
        print("ERROR: command failed with exit code {}".format(exc.returncode), file=sys.stderr)
        return exc.returncode


if __name__ == "__main__":
    raise SystemExit(main())
