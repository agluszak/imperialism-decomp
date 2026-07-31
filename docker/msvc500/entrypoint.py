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
    # Registry-backed environment variables keep invocation simple in automation/scripts.
    reg_sets = [
        (
            "PATH",
            r"C:\msvc\bin;C:\msvc\redist;C:\cmake\bin;C:\windows\system32",
        ),
        (
            # C:\dxsdk\include (DirectX 5 SDK) must precede C:\msvc\include so its
            # IDirectPlay2-era <dplay.h> shadows the DirectX 1 copy in the toolchain.
            "INCLUDE",
            r"C:\dxsdk\include;C:\msvc\include;C:\msvc\mfc\include;C:\msvc\atl\include",
        ),
        (
            "LIB",
            r"C:\msvc\lib;C:\msvc\mfc\lib;C:\dxsdk\lib",
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
    lint_mode = os.getenv("LINT") == "1"
    if lint_mode:
        source_dir = "/imperialism"
        build_dir = "/build"
        toolchain = os.path.join(source_dir, "cmake", "clang-cl-i686.cmake")
        extra_flags = shlex.split(os.getenv("CMAKE_FLAGS", ""))

        try:
            cache_file = os.path.join(build_dir, "CMakeCache.txt")
            if os.path.exists(cache_file):
                try:
                    os.remove(cache_file)
                except Exception:
                    pass
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
            run(["cmake", "--build", build_dir, "--", "-k", "0"])
            return 0
        except subprocess.CalledProcessError as exc:
            print(
                "ERROR: lint command failed with exit code {}".format(exc.returncode),
                file=sys.stderr,
            )
            return exc.returncode

    # BUILD_ONLY skips the Wine `cmake` configure and goes straight to `cmake --build`.
    # The configure is several seconds of Wine startup plus a full compiler re-probe, which
    # dominates the edit-compile-run loop for a one-file change. It is only safe when the
    # build tree is already configured and the file set has not changed: CMake's
    # CONFIGURE_DEPENDS globs are re-evaluated by a configure, not by a build, so a new or
    # deleted source needs the full path. `just runtime-dev` decides that and only sets
    # this when the source set is unchanged.
    build_only = os.getenv("BUILD_ONLY") == "1"

    try:
        configure_wine_env()

        generator = os.getenv("CMAKE_GENERATOR", "NMake Makefiles")
        build_jobs = os.getenv("BUILD_JOBS", "")
        cmake_flags = shlex.split(os.getenv("CMAKE_FLAGS", ""))

        cmake_exe = r"C:\cmake\bin\cmake.exe"
        source_dir = r"Z:\imperialism"
        build_dir = r"Z:\build"

        # A generator switch (NMake <-> NMake JOM) invalidates the cache; CMake
        # hard-errors on the mismatch, so drop the stale cache first.
        cache_path = "/build/CMakeCache.txt"
        if os.path.exists(cache_path):
            with open(cache_path, encoding="utf-8", errors="ignore") as fh:
                cached = fh.read()
            if f"CMAKE_GENERATOR:INTERNAL={generator}\n" not in cached:
                os.remove(cache_path)

        if generator == "NMake Makefiles JOM":
            cmake_flags.append(r"-DCMAKE_MAKE_PROGRAM=C:\jom\jom.exe")

        if build_only and not os.path.exists(cache_path):
            print(
                "BUILD_ONLY was requested but /build has no CMakeCache.txt; configuring once.",
                file=sys.stderr,
            )
            build_only = False

        if build_only:
            print("Configure command: skipped (BUILD_ONLY=1)")
        else:
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
        if build_jobs:
            build_cmd += ["--", "-j", build_jobs]
        print("Build command:", " ".join(build_cmd))
        run(build_cmd)
        return 0
    except subprocess.CalledProcessError as exc:
        print("ERROR: command failed with exit code {}".format(exc.returncode), file=sys.stderr)
        return exc.returncode


if __name__ == "__main__":
    raise SystemExit(main())
