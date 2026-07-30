#!/usr/bin/env python3
"""Recompile only what changed in the runtime-test build, for the authoring inner loop.

`just runtime-test` is the canonical, gated path: it runs the vtable gate, regenerates
every derived build input (stubs, UI factories, the native registry), and has Docker run a
full Wine `cmake` configure before `cmake --build`. That is right before a commit and wrong
while editing one test: the gate and the generation step are unrelated to a scenario body,
and the Wine configure re-probes the compiler from scratch every time.

This driver does the minimum that is still correct:

* regenerate the native registry include only when `catalog.py` is newer than it, since
  that file is the only generated input a scenario edit can invalidate;
* pass ``BUILD_ONLY=1`` so the container skips the configure -- but only while the source
  file set is unchanged. CMake re-evaluates its ``CONFIGURE_DEPENDS`` globs during a
  configure, not during a build, so adding or deleting a scenario `.cpp` needs the full
  path or the new file is silently never compiled. A stamp file records the set that the
  last configure saw, and any difference forces a configure.

It deliberately does *not* run the vtable gate, `tools.generate`, or the source-policy
gate. `just precommit` and `just runtime-test` still do, so nothing here weakens what runs
before a commit.
"""

from __future__ import annotations

import argparse
import hashlib
import subprocess
import sys
from pathlib import Path

from tools.common.repo import repo_root_from_file


DOCKER_IMAGE = "imperialism-msvc500"

# Every glob CMakeLists.txt uses with CONFIGURE_DEPENDS to find runtime-test sources.
# A change to the *set* of matching files needs a configure; a change to their contents
# does not. Keep this in step with CMakeLists.txt:41.
SOURCE_GLOBS = ("tests/runtime/native/**/*.cpp",)


def source_set_digest(repo: Path) -> str:
    """A digest of the runtime-test source *file set*, ignoring contents."""
    names: list[str] = []
    for pattern in SOURCE_GLOBS:
        names.extend(sorted(str(p.relative_to(repo)) for p in repo.glob(pattern)))
    joined = "\n".join(sorted(names))
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


def regenerate_registry_if_stale(repo: Path, build_dir: Path) -> bool:
    """Regenerate RuntimeRegistry.inc when the catalog is newer. Returns True if written."""
    catalog = repo / "tools" / "runtime" / "catalog.py"
    generator = repo / "tools" / "runtime" / "generate_native_registry.py"
    output = build_dir / "generated" / "runtime" / "RuntimeRegistry.inc"
    if output.exists():
        newest_input = max(catalog.stat().st_mtime, generator.stat().st_mtime)
        if output.stat().st_mtime >= newest_input:
            return False
    output.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.runtime.generate_native_registry",
            "--output",
            str(output),
        ],
        cwd=repo,
        check=True,
    )
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--build-dir",
        default="build-runtime-tests",
        help="Runtime-test build tree (default: build-runtime-tests).",
    )
    parser.add_argument(
        "--configure",
        action="store_true",
        help="Force a full CMake configure even when the source set is unchanged.",
    )
    args = parser.parse_args(argv)

    repo = repo_root_from_file(__file__)
    build_dir = (repo / args.build_dir).resolve()
    if not build_dir.is_dir():
        print(
            f"{build_dir} does not exist; run `just runtime-test-build` once first.",
            file=sys.stderr,
        )
        return 2

    if regenerate_registry_if_stale(repo, build_dir):
        print("regenerated RuntimeRegistry.inc (catalog changed)")

    stamp = build_dir / ".runtime-source-set"
    digest = source_set_digest(repo)
    previous = stamp.read_text(encoding="utf-8").strip() if stamp.is_file() else ""
    needs_configure = args.configure or digest != previous
    if needs_configure and previous:
        # Say why, so a slow run in the inner loop is never a mystery.
        print("runtime-test source set changed; running a full CMake configure")
    elif needs_configure:
        print("no recorded source set; running a full CMake configure")

    environment = {
        "CMAKE_FLAGS": "-DIMPERIALISM_RUNTIME_TESTS=ON",
    }
    if not needs_configure:
        environment["BUILD_ONLY"] = "1"

    command = ["docker", "run", "--rm", "--network", "none"]
    for key, value in environment.items():
        command += ["-e", f"{key}={value}"]
    command += [
        "-v",
        f"{repo}:/imperialism",
        "-v",
        f"{build_dir}:/build",
        DOCKER_IMAGE,
    ]
    # Share the MSVC build lock: the toolchain writes shared temporaries into the build
    # tree, so a concurrent `just build` in the same checkout would corrupt this one.
    locked = [
        sys.executable,
        "-m",
        "tools.workflow.msvc_build_lock",
        "--lock",
        str(repo / "build-msvc500" / ".msvc-build.lock"),
        "--",
        *command,
    ]
    result = subprocess.run(locked, cwd=repo)
    if result.returncode != 0:
        return result.returncode

    stamp.write_text(digest + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
