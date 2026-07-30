#!/usr/bin/env python3
"""Recompile only what changed in the runtime-test build, for the authoring inner loop.

`just runtime-test` is the canonical, gated path: it runs the vtable gate, regenerates
every derived build input (stubs, UI factories, the native registry), and has Docker run a
full Wine `cmake` configure before `cmake --build`. That is right before a commit and wrong
while editing one test: the gate and the generation step are unrelated to a scenario body,
and the Wine configure re-probes the compiler from scratch every time.

Authoring a runtime test is not only editing test files. The loop is: write a scenario, watch
it fail, fix production game code, sometimes add a production `.cpp` or change a marker, run
again. So "recompile only what changed" has to be correct for changes to the *game*, not just
to `tests/runtime/native`.

What this driver does:

* regenerate the native registry include when `catalog.py` is newer than it;
* re-run `tools.generate` when a manual source or one of its config inputs is newer than the
  generated tree. Stubs and UI factories are compiled from that tree, so skipping this step
  after a marker or ownership edit builds the *previous* generation's stubs -- a stale product
  that looks like a real result;
* pass ``BUILD_ONLY=1`` so the container skips the Wine configure while the source set is
  unchanged, and bootstrap a missing build tree with a full configure instead of refusing to
  run.

Verified rather than assumed: adding a `src/game/*.cpp` and running this driver *does* compile
it even under ``BUILD_ONLY=1``. CMake's ``CONFIGURE_DEPENDS`` re-globs during the build and
re-runs the configure itself, so the source-set stamp below is a latency optimisation, not what
makes a new file visible.

It deliberately does *not* run the vtable gate or the source-policy gate. `just precommit` and
`just runtime-test` still do, so nothing here weakens what runs before a commit.
"""

from __future__ import annotations

import argparse
import hashlib
import subprocess
import sys
from pathlib import Path

from tools.common.repo import repo_root_from_file


# Only the fallback for a direct `python -m` run; `just runtime-dev` passes the configured
# image so this file never disagrees with justfile's `docker_image`.
DEFAULT_DOCKER_IMAGE = "imperialism-msvc500"

# Every glob CMakeLists.txt uses with CONFIGURE_DEPENDS to find runtime-test sources.
# A change to the *set* of matching files needs a configure; a change to their contents
# does not. Keep this in step with CMakeLists.txt:41.
SOURCE_GLOBS = ("tests/runtime/native/**/*.cpp",)

# What `tools.generate` reads. A newer input here means the generated tree -- stubs, UI
# factories, the symbol overlay -- describes the previous state of the source model.
GENERATED_INPUT_GLOBS = (
    "src/**/*.cpp",
    "include/**/*.h",
    "config/original_entities.csv",
    "config/reviewed_library_identities.csv",
    "config/ui_factory_codegen.yml",
)


def source_set_digest(repo: Path) -> str:
    """A digest of the runtime-test source *file set*, ignoring contents."""
    names: list[str] = []
    for pattern in SOURCE_GLOBS:
        names.extend(sorted(str(p.relative_to(repo)) for p in repo.glob(pattern)))
    joined = "\n".join(sorted(names))
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


def newest_generated_input(repo: Path) -> float:
    """mtime of the most recently touched thing `tools.generate` consumes."""
    newest = 0.0
    for pattern in GENERATED_INPUT_GLOBS:
        for path in repo.glob(pattern):
            if path.is_file():
                newest = max(newest, path.stat().st_mtime)
    return newest


def regenerate_sources_if_stale(repo: Path, build_dir: Path) -> bool:
    """Re-run `tools.generate` when a manual source outdates the generated tree.

    The stubs and UI factories in that tree are compiled into the same binary the scenario
    exercises, so building against a stale generation is not a slow loop -- it is a wrong
    answer that looks like a real one.
    """
    gen_dir = build_dir / "generated"
    model = gen_dir / "source_model.json"
    if model.is_file() and model.stat().st_mtime >= newest_generated_input(repo):
        return False
    subprocess.run(
        [sys.executable, "-m", "tools.generate", "--gen-dir", str(gen_dir)],
        cwd=repo,
        check=True,
    )
    return True


def regenerate_registry_if_stale(repo: Path, build_dir: Path) -> bool:
    """Regenerate RuntimeRegistry.inc when the catalog is newer. Returns True if written.

    Staleness is tracked in a stamp rather than by comparing the output's own mtime, because
    the generator deliberately leaves the file alone when the content is unchanged -- so its
    mtime stays behind the catalog's forever, and an mtime comparison re-runs the generator on
    every single invocation of the inner loop. Touching the output instead would trade that
    for a spurious recompile of everything that includes it.
    """
    catalog = repo / "tools" / "runtime" / "catalog.py"
    generator = repo / "tools" / "runtime" / "generate_native_registry.py"
    output = build_dir / "generated" / "runtime" / "RuntimeRegistry.inc"
    stamp = build_dir / ".runtime-registry-inputs"
    newest_input = f"{max(catalog.stat().st_mtime, generator.stat().st_mtime)}"
    if output.exists() and stamp.is_file():
        if stamp.read_text(encoding="utf-8").strip() == newest_input:
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
    stamp.write_text(newest_input + "\n", encoding="utf-8")
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
    parser.add_argument(
        "--docker-image",
        default=DEFAULT_DOCKER_IMAGE,
        help="Toolchain image (default: the justfile's docker_image).",
    )
    args = parser.parse_args(argv)

    repo = repo_root_from_file(__file__)
    build_dir = (repo / args.build_dir).resolve()
    # A missing build tree is the state every fresh clone starts in. Bootstrapping it is one
    # configure; demanding a separate canonical build first is a detour through the very gates
    # this loop exists to skip.
    bootstrapping = not build_dir.is_dir()
    if bootstrapping:
        print(f"{build_dir.name} does not exist; bootstrapping it with a full configure")
        build_dir.mkdir(parents=True)

    if regenerate_sources_if_stale(repo, build_dir):
        print("regenerated stubs/UI factories (a manual source outdated the generated tree)")
    if regenerate_registry_if_stale(repo, build_dir):
        print("regenerated RuntimeRegistry.inc (catalog changed)")

    stamp = build_dir / ".runtime-source-set"
    digest = source_set_digest(repo)
    previous = stamp.read_text(encoding="utf-8").strip() if stamp.is_file() else ""
    needs_configure = args.configure or bootstrapping or digest != previous
    if needs_configure and previous:
        # Say why, so a slow run in the inner loop is never a mystery.
        print("runtime-test source set changed; running a full CMake configure")
    elif needs_configure and not bootstrapping:
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
        args.docker_image,
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
