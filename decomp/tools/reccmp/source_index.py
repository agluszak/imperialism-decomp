"""Collect reccmp's Clang source facts for the production VC5 source tree."""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
from pathlib import Path
import shlex
import subprocess

import reccmp.source.batch
from reccmp.source.index import SourceIndex
import yaml

from tools.common.repo import repo_root_from_file, resolve_repo_path
from tools.workflow.gen_compile_commands import rewrite


def collect(repo: Path, build: Path, image: str, jobs: int) -> Path:
    cache = build / "reccmp-source"
    configure = cache / "cmake"
    configure.mkdir(parents=True, exist_ok=True)
    generated = "/imperialism/" + (build / "generated").relative_to(repo).as_posix()
    subprocess.run(
        [
            "docker", "run", "--rm", "--network", "none",
            "-v", f"{repo}:/imperialism", "-v", f"{configure}:/build",
            "--entrypoint", "cmake", image,
            "-S", "/imperialism", "-B", "/build", "-G", "Ninja",
            "-DCMAKE_TOOLCHAIN_FILE=/imperialism/cmake/clang-cl-i686.cmake",
            "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
            f"-DIMPERIALISM_GENERATED_DIR={generated}",
        ],
        check=True,
    )
    entries = rewrite(
        json.loads((configure / "compile_commands.json").read_text()),
        str(repo), str(configure),
    )
    # This marker carrier deliberately emits no code and has no product object.
    # Give Clang its normal source context so reccmp sees its LIBRARY markers.
    carrier = repo / "src/game/core/library_identities.cpp"
    context = next(entry for entry in entries if "/src/game/" in entry["file"])
    entries.append({
        **context,
        "file": str(carrier),
        "command": context["command"].replace(context["file"], str(carrier)),
    })
    database = cache / "compile_commands.json"
    database.write_text(json.dumps(entries, indent=1) + "\n")

    source = Path(reccmp.source.batch.__file__).with_name("indexer.cpp")
    image_id = subprocess.check_output(
        ["docker", "image", "inspect", image, "--format", "{{.Id}}"], text=True
    ).strip()
    digest = hashlib.sha256(source.read_bytes() + image_id.encode()).hexdigest()
    binary = cache / "indexer"
    stamp = cache / "indexer.sha256"
    if not binary.is_file() or not stamp.is_file() or stamp.read_text() != digest:
        subprocess.run(
            [
                "docker", "run", "--rm", "--network", "none",
                "-v", f"{cache}:{cache}", "-v", f"{source}:/indexer.cpp:ro",
                "--entrypoint", "clang++-19", image,
                "-O2", "-std=c++17", "-fno-rtti", "-fno-exceptions",
                "-I/usr/lib/llvm-19/include", "/indexer.cpp", "-o", str(binary),
                "/usr/lib/llvm-19/lib/libclang-cpp.so.19.1",
                "/usr/lib/llvm-19/lib/libLLVM.so",
            ],
            check=True,
        )
        stamp.write_text(digest)
    wrapper = cache / "docker-indexer"
    command = [
        "docker", "run", "--rm", "-i", "--network", "none",
        "-v", f"{repo}:{repo}", "-e", f"RECCMP_SOURCE_ROOT={repo}",
        "--entrypoint", str(binary), image,
    ]
    wrapper.write_text(
        f'#!/bin/sh\n# indexer {digest}\nexec {shlex.join(command)} "$@"\n'
    )
    wrapper.chmod(0o755)
    os.environ["RECCMP_SOURCE_INDEXER"] = str(wrapper)

    project = yaml.safe_load((repo / "reccmp-project.yml").read_text())
    targets = {
        target: sorted({
            path.resolve()
            for root in config["source_root"]
            for path in (repo / root).rglob("*")
            if path.suffix in {".h", ".hpp", ".c", ".cpp"}
        })
        for target, config in project["targets"].items()
    }
    SourceIndex.from_compile_database(
        repo, database, targets, clang="/usr/bin/clang-cl", jobs=jobs, cache_dir=cache
    )
    output = cache / "source-index.json"
    config_path = build / "reccmp-build.yml"
    config = yaml.safe_load(config_path.read_text())
    config.pop("source_index", None)
    config["source-index"] = str(output)
    config_path.write_text(yaml.safe_dump(config, sort_keys=False))
    print(f"Wrote {output}")
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", default="build-msvc500")
    parser.add_argument("--image", default="imperialism-msvc500")
    parser.add_argument("--jobs", type=int, default=2)
    args = parser.parse_args()
    repo = repo_root_from_file(__file__)
    logging.basicConfig(level=logging.INFO)
    collect(repo, resolve_repo_path(repo, args.build_dir), args.image, args.jobs)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
