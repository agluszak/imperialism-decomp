"""Collect whole-program scalar facts and run the shared recovery solvers.

Every translation unit of the production Clang profile (`just source-index`) is collected,
including generated stubs and factories, so callers outside manual source still constrain
recovery. Each run owns a fresh fact directory; source edits stay reviewable patches.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
from collections import Counter
from pathlib import Path

from tools.common.repo import repo_root_from_file, resolve_repo_path

PLUGIN = "docker/msvc500/clang-tidy-plugin"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=1) + "\n", encoding="utf-8")


def campaign(
    repo: Path,
    build: Path,
    image: str,
    *,
    jobs: int,
    evidence: Path | None,
    patch: bool,
    padding: bool,
    propagate_enums: list[str],
    boolean_expressions: bool,
    promote_bool: bool,
    narrow_casts: bool = False,
) -> dict:
    if (boolean_expressions or promote_bool or narrow_casts) and not patch:
        raise ValueError("--boolean-expressions, --promote-bool and --narrow-casts require --patch")
    configure = build / "reccmp-source/cmake"
    database = configure / "compile_commands.json"
    if not database.is_file():
        raise FileNotFoundError("Production Clang profile is missing; run just source-index")
    units = sorted(
        entry["file"].removeprefix("/imperialism/")
        for entry in json.loads(database.read_text(encoding="utf-8"))
    )
    if any(unit.startswith("/") for unit in units):
        raise RuntimeError("Compile database unit outside the repository")
    parent = build / "scalar-campaigns"
    parent.mkdir(exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix="run-", dir=parent))
    container = "/out/" + directory.relative_to(build).as_posix()
    manifest = {
        "schema": "imperialism.scalar-campaign-v1",
        "status": "collecting",
        "image": subprocess.check_output(
            ["docker", "image", "inspect", image, "--format", "{{.Id}}"], text=True
        ).strip(),
        "compile_commands_sha256": sha256_file(database),
        "translation_units": units,
        "evidence_sha256": sha256_file(evidence) if evidence else None,
        "solver_sha256": sha256_file(repo / PLUGIN / "scalar_facts.py"),
        "propagate_source_enums": propagate_enums,
        "simplify_boolean_expressions": boolean_expressions,
        "promote_bool": promote_bool,
        "narrow_casts": narrow_casts,
    }
    write_json(directory / "manifest.json", manifest)
    facts = directory / "facts"
    facts.mkdir()
    # The solver verifies source-side boundary completeness against this census.
    (facts / "expected-units.txt").write_text("".join(unit + "\n" for unit in units))
    (directory / "units.txt").write_text(
        "".join(f"/imperialism/{unit}\n" for unit in units)
    )
    docker = [
        "docker", "run", "--rm", "--network", "none",
        "-v", f"{repo}:/imperialism:ro", "-v", f"{configure}:/build:ro",
        "-v", f"{build}:/out",
    ]
    try:
        with (directory / "collect.log").open("w", encoding="utf-8") as log:
            subprocess.run(
                [
                    *docker,
                    "-e", "IMPERIALISM_REDUNDANT_CAST_LINES=*",
                    "-e", f"IMPERIALISM_SCALAR_FACTS_DIR={container}/facts",
                    "--entrypoint", "xargs", image,
                    "-a", f"{container}/units.txt", "-P", str(jobs), "-n", "8",
                    # The real binary: the wrapper's boolean post-pass would read
                    # fact files that concurrent shards are still writing.
                    "clang-tidy-21", "--load=/usr/local/lib/imperialism-clang-tidy.so",
                    "--quiet", "-p", "/build",
                    "--checks=-*,imperialism-bool-like-byte,imperialism-scalar-facts", "--warnings-as-errors=",
                ],
                stdout=log, stderr=subprocess.STDOUT, check=True,
            )
        replay = list(docker)
        if evidence is not None:
            replay += ["-v", f"{evidence}:/scalar-evidence.json:ro"]
        replay += [
            "--entrypoint", "python3", image,
            f"/imperialism/{PLUGIN}/clang-tidy-wrapper.py",
            "--imperialism-scalar-report", f"{container}/facts",
            "--output", f"{container}/report.json",
        ]
        if evidence is not None:
            replay += ["--evidence", "/scalar-evidence.json"]
        for name in propagate_enums:
            replay += ["--propagate-enum", name]
        if patch:
            replay += ["--repository", "/imperialism", "--patch", f"{container}/recovery.patch"]
            if padding:
                replay.append("--padding")
            if boolean_expressions:
                replay.append("--boolean-expressions")
            if promote_bool:
                replay.append("--promote-bool")
            if narrow_casts:
                replay.append("--narrow-casts")
        with (directory / "solve.log").open("w", encoding="utf-8") as log:
            subprocess.run(replay, stdout=log, stderr=subprocess.STDOUT, check=True)
        subprocess.run(
            [
                *docker, "--entrypoint", "python3", image,
                f"/imperialism/{PLUGIN}/clang-tidy-wrapper.py",
                "--imperialism-bool-report", f"{container}/facts",
                "--output", f"{container}/bool-domain.json",
            ],
            check=True,
        )
        report = json.loads((directory / "report.json").read_text(encoding="utf-8"))
        bool_domain = json.loads((directory / "bool-domain.json").read_text(encoding="utf-8"))
        observed = set(report["translation_units"])
        if set(units) != observed or not report["declarations"]:
            raise RuntimeError(
                "incomplete scalar fact coverage: "
                f"missing={sorted(set(units) - observed)}, "
                f"unexpected={sorted(observed - set(units))}"
            )
    except Exception:
        manifest["status"] = "failed"
        write_json(directory / "manifest.json", manifest)
        raise
    manifest["status"] = "completed"
    write_json(directory / "manifest.json", manifest)
    structural = report["structural_inventory"]
    summary = {
        "status": "completed",
        "translation_units": len(units),
        "declarations": len(report["declarations"]),
        "flows": len(report["flows"]),
        "source_coverage_complete": report["coverage"]["complete"],
        "source_complete_boundaries": report["coverage"]["source_complete_boundaries"],
        "domain_behaviors": dict(Counter(row["behavior"] for row in report["domain_inventory"])),
        "value_domains": dict(Counter(row["value_domain"] for row in report["domain_inventory"])),
        "callbacks": dict(Counter(row["status"] for row in report["callbacks"])),
        "bool_domain": dict(Counter(row["evidence"] for row in bool_domain)),
        "predicate32_inventory": len(report["predicate32_inventory"]),
        "padding_proposals": dict(Counter(row["status"] for row in structural["padding"])),
        "divergent_layouts": len(structural["divergent_layouts"]),
        "integer_proposals": {
            name: dict(Counter(row["status"] for row in rows))
            for name, rows in report["integer_components"].items()
        },
        "pointer_proposals": dict(Counter(row["status"] for row in report["pointer_components"])),
        "nominal_proposals": dict(Counter(row["status"] for row in report["nominal_components"])),
        "enum_propagation": dict(
            Counter(
                row["status"]
                for row in report.get("enum_propagation", {}).get("proposals", [])
            )
        ),
        "artifacts": directory.relative_to(repo).as_posix(),
        "recovery_patch": report.get("recovery_patch"),
    }
    write_json(directory / "summary.json", summary)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", default="build-msvc500")
    parser.add_argument("--image", default="imperialism-msvc500")
    parser.add_argument("--jobs", type=int, default=os.cpu_count() or 1)
    parser.add_argument("--evidence", type=Path, help="reviewed scalar-evidence-v1 claims")
    parser.add_argument("--patch", action="store_true", help="write a reviewable recovery patch")
    parser.add_argument("--padding", action="store_true")
    parser.add_argument("--propagate-enum", action="append", default=[])
    parser.add_argument("--boolean-expressions", action="store_true")
    parser.add_argument("--promote-bool", action="store_true")
    parser.add_argument("--narrow-casts", action="store_true")
    args = parser.parse_args()
    repo = repo_root_from_file(__file__)
    summary = campaign(
        repo,
        resolve_repo_path(repo, args.build_dir),
        args.image,
        jobs=args.jobs,
        evidence=args.evidence.resolve(strict=True) if args.evidence else None,
        patch=args.patch,
        padding=args.padding,
        propagate_enums=args.propagate_enum,
        boolean_expressions=args.boolean_expressions,
        promote_bool=args.promote_bool,
        narrow_casts=args.narrow_casts,
    )
    print(json.dumps(summary, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
