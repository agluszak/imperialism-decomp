"""Select authored FUNCTION claims and run current reccmp/Ghidriff."""

from __future__ import annotations

import argparse
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from reccmp.source.index import SourceIndex

from tools.common.reccmp_report import function_counts, run_report
from tools.common.repo import repo_root_from_file
from tools.source_model import Claim, build_model


def authored_claims(repo: Path, target: str) -> dict[int, Claim]:
    model = build_model(repo, target)
    if model.duplicates:
        raise ValueError("Duplicate source claims; run the marker gate")
    return {
        address: claim
        for address, claim in model.functions.items()
        if claim.kind == "FUNCTION" and claim.origin == "marker"
    }


def changed_files(repo: Path, base: str) -> set[str]:
    names = subprocess.check_output(
        ["git", "diff", "--name-only", "-z", "--relative", base, "--", "."],
        cwd=repo,
        text=True,
    ).split("\0")
    untracked = subprocess.check_output(
        ["git", "ls-files", "--others", "--exclude-standard", "-z"],
        cwd=repo,
        text=True,
    ).split("\0")
    return {name for name in names + untracked if name}


def select_addresses(
    claims: dict[int, Claim],
    selectors: list[str],
    files: list[str],
    *,
    all_functions: bool = False,
    dependencies: dict[str, tuple[str, ...]] | None = None,
) -> list[int]:
    if all_functions:
        return sorted(claims)
    wanted = set()
    for selector in selectors:
        try:
            address = int(selector, 16)
        except ValueError:
            matches = {
                address
                for address, claim in claims.items()
                if selector.lower() in claim.name.lower()
            }
        else:
            matches = {address} if address in claims else set()
        if not matches:
            raise ValueError(f"No authored FUNCTION matches {selector!r}")
        wanted.update(matches)
    for file in files:
        owners = {file}
        if Path(file).suffix in {".h", ".hpp"}:
            if dependencies is None:
                raise ValueError(
                    "Header selection needs the built source index; run just source-index"
                )
            owners.update(
                unit for unit, includes in dependencies.items() if file in includes
            )
        wanted.update(
            address for address, claim in claims.items() if claim.file in owners
        )
    return sorted(wanted)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="IMPERIALISM")
    parser.add_argument("--build-dir", type=Path, default=Path("build-msvc500"))
    parser.add_argument(
        "--all", action="store_true", help="every authored FUNCTION marker"
    )
    parser.add_argument(
        "--file", action="append", default=[], help="source file or header"
    )
    parser.add_argument("--changed", action="store_true")
    parser.add_argument("--base", default="origin/main")
    parser.add_argument("--output", type=Path, help="new saved report directory")
    parser.add_argument(
        "selectors", nargs="*", help="original addresses or source-name substrings"
    )
    args = parser.parse_args()
    repo = repo_root_from_file(__file__)
    files = list(args.file)
    if args.all and (files or args.selectors or args.changed):
        parser.error("--all cannot be combined with selectors")
    if args.changed:
        base = subprocess.check_output(
            ["git", "merge-base", "HEAD", args.base],
            cwd=repo,
            text=True,
        ).strip()
        files.extend(changed_files(repo, base))
    if not (args.all or files or args.selectors or args.changed):
        parser.error("Select addresses/names, --file, --changed, or --all")
    files = [(repo / file).resolve().relative_to(repo).as_posix() for file in files]
    dependencies = None
    if any(Path(file).suffix in {".h", ".hpp"} for file in files):
        dependencies = SourceIndex.read(
            args.build_dir / "reccmp-source/source-index.json"
        ).unit_dependencies
    claims = authored_claims(repo, args.target)
    addresses = select_addresses(
        claims,
        args.selectors,
        files,
        all_functions=args.all,
        dependencies=dependencies,
    )
    if not addresses:
        print("No authored functions selected.")
        return 0
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    output = args.output or repo / "build/comparisons" / stamp
    selection = {
        "scope": "all-authored" if args.all else "selected-authored",
        "revision": subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=repo,
            text=True,
        ).strip(),
        "dirty": subprocess.check_output(
            ["git", "status", "--porcelain"],
            cwd=repo,
            text=True,
        ).splitlines(),
        "functions": [
            {
                "orig": hex(address),
                "file": claims[address].file,
                "line": claims[address].line,
                "name": claims[address].name,
            }
            for address in addresses
        ],
    }
    summary = run_report(
        args.target,
        args.build_dir,
        orig_addresses=addresses,
        output=output,
        selection=selection,
    )
    print(json.dumps(function_counts(summary["functions"]), indent=1))
    print(f"Saved comparison: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
