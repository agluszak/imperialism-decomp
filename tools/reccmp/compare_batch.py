"""Batch compare: score many functions from a single reccmp PDB parse.

`reccmp-reccmp --verbose <addr>` cold-parses the whole PDB (~3s) for *one*
function, so checking N addresses serially costs N*3s. This instead runs reccmp
once with `--json` (all ~9600 functions in ~4s) and reports the scores for the
requested addresses, or for every `// FUNCTION` marker in a source file.

Usage:
    python -m tools.reccmp.compare_batch --target IMPERIALISM --build-dir <dir> \
        [ADDR ...] [--file SRC.cpp ...]

Exit status is non-zero if any requested function is below 100%, so it doubles
as a regression gate over a batch.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

MARKER_RE = re.compile(r"//\s*FUNCTION:\s*\w+\s+0x([0-9A-Fa-f]+)")


def norm(addr: str) -> int:
    return int(addr, 16)


def addrs_from_file(path: Path) -> list[int]:
    out: list[int] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = MARKER_RE.search(line)
        if m:
            out.append(int(m.group(1), 16))
    return out


def run_reccmp_json(target: str, build_dir: Path) -> list[dict]:
    with tempfile.NamedTemporaryFile("r", suffix=".json", delete=False) as tf:
        json_path = tf.name
    subprocess.run(
        [
            "uv", "run", "reccmp-reccmp",
            "--target", target,
            "--json", json_path,
            "--json-diet", "--silent",
        ],
        cwd=build_dir,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    return json.loads(Path(json_path).read_text())["data"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--build-dir", required=True, type=Path)
    ap.add_argument("--file", action="append", default=[], type=Path,
                    help="source file(s); compare every // FUNCTION marker in it")
    ap.add_argument("addrs", nargs="*", help="original-binary offsets (hex)")
    args = ap.parse_args()

    wanted: list[int] = [norm(a) for a in args.addrs]
    for f in args.file:
        wanted.extend(addrs_from_file(f))
    if not wanted:
        print("no addresses given (pass hex offsets and/or --file SRC.cpp)", file=sys.stderr)
        return 2
    wanted_set = set(wanted)

    rows = run_reccmp_json(args.target, args.build_dir)
    by_addr = {norm(r["address"]): r for r in rows}

    passed = failed = missing = 0
    fails: list[str] = []
    for a in sorted(wanted_set):
        r = by_addr.get(a)
        if r is None:
            missing += 1
            print(f"  0x{a:08x}  ???.??%  <not found in reccmp output>")
            fails.append(f"0x{a:08x}(missing)")
            continue
        pct = r["matching"] * 100.0
        mark = "OK " if pct >= 100.0 else "   "
        print(f"{mark}0x{a:08x}  {pct:6.2f}%  {r['name']}")
        if pct >= 100.0:
            passed += 1
        else:
            failed += 1
            fails.append(f"0x{a:08x}({pct:.2f}%)")

    print(f"\n{passed} at 100%, {failed} below, {missing} missing (of {len(wanted_set)})")
    if fails:
        print("BELOW 100%: " + " ".join(fails))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
