#!/usr/bin/env python3
"""Split global_data_tables.h into per-subsystem globals headers (bead 8mo.2).

Every ``extern`` in the god header is assigned to a subsystem by looking at which
manual TUs reference its name and mapping those TUs through
``docs/reference/subsystem_assignment.csv`` (the original-module evidence from
``just assign-subsystems``). A global used by exactly one subsystem moves to
``include/game/globals/<subsystem>_globals.h``; a global used by several — or by
none yet (its users are unported) — goes to ``globals/shared_globals.h``.

The god header's non-extern content (its prelude includes, record definitions,
free-function declarations) moves verbatim to ``globals/prelude.h``, which every
subsystem header includes first. ``global_data_tables.h`` itself becomes an
umbrella: prelude + every subsystem header, so all existing includers compile
unchanged. Definitions stay in global_data_tables.cpp (datacmp/link order).

Idempotence: rerunning after the split is a no-op refusal (the god header no
longer contains externs). This is a one-shot migration tool kept for the record
and for regenerating the assignment report (--report).

usage: uv run python -m tools.analysis.split_globals [--report] [--apply]
"""

from __future__ import annotations

import argparse
import re
from collections import defaultdict
from pathlib import Path

from tools.common.pipe_csv import read_pipe_rows
from tools.common.repo import repo_root_from_file

GOD = "include/game/global_data_tables.h"
ASSIGN = "docs/reference/subsystem_assignment.csv"
OUT_DIR = "include/game/globals"

NAME_RE = re.compile(r"\b(\w+)\s*(?:\[[^\]]*\]\s*)*;\s*(?://.*)?$")


def parse_god_header(text: str):
    """-> (prelude_lines, [(name, c_linkage, block_lines)]) — lossless partition.

    ``extern "C" { ... }`` brace blocks are dissolved: each member extern is
    extracted with a c_linkage flag and re-emitted inside a per-header
    ``extern "C"`` section by the writer."""
    lines = text.splitlines(keepends=True)
    prelude: list[str] = []
    externs: list[tuple[str, bool, list[str]]] = []
    pending_comments: list[str] = []
    in_c_block = False
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if stripped.startswith("//") or not stripped:
            pending_comments.append(line)
            i += 1
            continue
        if re.match(r'extern\s+"C"\s*\{', stripped):
            prelude.extend(pending_comments)
            pending_comments = []
            in_c_block = True
            i += 1
            continue
        if in_c_block and re.match(r"\}\s*(?://.*)?$", stripped):
            prelude.extend(pending_comments)
            pending_comments = []
            in_c_block = False
            i += 1
            continue
        if line.startswith("extern "):
            block = list(pending_comments)
            pending_comments = []
            stmt = [line]
            while ";" not in stmt[-1]:
                i += 1
                stmt.append(lines[i])
            block += stmt
            m = NAME_RE.search("".join(s.strip() for s in stmt))
            name = m.group(1) if m else ""
            c_linkage = in_c_block or stmt[0].startswith('extern "C"')
            externs.append((name, c_linkage, block))
            i += 1
            continue
        # Anything else (fwd decls, typedefs) is linkage-neutral: prelude,
        # whether inside an extern-C block or not.
        prelude.extend(pending_comments)
        pending_comments = []
        prelude.append(line)
        i += 1
    prelude.extend(pending_comments)
    return prelude, externs


def tu_subsystems(repo_root: Path) -> dict[str, str]:
    """file -> subsystem, only for files with at least one sampled-confidence
    marker. A file whose every address sits in an unsampled tail zone (e.g. the
    flavor-text builders inside UUnit.cpp's single-sample tail) has a guessed
    subsystem and must not vote on global placement."""
    out = {}
    for row in read_pipe_rows(repo_root / ASSIGN):
        subsystem = row["proposed_subsystem"]
        if subsystem and int(row["tail_uncertain"]) < int(row["n_markers"]):
            out[row["file"]] = subsystem
    return out


def main() -> int:
    repo_root = repo_root_from_file(__file__)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="write the split headers")
    parser.add_argument("--report", action="store_true", help="print per-global assignment")
    args = parser.parse_args()

    god_path = repo_root / GOD
    text = god_path.read_text(encoding="utf-8")
    prelude, externs = parse_god_header(text)
    if not externs:
        print("global_data_tables.h holds no externs; already split.")
        return 0

    subs = tu_subsystems(repo_root)
    # One tokenize pass over manual TUs.
    users: dict[str, set[str]] = defaultdict(set)
    names = {n for n, _c, _ in externs if n}
    for src in sorted((repo_root / "src/game").glob("*.cpp")):
        if src.name == "global_data_tables.cpp":
            continue
        toks = set(re.findall(r"[A-Za-z_]\w*", src.read_text(encoding="utf-8")))
        for n in names & toks:
            users[n].add(src.name)

    buckets: dict[str, list[tuple[bool, list[str]]]] = defaultdict(list)
    stats = defaultdict(int)
    for name, c_linkage, block in externs:
        subsets = {sub for f in users.get(name, ()) if (sub := subs.get(f))}
        dest = next(iter(subsets)) if len(subsets) == 1 else "shared"
        buckets[dest].append((c_linkage, block))
        stats[dest] += 1
        if args.report:
            print(f"{name}|{dest}|{'+'.join(sorted(subsets)) or '(no confident users)'}")

    print("assignment:", dict(sorted(stats.items(), key=lambda kv: -kv[1])))
    if not args.apply:
        return 0

    out_dir = repo_root / OUT_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    banner = (
        "// Split from global_data_tables.h by tools/analysis/split_globals.py\n"
        "// (bead 8mo.2). Definitions stay in src/game/global_data_tables.cpp;\n"
        "// assignment evidence: docs/reference/subsystem_assignment.csv.\n"
    )
    (out_dir / "prelude.h").write_text(
        "#pragma once\n" + banner + "".join(prelude), encoding="utf-8"
    )
    sub_headers = []
    for dest in sorted(buckets):
        rel = f"{dest}_globals.h"
        cxx = "".join("".join(b) + "\n" for c, b in buckets[dest] if not c)
        c_blocks = "".join("".join(b) + "\n" for c, b in buckets[dest] if c)
        body = cxx
        if c_blocks:
            body += 'extern "C" {\n' + c_blocks + '} // extern "C"\n'
        (out_dir / rel).write_text(
            "#pragma once\n" + banner + '#include "game/globals/prelude.h"\n\n' + body,
            encoding="utf-8",
        )
        sub_headers.append(rel)
    umbrella = (
        "#pragma once\n"
        "// Umbrella over the per-subsystem globals headers (split by\n"
        "// tools/analysis/split_globals.py, bead 8mo.2). New globals go in the\n"
        "// subsystem header their users live in (shared_globals.h when unsure);\n"
        "// consumers should migrate to the specific headers over time.\n"
        '#include "game/globals/prelude.h"\n'
        + "".join(f'#include "game/globals/{h}"\n' for h in sub_headers)
    )
    god_path.write_text(umbrella, encoding="utf-8")
    print(f"wrote {len(sub_headers)} subsystem headers + prelude; umbrella installed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
