#!/usr/bin/env python3
"""Merge the signature-projection evidence trails into one address-keyed view.

`tools.ghidra.apply_source_signatures` produces FIVE separate read-only/read-
adjacent evidence files, each answering a different question about the same
functions:

  - source_signature_queue_in_stack.csv  — in_stack-triggered projector queue
  - source_signature_queue_divergent.csv — source-driven ("divergent") projector queue
  - source_signature_queue_packed.csv    — packed CUSTOM_STORAGE projector queue
  - signature_convergence.csv            — the structural audit's 3-tier verdict
  - datatype_hygiene.csv                 — by-value opaque-type usage audit
  - in_stack_audit.csv (tools.ghidra.in_stack_audit) — per-function in_stack bucket

Before this tool, the three queue files used to collide on ONE shared default
filename with no `--queue-out` override in any `just` recipe — a full
`ghidra-apply-source-full` run silently left only the LAST projector's queue on
disk, discarding the other two phases' evidence entirely. Giving each projector
its own default file (see `_QUEUE_OUT_BY_MODE` in apply_source_signatures.py)
fixed the overwrite; this tool is the "keyed union" that lets a human (or a
strict gate) see every phase's evidence for a given address side by side,
without any one phase's row masking another's.

READ-ONLY: reads whichever of the six CSVs exist on disk (missing files are
skipped, not an error — a fresh checkout may not have run every phase yet) and
writes one row per address to signature_evidence_union.csv. No Ghidra needed —
this is pure file I/O.

`--strict` fails (nonzero exit) on "unexplained structural divergence": a
structural-audit row whose LOGICAL tier did NOT converge, yet appears in NONE
of the other five evidence sources. Every non-converged function should be
accounted for somewhere (queued for projection, flagged as a datatype-hygiene
issue, or bucketed by the in_stack audit) — a row with a logical gap and zero
trace anywhere else means some function fell through every audit's net, which
is itself a defect in audit coverage, not a classified/explained state.

  just signature-evidence-union            # build the union
  just signature-evidence-union --strict   # + fail on unexplained divergence
"""

from __future__ import annotations

import argparse
from pathlib import Path

from tools.common.pipe_csv import read_pipe_rows
from tools.common.repo import repo_root_from_file

_DEFAULT_INPUTS = {
    "in_stack_queue": "build-msvc500/evidence/source_signature_queue_in_stack.csv",
    "divergent_queue": "build-msvc500/evidence/source_signature_queue_divergent.csv",
    "packed_queue": "build-msvc500/evidence/source_signature_queue_packed.csv",
    "structural_audit": "build-msvc500/evidence/signature_convergence.csv",
    "datatype_hygiene": "build-msvc500/evidence/datatype_hygiene.csv",
    "in_stack_audit": "build-msvc500/evidence/in_stack_audit.csv",
}
_DEFAULT_OUT = "build-msvc500/evidence/signature_evidence_union.csv"

_QUEUE_KEYS = ("in_stack_queue", "divergent_queue", "packed_queue")
_LOGICAL_CONVERGED = "logical_converged"


def _norm_addr(text: str) -> int:
    return int(text.strip(), 16)


def load_evidence_files(
    repo_root: Path, paths: dict[str, str],
) -> tuple[dict[str, dict[int, dict]], set[str]]:
    """Load each named CSV into {address: row_dict}; a missing file yields {}.

    Returns (loaded, found_on_disk) — `found_on_disk` tracks actual file
    EXISTENCE separately from whether it has any data rows, so a legitimately
    empty audit (e.g. datatype_hygiene.csv with zero opaque-by-value issues)
    is not misreported as "not found" alongside a genuinely absent file (a
    phase that hasn't been run yet).
    """
    loaded: dict[str, dict[int, dict]] = {}
    found_on_disk: set[str] = set()
    for key, rel in paths.items():
        p = Path(rel)
        if not p.is_absolute():
            p = repo_root / p
        by_addr: dict[int, dict] = {}
        if p.exists():
            found_on_disk.add(key)
            for row in read_pipe_rows(p):
                addr_text = row.get("address", "")
                if not addr_text:
                    continue
                by_addr[_norm_addr(addr_text)] = row
        loaded[key] = by_addr
    return loaded, found_on_disk


def build_union_rows(evidence: dict[str, dict[int, dict]]) -> list[dict]:
    """Pure: one row per address seen in ANY evidence source, with every source's
    contribution alongside it (empty string when that source has nothing for the
    address) plus a computed `explained` flag.

    `explained` is True when the structural audit is absent (nothing to explain)
    or logically converged, OR when at least one other evidence source has a row
    for that address (queued, hygiene-flagged, or in_stack-audited) — i.e. some
    tool accounted for the gap. False only for a structural divergence with zero
    trace anywhere else.
    """
    all_addrs: set[int] = set()
    for by_addr in evidence.values():
        all_addrs.update(by_addr.keys())

    rows = []
    for addr in sorted(all_addrs):
        structural = evidence.get("structural_audit", {}).get(addr)
        name = ""
        for key in ("structural_audit", *_QUEUE_KEYS, "datatype_hygiene", "in_stack_audit"):
            row = evidence.get(key, {}).get(addr)
            if row and row.get("name"):
                name = row["name"]
                break

        logical_cat = structural.get("category", "") if structural else ""
        has_other_evidence = any(
            evidence.get(key, {}).get(addr) for key in
            (*_QUEUE_KEYS, "datatype_hygiene", "in_stack_audit"))
        explained = (
            structural is None
            or logical_cat == _LOGICAL_CONVERGED
            or has_other_evidence
        )

        rows.append({
            "address": addr,
            "name": name,
            "structural_category": logical_cat,
            "structural_abi": structural.get("abi_storage", "") if structural else "",
            "structural_semantic": structural.get("semantic", "") if structural else "",
            "in_stack_queue_reason": _reason(evidence, "in_stack_queue", addr),
            "divergent_queue_reason": _reason(evidence, "divergent_queue", addr),
            "packed_queue_reason": _reason(evidence, "packed_queue", addr),
            "datatype_hygiene_category": _field(evidence, "datatype_hygiene", addr, "category"),
            "in_stack_audit_bucket": _field(evidence, "in_stack_audit", addr, "bucket"),
            "explained": explained,
        })
    return rows


def _reason(evidence, key, addr) -> str:
    row = evidence.get(key, {}).get(addr)
    return row.get("reason", "") if row else ""


def _field(evidence, key, addr, field) -> str:
    row = evidence.get(key, {}).get(addr)
    return row.get(field, "") if row else ""


_UNION_COLUMNS = [
    "address", "name", "structural_category", "structural_abi", "structural_semantic",
    "in_stack_queue_reason", "divergent_queue_reason", "packed_queue_reason",
    "datatype_hygiene_category", "in_stack_audit_bucket", "explained",
]


def write_union(rows: list[dict], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    lines = ["|".join(_UNION_COLUMNS)]
    for row in rows:
        cells = []
        for col in _UNION_COLUMNS:
            v = row[col]
            if col == "address":
                v = f"0x{v:08x}"
            elif col == "explained":
                v = "true" if v else "false"
            cells.append(str(v))
        lines.append("|".join(cells))
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--out", default=_DEFAULT_OUT)
    p.add_argument("--strict", action="store_true",
                   help="Fail if any structural-divergence row has zero corroborating "
                        "evidence in every other audit (an unexplained gap).")
    args = p.parse_args()

    repo_root = repo_root_from_file(__file__, levels_up=2)
    evidence, found_on_disk = load_evidence_files(repo_root, _DEFAULT_INPUTS)
    missing = sorted(set(_DEFAULT_INPUTS) - found_on_disk)
    if missing:
        print(f"note: {len(missing)} evidence source(s) not found on disk (skipped): "
              + ", ".join(missing))

    rows = build_union_rows(evidence)
    out_path = Path(args.out)
    if not out_path.is_absolute():
        out_path = repo_root / out_path
    write_union(rows, out_path)

    unexplained = [r for r in rows if not r["explained"]]
    print(f"[SIGNATURE EVIDENCE UNION] {len(rows)} addresses -> {out_path}")
    print(f"  unexplained structural divergence: {len(unexplained)}")
    if args.strict and unexplained:
        print(f"strict: {len(unexplained)} unexplained structural divergence row(s):")
        for r in unexplained[:10]:
            print(f"    - 0x{r['address']:08x} {r['name']}: {r['structural_category']}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
