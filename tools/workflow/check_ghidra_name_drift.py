#!/usr/bin/env python3
"""Offline gate: the Ghidra export must not contradict the authoritative source names.

`config/symbols.csv` is the source of truth for what class owns each address. The
Ghidra DB (and its `src/ghidra_autogen/` reflection) is *derived* from source and must
converge to it — but nothing enforced that, so names drifted independently: a function
renamed/re-attributed in source keeps its stale Ghidra name until someone remembers to
re-sync the DB. The decisive example is address 0x004c6740, curated in `symbols.csv` as
``TLongintList::InsertLast`` but still emitted by the autogen as
``TSoundChannelNode::SoundChannelNodeDummy00`` (TSoundChannelNode was a junk provisional
name explicitly retired when the class was recovered as the MacApp ``TLongintList``).

This gate is **offline** (no Ghidra) — it reads `config/symbols.csv` and the
``// GHIDRA_FUNCTION``/``// GHIDRA_NAME`` comments the autogen already carries. It flags:

1. **class-namespace drift** — a source-owned address whose autogen ``GHIDRA_NAME`` sits
   in a *different class namespace* than `symbols.csv` says (the TSoundChannelNode case).
2. **stale class buckets** — a `src/ghidra_autogen/<Class>.cpp` bucket none of whose
   addresses are still owned by ``<Class>`` in `symbols.csv`.

It intentionally does *not* gate method-name-only lag within the correct class (routine
churn between DB re-syncs). It is a **ratchet**: existing drift is grandfathered in
`config/ghidra_name_drift_baseline.csv`; a NEW class-drift or stale bucket fails, and
fixing one lets `--write-baseline` shrink the queue toward zero.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

from tools.common.pipe_csv import read_pipe_rows
from tools.common.repo import repo_root_from_file

SYMBOLS = "config/symbols.csv"
AUTOGEN_DIR = "src/ghidra_autogen"
NAME_OVERRIDES = "config/function_name_overrides.csv"
DEFAULT_BASELINE = "config/ghidra_name_drift_baseline.csv"

_FUNC_RE = re.compile(r"//\s*GHIDRA_FUNCTION\s+IMPERIALISM\s+0x([0-9A-Fa-f]+)")
_NAME_RE = re.compile(r"//\s*GHIDRA_NAME\s+(.+)")


def class_of(qualified: str) -> str:
    return qualified.rsplit("::", 1)[0] if "::" in qualified else ""


def sanitize_stem(class_name: str) -> str:
    """Map a symbols.csv class name to the autogen bucket-filename stem.

    Ghidra sanitizes template-instantiation datatype names into filename-safe stems:
    ``<`` and ``,`` become ``_`` while ``*``, ``>`` and spaces are dropped — e.g.
    ``CList<long,long>`` -> ``CList_long_long`` and
    ``CArray<void*,void*>`` -> ``CArray_void_void``. The autogen ``GHIDRA_NAME`` keeps
    the template syntax, so class-namespace drift compares apples to apples, but the
    *bucket filename* is sanitized; without this normalization every owned template
    bucket is falsely reported stale.
    """
    return (
        class_name.replace("<", "_")
        .replace(",", "_")
        .replace("*", "")
        .replace(">", "")
        .replace(" ", "")
    )


def norm_addr(raw: str) -> str:
    return raw.strip().lower().removeprefix("0x").zfill(8)


def load_symbols(repo: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for row in read_pipe_rows(repo / SYMBOLS):
        addr = (row.get("address") or "").strip()
        name = (row.get("name") or "").strip()
        if name and re.fullmatch(r"[0-9a-fA-F]+", addr):
            out[norm_addr(addr)] = name
    return out


def load_autogen(repo: Path) -> list[tuple[str, str, str]]:
    """Return (addr, ghidra_name, bucket_stem) for every autogen GHIDRA_FUNCTION."""
    rows: list[tuple[str, str, str]] = []
    for f in sorted((repo / AUTOGEN_DIR).rglob("*.cpp")):
        addr: str | None = None
        for line in f.read_text(encoding="utf-8", errors="ignore").splitlines():
            m = _FUNC_RE.match(line)
            if m:
                addr = norm_addr(m.group(1))
                continue
            m = _NAME_RE.match(line)
            if m and addr:
                rows.append((addr, m.group(1).strip(), f.stem))
                addr = None
    return rows


def find_drift(symbols: dict[str, str], autogen: list[tuple[str, str, str]]):
    """Return (class_drift, stale_buckets).

    class_drift: list of (addr, expected_qualified, actual_qualified)
    stale_buckets: list of (bucket, actual_class) where no address is owned by it.
    """
    class_drift: list[tuple[str, str, str]] = []
    bucket_addrs: dict[str, list[str]] = {}
    for addr, gname, bucket in autogen:
        bucket_addrs.setdefault(bucket, []).append(addr)
        exp = symbols.get(addr)
        if exp is None:
            continue
        ec, gc = class_of(exp), class_of(gname)
        if ec and gc and ec != gc:
            class_drift.append((addr, exp, gname))

    stale_buckets: list[tuple[str, str]] = []
    for bucket, addrs in bucket_addrs.items():
        owned_here = any(
            class_of(symbols.get(a, "")) == bucket
            or sanitize_stem(class_of(symbols.get(a, ""))) == bucket
            for a in addrs
        )
        if not owned_here and any(a in symbols for a in addrs):
            stale_buckets.append((bucket, bucket))
    return class_drift, stale_buckets


def find_override_drift(repo: Path, symbols: dict[str, str]) -> list[tuple[str, str, str]]:
    """Override entries that contradict symbols.csv, i.e. would revert a curated name.

    `config/function_name_overrides.csv` is applied to the Ghidra export *after* the
    curated-symbols merge, so a stale override entry silently reverts a rename that was
    made in symbols.csv/source (the TDiplomacyMgr::IsNationSlotEligibleForEventProcessing
    -> WrapperFor_...At413250 reversion). symbols.csv is authoritative: an override at a
    curated address must match it (or not exist). This is a hard invariant, not ratcheted.
    """
    path = repo / NAME_OVERRIDES
    if not path.is_file():
        return []
    out: list[tuple[str, str, str]] = []
    for row in read_pipe_rows(path):
        raw = (row.get("address") or "").strip()
        if not re.fullmatch(r"(?:0x)?[0-9a-fA-F]+", raw):
            continue
        addr = norm_addr(raw)
        oname = (row.get("name") or "").strip()
        curated = symbols.get(addr)
        if curated and oname and curated != oname:
            out.append((addr, curated, oname))
    return out


def read_baseline(path: Path) -> set[str]:
    if not path.is_file():
        return set()
    out: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if s and not s.startswith("#") and s != "key":
            out.add(s)
    return out


def keys_for(class_drift, stale_buckets) -> set[str]:
    keys = {f"fn|{a}|{class_of(g)}" for a, _e, g in class_drift}
    keys |= {f"bucket|{b}" for b, _c in stale_buckets}
    return keys


def main() -> int:
    repo = repo_root_from_file(__file__)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", default=str(repo / DEFAULT_BASELINE))
    parser.add_argument("--write-baseline", action="store_true")
    args = parser.parse_args()

    symbols = load_symbols(repo)
    autogen = load_autogen(repo)
    class_drift, stale_buckets = find_drift(symbols, autogen)
    keys = keys_for(class_drift, stale_buckets)
    override_drift = find_override_drift(repo, symbols)

    baseline_path = Path(args.baseline)
    if args.write_baseline:
        lines = ["key"] + sorted(keys)
        baseline_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"Wrote ghidra-name-drift baseline: {baseline_path} ({len(keys)} entries)")
        return 0

    baseline = read_baseline(baseline_path)
    new = sorted(keys - baseline)
    resolved = sorted(baseline - keys)

    print(
        f"ghidra-name-drift: {len(class_drift)} class-drift + {len(stale_buckets)} "
        f"stale-bucket(s) (baseline {len(baseline)})"
    )
    if resolved:
        print(f"  {len(resolved)} baselined drift(s) resolved — run --write-baseline to shrink.")
    if new:
        print("ghidra-name-drift gate failed: new DB/source name divergence (source is authoritative).")
        print("Re-sync the DB to the source name (push-source-names / ghidra-rename-class), then re-export.")
        drift_by_key = {f"fn|{a}|{class_of(g)}": (a, e, g) for a, e, g in class_drift}
        for k in new:
            if k in drift_by_key:
                a, e, g = drift_by_key[k]
                print(f"    - 0x{a}: symbols.csv={e!r} but autogen={g!r}")
            else:
                print(f"    - stale class bucket: {k.split('|', 1)[1]}")
        return 1

    # Override drift is a HARD invariant (not ratcheted): a stale function_name_overrides
    # row is applied after the curated merge and silently reverts a curated rename.
    if override_drift:
        print("ghidra-name-drift gate failed: config/function_name_overrides.csv contradicts "
              "symbols.csv (a stale override would revert a curated rename on the next sync).")
        for a, curated, oname in override_drift:
            print(f"    - 0x{a}: symbols.csv={curated!r} but override={oname!r}")
        return 1

    print("ghidra-name-drift gate passed (no new divergence).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
