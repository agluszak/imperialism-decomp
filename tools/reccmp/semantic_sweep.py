#!/usr/bin/env python3
"""Mass behavioural-divergence sweep across every compared function.

Joins reccmp's structured machine-level verdicts with the p-code call-contract
report and partitions the population by what actually matters: functions where
the recompiled game plausibly BEHAVES differently from retail (wrong callee,
wrong arguments, missing calls, wrong data or control flow).  Compiler-shape
noise -- inline-collapsed base ctors/dtors, provenance wobble -- is positively
identified, labeled, and suppressed from the actionable tiers, never emitted
as work.

Tiers:
  1  proven divergence   reccmp ``mismatch`` (the trusted machine-level proof),
                         grouped by behavioural defect class
  2  contract divergence call-contract mismatch on rows reccmp cannot prove,
                         auto-classified from the missing/extra call multisets
  3  no verdict          neither engine can say anything -- the residual blind
                         spot, sized by inconclusive reason
Proven-clean rows (reccmp exact/effective) are excluded from attention; the
machine-level oracle stays authoritative (Hard Rule 14).

Ranking deliberately ignores the raw match score -- for this population it is
noise.  Usage:

    just sweep [--limit 25] [--json out.json] [--csv out.csv]
               [--include-library]
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from tools.common.pipe_csv import read_pipe_rows
from tools.common.repo import repo_root_from_file
from tools.common.symbols import names_by_address, ownership_by_address

REPO_ROOT = repo_root_from_file(__file__)

# reccmp difference kinds grouped by how directly they describe behaviour.
DEFECT_CLASSES: tuple[tuple[str, frozenset[str]], ...] = (
    ("wrong-call", frozenset({"call_target", "call_argument"})),
    ("wrong-control-flow", frozenset({"branch_condition", "branch_target"})),
    (
        "wrong-data",
        frozenset(
            {"memory_value", "immediate_value", "return_value", "memory_address"}
        ),
    ),
    ("state", frozenset({"preserved_state"})),
    ("identity", frozenset({"symbol_resolution"})),
)
DEFECT_CLASS_RANK = {
    name: rank for rank, (name, _kinds) in enumerate(DEFECT_CLASSES)
}

# Contract-classifier buckets, most severe first.  ``chain_unverified`` ranks
# with different_callee: a ctor/dtor pair whose inheritance chain could not be
# verified must stay actionable (fail open).
CONTRACT_BUCKET_RANK = {
    "different_callee": 0,
    "chain_unverified": 0,
    "missing_call": 1,
    "extra_call": 1,
    "same_callee_arity": 2,
    "kind_flip": 3,
}
SUPPRESSED_BUCKETS = frozenset({"inline_collapse_ctor_dtor", "provenance_noise"})

CTOR_DTOR_MARKERS = ("`scalar deleting destructor'", "`vector deleting destructor'")


def defect_class(kind: str) -> str:
    for name, kinds in DEFECT_CLASSES:
        if kind in kinds:
            return name
    return "other"


def load_reccmp_by_addr(path: Path) -> dict[int, dict[str, Any]]:
    value = json.loads(path.read_text(encoding="utf-8"))
    data = value.get("data")
    if value.get("format") != 1 or not isinstance(data, list):
        raise ValueError(f"{path} is not a current reccmp JSON report")
    out: dict[int, dict[str, Any]] = {}
    for entity in data:
        if not isinstance(entity, dict) or entity.get("type") != 1:
            continue
        if not isinstance(entity.get("comparison"), dict):
            raise ValueError(f"{path} lacks structured comparison results")
        out[int(entity["address"], 16)] = entity
    return out


def load_contract_by_addr(path: Path) -> dict[int, dict[str, Any]] | None:
    if not path.is_file():
        return None
    value = json.loads(path.read_text(encoding="utf-8"))
    functions = value.get("functions")
    if not isinstance(functions, list):
        return None
    return {int(row["original"], 16): row for row in functions}


def load_sizes(repo_root: Path) -> dict[int, int]:
    out: dict[int, int] = {}
    for row in read_pipe_rows(repo_root / "config" / "original_entities.csv"):
        try:
            address = int(row.get("address", ""), 16)
            size = int(row.get("size") or 0)
        except ValueError:
            continue
        out[address] = size
    return out


def load_datacmp_flags(repo_root: Path) -> dict[str, str]:
    path = repo_root / "config" / "baselines" / "datacmp_baseline.csv"
    if not path.is_file():
        return {}
    return {
        str(row.get("name", "")): str(row.get("status", ""))
        for row in read_pipe_rows(path)
        if row.get("status") in {"WARN", "FAIL"}
    }


class CtorDtorIndex:
    """Positive-attribution inheritance oracle for inline-collapse detection."""

    def __init__(self, record_model: dict[str, Any] | None):
        self._ancestors: dict[str, set[str]] | None = None
        if record_model is None:
            return
        direct: dict[str, set[str]] = {}
        for name, record in record_model.items():
            bases = record.get("bases") or []
            direct[name] = {
                str(base.get("type", "")) for base in bases if base.get("type")
            }
        ancestors: dict[str, set[str]] = {}

        def resolve(name: str, active: frozenset[str]) -> set[str]:
            if name in ancestors:
                return ancestors[name]
            if name in active:
                return set()
            found: set[str] = set()
            for base in direct.get(name, set()):
                found.add(base)
                found |= resolve(base, active | {name})
            ancestors[name] = found
            return found

        for name in direct:
            resolve(name, frozenset())
        self._ancestors = ancestors

    @property
    def available(self) -> bool:
        return self._ancestors is not None

    def knows(self, class_name: str) -> bool:
        return self._ancestors is not None and class_name in self._ancestors

    def same_chain(self, left: str, right: str) -> bool:
        if self._ancestors is None:
            return False
        if left == right:
            return True
        return (
            left in self._ancestors.get(right, set())
            or right in self._ancestors.get(left, set())
        )

    def is_ancestor(self, ancestor: str, descendant: str) -> bool:
        if self._ancestors is None:
            return False
        return ancestor in self._ancestors.get(descendant, set())


def parse_ctor_dtor(name: str) -> tuple[str, str] | None:
    """(class, 'ctor'|'dtor') for constructor/destructor symbol names."""
    for marker in CTOR_DTOR_MARKERS:
        if name.endswith(marker):
            return name[: -len(marker)].rstrip(":"), "dtor"
    parts = name.rsplit("::", 1)
    if len(parts) != 2:
        return None
    scope, member = parts
    class_name = scope.rsplit("::", 1)[-1]
    if member == class_name:
        return scope, "ctor"
    if member == "~" + class_name:
        return scope, "dtor"
    return None


def callee_identity(call: dict[str, Any]) -> tuple[str, Any]:
    """Cross-image callee identity, receiver EXCLUDED.

    A virtual call's receiver expression lives inside its target; comparing it
    as part of identity inflates the different-callee bucket with provenance
    wobble (the bead-0b6g audit lost a full analysis pass to this).  Indirect
    targets are provenance-shaped expressions, coarsened for the same reason.
    """
    kind = call.get("kind")
    target = call.get("target")
    if kind == "direct" and isinstance(target, dict):
        function = target.get("function")
        if isinstance(function, str):
            return ("direct", function)
        external = target.get("external")
        if isinstance(external, dict):
            return (
                "direct",
                f"{external.get('library', '?')}!{external.get('symbol', '?')}",
            )
    if kind == "virtual" and isinstance(target, dict):
        return ("virtual", target.get("slot"))
    return ("indirect", None)


def _expand(rows: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []
    for row in rows or []:
        for _ in range(int(row.get("count", 1))):
            calls.append(row["call"])
    return calls


def _target_name(call: dict[str, Any], names: dict[int, str]) -> str | None:
    kind, identity = callee_identity(call)
    if kind != "direct" or not isinstance(identity, str):
        return None
    if identity.startswith("0x"):
        return names.get(int(identity, 16))
    return identity.rsplit("!", 1)[-1]


def _arg_count(call: dict[str, Any]) -> int:
    arguments = call.get("arguments")
    return len(arguments) if isinstance(arguments, list) else -1


def classify_contract_row(
    row: dict[str, Any],
    names: dict[int, str],
    ctor_index: CtorDtorIndex,
) -> dict[str, Any]:
    """Bucket a contract-mismatch row's missing/extra multisets."""
    missing = _expand(row.get("missing"))
    extra = _expand(row.get("extra"))
    buckets: Counter[str] = Counter()
    details: list[dict[str, Any]] = []

    def note(bucket: str, orig: dict | None, recomp: dict | None) -> None:
        buckets[bucket] += 1
        detail: dict[str, Any] = {"bucket": bucket}
        for label, call in (("original", orig), ("recompiled", recomp)):
            if call is None:
                continue
            kind, identity = callee_identity(call)
            named = _target_name(call, names)
            detail[label] = {
                "kind": kind,
                "identity": identity,
                "name": named,
                "argument_count": _arg_count(call),
            }
        details.append(detail)

    # Phase 1: same callee identity on both sides -> provenance or arity.
    remaining_extra = list(extra)
    unpaired_missing: list[dict[str, Any]] = []
    for call in missing:
        identity = callee_identity(call)
        match_index = next(
            (
                index
                for index, other in enumerate(remaining_extra)
                if callee_identity(other) == identity
            ),
            None,
        )
        if match_index is None:
            unpaired_missing.append(call)
            continue
        other = remaining_extra.pop(match_index)
        if _arg_count(call) != _arg_count(other):
            note("same_callee_arity", call, other)
        else:
            note("provenance_noise", call, other)

    # Phase 2: ctor/dtor pairs on one inheritance chain -> inline collapse.
    # Suppression requires POSITIVE attribution: both calls must be ctors (or
    # both dtors) of classes the record model places on one chain.  Unknown
    # classes stay actionable as chain_unverified -- a genuinely wrong callee
    # must never hide behind an unproven hierarchy claim.
    still_missing: list[dict[str, Any]] = []
    for call in unpaired_missing:
        name = _target_name(call, names)
        parsed = parse_ctor_dtor(name) if name else None
        if parsed is None:
            still_missing.append(call)
            continue
        match_index = None
        match_bucket = None
        for index, other in enumerate(remaining_extra):
            other_name = _target_name(other, names)
            other_parsed = parse_ctor_dtor(other_name) if other_name else None
            if other_parsed is None or other_parsed[1] != parsed[1]:
                continue
            if ctor_index.same_chain(parsed[0], other_parsed[0]):
                match_index, match_bucket = index, "inline_collapse_ctor_dtor"
                break
            if not (
                ctor_index.knows(parsed[0]) and ctor_index.knows(other_parsed[0])
            ):
                match_index, match_bucket = index, "chain_unverified"
                break
        if match_index is None:
            still_missing.append(call)
            continue
        note(match_bucket or "chain_unverified", call, remaining_extra.pop(match_index))

    # Phase 3: identical argument lists, direct vs virtual/indirect -> a
    # classification flip by the two decompilers, not a different callee.
    final_missing: list[dict[str, Any]] = []
    for call in still_missing:
        match_index = next(
            (
                index
                for index, other in enumerate(remaining_extra)
                if callee_identity(other)[0] != callee_identity(call)[0]
                and call.get("arguments") == other.get("arguments")
                and isinstance(call.get("arguments"), list)
            ),
            None,
        )
        if match_index is None:
            final_missing.append(call)
            continue
        note("kind_flip", call, remaining_extra.pop(match_index))

    # Phase 4: one-sided inlined ancestor ctor/dtor bodies inside the
    # containing function's own ctor/dtor collapse without a counterpart.
    containing = parse_ctor_dtor(str(row.get("name", "")))
    leftovers: list[dict[str, Any]] = []
    for call in final_missing:
        name = _target_name(call, names)
        parsed = parse_ctor_dtor(name) if name else None
        if (
            parsed is not None
            and containing is not None
            and ctor_index.is_ancestor(parsed[0], containing[0])
        ):
            note("inline_collapse_ctor_dtor", call, None)
            continue
        leftovers.append(call)

    # Phase 5: leftovers pair as wrong callee; one-sided rows are missing or
    # extra real work.
    for call, other in zip(leftovers, remaining_extra):
        note("different_callee", call, other)
    for call in leftovers[len(remaining_extra) :]:
        note("missing_call", call, None)
    for other in remaining_extra[len(leftovers) :]:
        note("extra_call", None, other)

    actionable = {
        bucket: count
        for bucket, count in buckets.items()
        if bucket not in SUPPRESSED_BUCKETS
    }
    return {
        "buckets": dict(buckets),
        "details": details,
        "actionable": actionable,
        "divergent": bool(actionable),
    }


def _difference_symbols(comparison: dict[str, Any]) -> set[str]:
    symbols: set[str] = set()
    difference = comparison.get("difference")
    if not isinstance(difference, dict):
        return symbols
    for side in ("orig", "recomp"):
        facts = (difference.get(side) or {}).get("facts")
        if isinstance(facts, dict):
            symbol = facts.get("symbol")
            if isinstance(symbol, str) and symbol:
                symbols.add(symbol)
    return symbols


def sweep(
    reccmp_by_addr: dict[int, dict[str, Any]],
    contract_by_addr: dict[int, dict[str, Any]] | None,
    names: dict[int, str],
    sizes: dict[int, int],
    ownership: dict[int, str],
    datacmp_flags: dict[str, str],
    ctor_index: CtorDtorIndex,
    include_library: bool = False,
) -> dict[str, Any]:
    tier1: list[dict[str, Any]] = []
    tier2: list[dict[str, Any]] = []
    tier3: list[dict[str, Any]] = []
    clean = 0
    suppressed_rows: list[dict[str, Any]] = []

    addresses = set(reccmp_by_addr)
    if contract_by_addr:
        addresses |= set(contract_by_addr)

    for address in sorted(addresses):
        if not include_library and ownership.get(address) == "library":
            continue
        entity = reccmp_by_addr.get(address)
        comparison = (entity or {}).get("comparison") or {}
        status = comparison.get("status")
        contract = (contract_by_addr or {}).get(address)
        base = {
            "address": f"0x{address:x}",
            "name": (entity or {}).get("name")
            or (contract or {}).get("name")
            or names.get(address, ""),
            "size": sizes.get(address, 0),
            "reccmp_status": status,
        }

        if status in ("exact", "effective"):
            clean += 1
            continue

        if status == "mismatch":
            kind = str((comparison.get("difference") or {}).get("kind", ""))
            corroborated = sorted(
                symbol
                for symbol in _difference_symbols(comparison)
                if symbol in datacmp_flags
            )
            tier1.append(
                {
                    **base,
                    "kind": kind,
                    "defect_class": defect_class(kind),
                    "datacmp": corroborated,
                }
            )
            continue

        contract_status = (contract or {}).get("status")
        if contract is not None and contract_status == "mismatch":
            diagnosis = classify_contract_row(contract, names, ctor_index)
            if diagnosis["divergent"]:
                worst = min(
                    (
                        CONTRACT_BUCKET_RANK.get(bucket, 0)
                        for bucket in diagnosis["actionable"]
                    ),
                    default=len(CONTRACT_BUCKET_RANK),
                )
                tier2.append(
                    {
                        **base,
                        "contract_reason": contract.get("reason"),
                        "buckets": diagnosis["buckets"],
                        "details": diagnosis["details"],
                        "severity": worst,
                        "divergent_calls": sum(diagnosis["actionable"].values()),
                    }
                )
                continue
            suppressed_rows.append(
                {**base, "buckets": diagnosis["buckets"]}
            )
            continue

        tier3.append(
            {
                **base,
                "inconclusive_reason": comparison.get("inconclusive_reason"),
                "contract_status": contract_status,
                "contract_reason": (contract or {}).get("reason"),
            }
        )

    tier1.sort(
        key=lambda row: (
            DEFECT_CLASS_RANK.get(row["defect_class"], len(DEFECT_CLASS_RANK)),
            -len(row["datacmp"]),
            -row["size"],
            row["address"],
        )
    )
    tier2.sort(
        key=lambda row: (
            row["severity"],
            -row["divergent_calls"],
            -row["size"],
            row["address"],
        )
    )
    tier3.sort(key=lambda row: (-row["size"], row["address"]))
    return {
        "tier1_proven_divergence": tier1,
        "tier2_contract_divergence": tier2,
        "tier3_no_verdict": tier3,
        "suppressed_noise": suppressed_rows,
        "proven_clean": clean,
    }


def _print_summary(result: dict[str, Any], limit: int) -> None:
    tier1 = result["tier1_proven_divergence"]
    tier2 = result["tier2_contract_divergence"]
    tier3 = result["tier3_no_verdict"]
    suppressed = result["suppressed_noise"]

    print("== semantic sweep: behavioural divergence candidates ==")
    print(
        f"proven-clean {result['proven_clean']}  |  tier1 proven {len(tier1)}"
        f"  |  tier2 contract {len(tier2)}  |  tier3 no-verdict {len(tier3)}"
        f"  |  suppressed-noise rows {len(suppressed)}"
    )

    print(f"\n-- tier 1: proven divergence (reccmp mismatch), top {limit} --")
    print(
        "   by class:",
        dict(Counter(row["defect_class"] for row in tier1)),
    )
    for row in tier1[:limit]:
        corroborated = f"  datacmp:{','.join(row['datacmp'])}" if row["datacmp"] else ""
        print(
            f"  {row['address']}  {row['defect_class']:<18} {row['kind']:<16}"
            f" {row['size']:>6}B  {row['name'][:56]}{corroborated}"
        )
        print(f"      -> just triage {row['address']}")

    print(f"\n-- tier 2: contract divergence on unproven rows, top {limit} --")
    bucket_totals: Counter[str] = Counter()
    for row in tier2:
        bucket_totals.update(row["buckets"])
    print("   by bucket:", dict(bucket_totals))
    for row in tier2[:limit]:
        actionable = {
            bucket: count
            for bucket, count in row["buckets"].items()
            if bucket not in SUPPRESSED_BUCKETS
        }
        print(
            f"  {row['address']}  {row['size']:>6}B  {row['name'][:56]}  {actionable}"
        )

    print("\n-- tier 3: no verdict (residual blind spot) --")
    crosstab = Counter(
        (
            str(row.get("inconclusive_reason")),
            str(row.get("contract_status")),
        )
        for row in tier3
    )
    for (reason, contract_status), count in crosstab.most_common():
        print(f"  {count:>5}  reccmp={reason:<26} contract={contract_status}")


def _write_csv(result: dict[str, Any], path: Path) -> None:
    import csv

    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(
            ["tier", "address", "name", "size", "class_or_buckets", "detail"]
        )
        for row in result["tier1_proven_divergence"]:
            writer.writerow(
                [
                    1,
                    row["address"],
                    row["name"],
                    row["size"],
                    row["defect_class"],
                    row["kind"],
                ]
            )
        for row in result["tier2_contract_divergence"]:
            actionable = {
                bucket: count
                for bucket, count in row["buckets"].items()
                if bucket not in SUPPRESSED_BUCKETS
            }
            writer.writerow(
                [
                    2,
                    row["address"],
                    row["name"],
                    row["size"],
                    json.dumps(actionable, sort_keys=True),
                    row.get("contract_reason", ""),
                ]
            )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="IMPERIALISM")
    parser.add_argument(
        "--build-dir", default=str(REPO_ROOT / "build-msvc500")
    )
    parser.add_argument("--report-json", default="")
    parser.add_argument("--semantic-json", default="")
    parser.add_argument("--limit", type=int, default=25)
    parser.add_argument("--json", dest="json_out", default="")
    parser.add_argument("--csv", dest="csv_out", default="")
    parser.add_argument("--include-library", action="store_true")
    args = parser.parse_args()

    build_dir = Path(args.build_dir)
    report_path = (
        Path(args.report_json)
        if args.report_json
        else build_dir / "reccmp_report.json"
    )
    if not report_path.is_file():
        print(
            f"missing {report_path}; run `just stats` to generate the reccmp report",
            file=sys.stderr,
        )
        return 1
    semantic_path = (
        Path(args.semantic_json)
        if args.semantic_json
        else build_dir / "semantic" / "semantic_report.json"
    )
    contract_by_addr = load_contract_by_addr(semantic_path)
    if contract_by_addr is None:
        print(
            f"note: {semantic_path} not found -- tier 2 is empty; run"
            " `just semantic-gate --generate-if-stale` for call contracts",
            file=sys.stderr,
        )

    record_model_path = build_dir / "generated" / "record_model.json"
    record_model = (
        json.loads(record_model_path.read_text(encoding="utf-8"))
        if record_model_path.is_file()
        else None
    )
    ctor_index = CtorDtorIndex(record_model)
    if not ctor_index.available:
        print(
            f"note: {record_model_path} not found -- inline-collapse suppression"
            " disabled; ctor/dtor pairs stay actionable as chain_unverified",
            file=sys.stderr,
        )

    result = sweep(
        load_reccmp_by_addr(report_path),
        contract_by_addr,
        names_by_address(REPO_ROOT),
        load_sizes(REPO_ROOT),
        ownership_by_address(REPO_ROOT),
        load_datacmp_flags(REPO_ROOT),
        ctor_index,
        include_library=args.include_library,
    )

    _print_summary(result, args.limit)
    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps(result, indent=1, sort_keys=True), encoding="utf-8"
        )
        print(f"\nfull partition: {args.json_out}")
    if args.csv_out:
        _write_csv(result, Path(args.csv_out))
        print(f"actionable worklist: {args.csv_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
