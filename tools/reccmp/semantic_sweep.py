#!/usr/bin/env python3
"""Mass behavioural-divergence sweep across every compared function.

Joins reccmp's structured machine-level verdicts with the p-code call-contract
report and partitions the population by what actually matters: functions where
the recompiled game plausibly BEHAVES differently from retail (wrong callee,
wrong arguments, missing calls, wrong data or control flow).  Compiler-shape
noise -- inline-collapsed base ctors/dtors, provenance wobble, library value
construction -- is positively identified, labeled, and suppressed from the
actionable tiers, never emitted as work.

Correspondence is never invented.  A `different_callee` claim means the same
values reached a different target, or that exactly one candidate remained on
each side; leftovers with no such evidence are reported as the one-sided work
they are.  (Pairing them positionally, as this once did, manufactured 23 wrong
callees for TViewMgr::ShowTerrainMap whose only real one-sided differences were
CString temporaries.)

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
import re
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
SUPPRESSED_BUCKETS = frozenset(
    {"inline_collapse_ctor_dtor", "provenance_noise", "library_value_churn"}
)

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


def _callee_address(call: dict[str, Any]) -> int | None:
    kind, identity = callee_identity(call)
    if kind != "direct" or not isinstance(identity, str) or not identity.startswith("0x"):
        return None
    return int(identity, 16)


def _is_library_construction(
    call: dict[str, Any], names: dict[int, str], ownership: dict[int, str]
) -> bool:
    """A one-sided call that only builds or tears down a library value.

    A CString temporary constructed in one image and assigned in the other is
    construction shape, not behaviour: the game state it produces is identical.
    Attribution is positive on BOTH counts -- the callee must be library-owned
    *and* parse as a constructor, destructor or assignment -- so a genuinely
    dropped game call can never reach this bucket.
    """
    address = _callee_address(call)
    if address is None or ownership.get(address) != "library":
        return False
    name = _target_name(call, names)
    if not name:
        return False
    if parse_ctor_dtor(name) is not None:
        return True
    return name.rsplit("::", 1)[-1].startswith("operator=")


def _corresponds(call: dict[str, Any], other: dict[str, Any]) -> int | None:
    """Whether two leftover calls can be said to occupy the same slot.

    Identical argument lists are the only evidence that survives scrutiny: the
    same values flowing to a different target is a wrong callee. Matching kind
    and arity is NOT evidence -- nearly every one-argument direct call matches
    every other, which is positional zipping with extra steps.

    `None` means no correspondence, and claiming a wrong-callee pair anyway
    would be an invention.
    """
    arguments = call.get("arguments")
    if isinstance(arguments, list) and arguments == other.get("arguments"):
        return 0
    return None


def classify_contract_row(
    row: dict[str, Any],
    names: dict[int, str],
    ctor_index: CtorDtorIndex,
    ownership: dict[int, str] | None = None,
) -> dict[str, Any]:
    """Bucket a contract-mismatch row's missing/extra multisets."""
    ownership = ownership or {}
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

    # Phase 5: a wrong-callee claim needs evidence that the two calls occupy the
    # same slot -- identical arguments, or at least the same kind and arity.
    # Pairing the leftovers positionally (what this used to do) manufactured
    # `different_callee` out of two calls that had nothing to do with each
    # other: TViewMgr::ShowTerrainMap reported 23 wrong callees when its only
    # one-sided differences were CString temporaries.  Strongest matches first,
    # so an exact-argument pair is never consumed by a weaker one.
    paired: list[tuple[int, int, int]] = sorted(
        (strength, call_index, extra_index)
        for call_index, call in enumerate(leftovers)
        for extra_index, other in enumerate(remaining_extra)
        for strength in (_corresponds(call, other),)
        if strength is not None
    )
    used_calls: set[int] = set()
    used_extras: set[int] = set()
    for _, call_index, extra_index in paired:
        if call_index in used_calls or extra_index in used_extras:
            continue
        used_calls.add(call_index)
        used_extras.add(extra_index)
        note("different_callee", leftovers[call_index], remaining_extra[extra_index])

    # An unambiguous 1:1 leftover is still a wrong-callee pair: with exactly one
    # candidate on each side the pairing is forced, not chosen.  Ambiguity is
    # what made positional zipping wrong, so this only applies when no choice
    # exists.
    unpaired_calls = [i for i in range(len(leftovers)) if i not in used_calls]
    unpaired_extras = [i for i in range(len(remaining_extra)) if i not in used_extras]
    if len(unpaired_calls) == 1 and len(unpaired_extras) == 1:
        used_calls.add(unpaired_calls[0])
        used_extras.add(unpaired_extras[0])
        note(
            "different_callee",
            leftovers[unpaired_calls[0]],
            remaining_extra[unpaired_extras[0]],
        )

    # Whatever is left is genuinely one-sided.  Library construction and
    # teardown is shape, not behaviour, and is labelled as such rather than
    # inflating the missing/extra work counts.
    for index, call in enumerate(leftovers):
        if index in used_calls:
            continue
        if _is_library_construction(call, names, ownership):
            note("library_value_churn", call, None)
        else:
            note("missing_call", call, None)
    for index, other in enumerate(remaining_extra):
        if index in used_extras:
            continue
        if _is_library_construction(other, names, ownership):
            note("library_value_churn", None, other)
        else:
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


_PROVENANCE_HASH = re.compile(r"#[0-9a-f]{6,}")
# Signed compare pairs that mean the same thing one step apart: `x < N` and
# `x <= N-1` are identical over integers, and MSVC picks between them freely.
_EQUIVALENT_FORMS: dict[tuple[str, str], int] = {
    ("lt_s", "le_s"): -1,
    ("le_s", "lt_s"): 1,
    ("gt_s", "ge_s"): 1,
    ("ge_s", "gt_s"): -1,
}


def _strip_provenance(text: str) -> str:
    """Drop the trailing value-provenance fingerprints reccmp renders.

    `ne:('imm', 2)#52a2881d` and `ne:('imm', 2)#b310eb7f` are the same
    comparison against the same constant; the hashes record where each side's
    operand came from, which differs whenever the two compilers schedule the
    load differently.
    """
    return _PROVENANCE_HASH.sub("", text)


def _split_trailing_int(text: str) -> tuple[str, int] | None:
    match = re.fullmatch(r"(.*?)(-?\d+)", text)
    if match is None:
        return None
    return match.group(1), int(match.group(2))


def tier1_noise(comparison: dict[str, Any]) -> str | None:
    """Name the shape when a reccmp `mismatch` describes no behavioural change.

    reccmp proves the two instruction streams differ; it does not claim the
    difference is observable.  Two shapes provably are not, and both dominated
    the ranked output until they were named:

      * the rendered facts are identical once value-provenance fingerprints are
        removed -- same operator, same operand, same constant;
      * the predicates are an equivalent signed compare pair (`< N` / `<= N-1`).

    Anything else stays actionable: this only ever suppresses on a positive
    match, never on absence of evidence.
    """
    difference = comparison.get("difference")
    if not isinstance(difference, dict):
        return None
    orig = (difference.get("orig") or {}).get("facts") or {}
    recomp = (difference.get("recomp") or {}).get("facts") or {}
    if not isinstance(orig, dict) or not isinstance(recomp, dict):
        return None

    for field in ("predicate", "value"):
        left, right = orig.get(field), recomp.get(field)
        if not isinstance(left, str) or not isinstance(right, str) or not left:
            continue
        if left == right:
            continue
        if _strip_provenance(left) == _strip_provenance(right):
            return "provenance_fingerprint"

    left, right = orig.get("predicate"), recomp.get("predicate")
    if isinstance(left, str) and isinstance(right, str):
        left, right = _strip_provenance(left), _strip_provenance(right)
        left_parts, right_parts = left.split(":", 1), right.split(":", 1)
        if len(left_parts) == 2 and len(right_parts) == 2:
            delta = _EQUIVALENT_FORMS.get((left_parts[0], right_parts[0]))
            left_split = _split_trailing_int(left_parts[1])
            right_split = _split_trailing_int(right_parts[1])
            if (
                delta is not None
                and left_split is not None
                and right_split is not None
                and left_split[0] == right_split[0]
                and right_split[1] == left_split[1] + delta
            ):
                return "equivalent_compare_form"
    return None


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
            # reccmp proved the streams differ; that is not the same as proving
            # the behaviour differs.  Named non-behavioural shapes leave tier 1.
            noise = tier1_noise(comparison)
            if noise is not None:
                suppressed_rows.append({**base, "kind": kind, "bucket": noise})
                continue
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
            diagnosis = classify_contract_row(contract, names, ctor_index, ownership)
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
