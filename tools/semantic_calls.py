#!/usr/bin/env python3
"""Strict high-p-code call-contract comparison for original/recompiled functions.

The comparator deliberately uses Ghidra objects rather than rendered assembly or
decompiler text.  Its result is one proof dimension: equal call multiplicity,
targets, receivers, and argument provenance.  reccmp's structured semantic result
remains a separate, broader dimension in the generated report.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import fcntl
import hashlib
import importlib.metadata
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence

from reccmp.compare import Compare
from reccmp.compare.db import ReccmpMatch
from reccmp.project.detect import RecCmpProject, RecCmpTarget
from reccmp.types import ImageId

from tools.common import ghidra_env
from tools.common.repo import repo_root_from_file
from tools.common.template_aliases import (
    CLASS_FOLDED_SYMBOL_GROUP,
    CLASS_LIBRARY_CALLEE_ALIAS,
    load_aliases,
)
from tools.binary.pe import load_decorated_symbols
from tools.mfc.reviewed_identities import ReviewedIdentity, load_reviewed_identities
from tools.source_model import Claim, build_model

SCHEMA_VERSION = 3
# The ratchet file has its own schema: the report format may evolve without
# rewriting the baseline (a bumped number there reads as growth to baseline_guard).
BASELINE_SCHEMA_VERSION = 3
PREP_SCHEMA_VERSION = 2
DEFAULT_TIMEOUT_SECONDS = 30
MAX_EXPRESSION_NODES = 4096
PROJECT_NAME = "recompiled-semantic"
PROGRAM_NAME = "Imperialism.exe"
# Keep the current cache plus one predecessor so a quick branch switch back does
# not pay a rebuild; anything older is dead weight (~46 MB per fingerprint).
CACHE_KEEP_COUNT = 2
TARGETED_REPORT_MAX_AGE_SECONDS = 7 * 24 * 3600
# Analyzers the call-contract proof does not depend on.  Decompiler Parameter ID
# must stay off so per-function decompilation depends only on the function's own
# bytes plus imported prototypes, never on whole-program parameter propagation.
DISABLED_ANALYZERS = (
    "Decompiler Parameter ID",
    "Embedded Media",
)
# Bytes of referenced data hashed into a row's reuse record; a shorter probe is
# used near section ends.  Content drift past the probe window in a referenced
# string is not detected by reuse (run `just semantic-verify` to audit).
DATA_PROBE_BYTES = 256
DATA_PROBE_FALLBACK_BYTES = 16
REUSE_DISABLE_ENV = "SEMANTIC_NO_REUSE"
PRECISION_AUDIT_ENV = "SEMANTIC_AUDIT_PRECISION"
REPORT_RELATIVE_PATH = Path("semantic") / "semantic_report.json"
# Audit runs (SEMANTIC_AUDIT_PRECISION=1) write here instead: the two modes
# compute different row sets, and sharing one file made each mode clobber the
# other's per-row reuse records, forcing a full recompute on every alternation.
AUDIT_REPORT_RELATIVE_PATH = Path("semantic") / "semantic_report.audit.json"
ORIG_CALLS_CACHE_RELATIVE_PATH = Path("semantic") / "orig_calls_cache.json"
BASELINE_RELATIVE_PATH = (
    Path("config") / "baselines" / "semantic_call_contract_baseline.json"
)


def _full_report_relative_path() -> Path:
    if os.environ.get(PRECISION_AUDIT_ENV) == "1":
        return AUDIT_REPORT_RELATIVE_PATH
    return REPORT_RELATIVE_PATH

STRIP_OPS = frozenset({"COPY", "CAST"})
# Compiler frame scaffolding excluded from the source-level call contract.
# A callee may enter this list ONLY if all three hold: (a) it has no
# source-level operands, (b) it exists purely to establish or tear down
# compiler-managed frame state, and (c) its emission is fully determined by
# machine facts another gate proves (reccmp's byte-level comparison sees the
# EH frame directly).  Named functions whose bodies exist in C++ source --
# inlined base ctors/dtors such as CWnd::~CWnd, _chkstk-style stack probes
# with a size operand, vector ctor/dtor iterators -- never qualify: their
# calls are source semantics and their absence is real porting signal.
# Matched by exact (thunk-resolved) callee name; Ghidra applies a call-fixup
# to the recompiled image's __EH_prolog so only the original side emits the
# CALL op at all.
SCAFFOLDING_CALLEE_NAMES = frozenset({"EH_prolog", "_EH_prolog", "__EH_prolog"})
# Result widths that follow the decompiler's inferred operand types rather than the
# machine encoding.  LOAD/PIECE/SUBPIECE are excluded on purpose: their widths are
# a real access size, not a declared type.
WIDTH_AGNOSTIC_OPS = frozenset(
    {
        "int_add",
        "int_mult",
        "int_sub",
        "int_and",
        "int_or",
        "int_xor",
        "int_left",
        "int_right",
        "int_sright",
        "int_negate",
        "int_2comp",
        "multiequal",
    }
)
COMMUTATIVE_OPS = frozenset(
    {
        "INT_ADD",
        "INT_MULT",
        "INT_AND",
        "INT_OR",
        "INT_XOR",
        "INT_EQUAL",
        "INT_NOTEQUAL",
        "BOOL_AND",
        "BOOL_OR",
        "BOOL_XOR",
        "FLOAT_ADD",
        "FLOAT_MULT",
        "FLOAT_EQUAL",
        "FLOAT_NOTEQUAL",
    }
)
SUPPORTED_OPS = frozenset(
    {
        *COMMUTATIVE_OPS,
        "INT_SUB",
        "INT_DIV",
        "INT_SDIV",
        "INT_REM",
        "INT_SREM",
        "INT_LEFT",
        "INT_RIGHT",
        "INT_SRIGHT",
        "INT_LESS",
        "INT_SLESS",
        "INT_LESSEQUAL",
        "INT_SLESSEQUAL",
        "INT_NEGATE",
        "INT_2COMP",
        "INT_CARRY",
        "INT_SCARRY",
        "INT_SBORROW",
        "BOOL_NEGATE",
        "FLOAT_SUB",
        "FLOAT_DIV",
        "FLOAT_NEG",
        "FLOAT_ABS",
        "FLOAT_SQRT",
        "FLOAT_NAN",
        "FLOAT_LESS",
        "FLOAT_LESSEQUAL",
        "FLOAT_INT2FLOAT",
        "FLOAT_FLOAT2FLOAT",
        "INT2FLOAT",
        "FLOAT2FLOAT",
        "FLOAT_TRUNC",
        "FLOAT_CEIL",
        "FLOAT_FLOOR",
        "FLOAT_ROUND",
        "INT_ZEXT",
        "INT_SEXT",
        "PIECE",
        "SUBPIECE",
        "PTRADD",
        "PTRSUB",
        "LOAD",
        "MULTIEQUAL",
        "INDIRECT",
    }
)


class UnresolvedExpression(RuntimeError):
    """Raised when a value cannot be related across the two image layouts."""


class DepRecorder:
    """Collect one row's cross-run dependencies during extraction.

    A recorded row may be reused on a later run without Ghidra when every
    dependency still resolves identically:
    - ``entity``/``map_fn``/``miss`` events replay against the fresh reccmp maps;
    - ``data``/``nonmem`` events replay against the fresh recompiled image bytes;
    - ``fn_pair`` events replay against the fresh per-entity identity digests.
    Recomp-side Ghidra symbol names that reach the normalized contract have no
    cheap replay, so they mark the row fragile (never reused).
    """

    def __init__(self) -> None:
        self.events: set[tuple[Any, ...]] = set()
        self.fragile = False

    @staticmethod
    def _tag(image_id: ImageId) -> str:
        return "orig" if image_id == ImageId.ORIG else "recomp"

    def entity(
        self, image_id: ImageId, offset: int, entity_type: int, original: int
    ) -> None:
        self.events.add(("entity", self._tag(image_id), offset, entity_type, original))

    def map_fn(self, image_id: ImageId, offset: int, mapped: int) -> None:
        self.events.add(("map_fn", self._tag(image_id), offset, mapped))

    def miss(self, image_id: ImageId, offset: int) -> None:
        self.events.add(("miss", self._tag(image_id), offset))

    def fn_pair(self, original: int) -> None:
        self.events.add(("fn_pair", original))

    def pairs_dep(self) -> None:
        """Row is valid only while the full pairing set is unchanged."""
        self.events.add(("pairs_fp",))

    def data(self, image_id: ImageId, offset: int) -> None:
        if image_id == ImageId.RECOMP:
            self.events.add(("data", "recomp", offset))

    def nonmem(self, image_id: ImageId, offset: int) -> None:
        if image_id == ImageId.RECOMP:
            self.events.add(("nonmem", "recomp", offset))

    def mark_fragile(self) -> None:
        self.fragile = True


def _orig_calls_entry(
    extracted: "ExtractedCalls", recorder: DepRecorder
) -> dict[str, Any]:
    """JSON-stable snapshot of one function's original-side extraction.

    Taken immediately after the original side extracts, while the shared
    recorder holds only original-side events.  The original image is
    immutable, so the snapshot stays valid as long as the cache key (the row
    context plus the original entity/function maps and the decompile timeout)
    is unchanged -- both sides of every recomputed row were paying the
    decompile cost even though only the recompiled side can change.
    """
    return {
        "calls": extracted.calls,
        "unresolved": list(extracted.unresolved),
        "events": sorted(list(event) for event in recorder.events),
        "fragile": recorder.fragile,
    }


def _restore_orig_calls(
    entry: dict[str, Any], recorder: DepRecorder
) -> "ExtractedCalls":
    """Rebuild a cached extraction and replay its dependency events."""
    for event in entry.get("events", []):
        recorder.events.add(tuple(event))
    if entry.get("fragile"):
        recorder.mark_fragile()
    return ExtractedCalls(
        calls=list(entry.get("calls", [])),
        unresolved=list(entry.get("unresolved", [])),
    )


def _load_orig_calls_cache(path: Path, key: str) -> dict[str, Any]:
    try:
        stored = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if stored.get("key") != key:
        return {}
    rows = stored.get("rows")
    return rows if isinstance(rows, dict) else {}


@dataclass(frozen=True)
class FunctionPair:
    original: int
    recompiled: int


@dataclass
class ExtractedCalls:
    calls: list[dict[str, Any]]
    unresolved: list[str]


@dataclass(frozen=True)
class DirectCallABI:
    parameter_count: int
    has_this: bool
    has_varargs: bool = False


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _canonical_arithmetic(mnemonic: str, size: int, values: list[Any]) -> Any:
    """Flatten associative integer arithmetic and fold width-sized constants."""
    flattened: list[Any] = []
    tag = mnemonic.lower()
    for value in values:
        if (
            isinstance(value, list)
            and len(value) >= 2
            and value[0] == tag
            and value[1] == size
        ):
            flattened.extend(value[2:])
        else:
            flattened.append(value)

    constants = [
        int(value[2])
        for value in flattened
        if isinstance(value, list)
        and len(value) == 3
        and value[0] == "constant"
    ]
    others = [
        value
        for value in flattened
        if not (
            isinstance(value, list)
            and len(value) == 3
            and value[0] == "constant"
        )
    ]
    modulus = 1 << (size * 8)
    if mnemonic == "INT_ADD":
        folded = sum(constants) % modulus
        if folded or not others:
            others.append(["constant", size, folded])
    else:
        folded = 1
        for constant in constants:
            folded = (folded * constant) % modulus
        if folded == 0:
            return ["constant", size, 0]
        if folded != 1 or not others:
            others.append(["constant", size, folded])
    if len(others) == 1:
        return others[0]
    others.sort(key=canonical_json)
    return [tag, size, *others]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_json(path: Path, value: Any, *, indent: int | None = 2) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = path.stat().st_mode & 0o777 if path.exists() else 0o644
    fd, raw_temp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temp = Path(raw_temp)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=indent, sort_keys=True)
            stream.write("\n")
        temp.chmod(mode)
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def _default_jobs() -> int:
    override = os.environ.get("SEMANTIC_JOBS")
    if override:
        return max(1, int(override))
    return min(32, os.cpu_count() or 1)


def _distribution_source() -> str:
    distribution = importlib.metadata.distribution("reccmp")
    return distribution.read_text("direct_url.json") or distribution.version


def _claims_payload(claims: Iterable[Claim]) -> list[dict[str, Any]]:
    return [asdict(claim) for claim in sorted(claims, key=lambda item: item.address)]


def required_claims(repo_root: Path) -> list[Claim]:
    model = build_model(repo_root)
    return sorted(
        (
            claim
            for claim in model.functions.values()
            if claim.kind == "FUNCTION" and claim.origin == "marker"
        ),
        key=lambda claim: claim.address,
    )


def ownership_counts(repo_root: Path) -> dict[str, int]:
    model = build_model(repo_root)
    counts = Counter(
        f"{claim.kind.lower()}:{claim.origin}"
        for claim in model.functions.values()
    )
    return dict(sorted(counts.items()))


def _fingerprint_files(paths: Iterable[Path]) -> dict[str, str]:
    return {
        str(path): sha256_file(path)
        for path in sorted(set(paths))
        if path.is_file()
    }


def cache_inputs(
    repo_root: Path, target: RecCmpTarget, claims: Sequence[Claim]
) -> dict[str, Any]:
    build_dir = target.recompiled_path.parent
    paths = [
        target.recompiled_path,
        target.recompiled_pdb,
        repo_root / "reccmp-project.yml",
        build_dir / "reccmp-build.yml",
        repo_root / "config" / "original_entities.csv",
        repo_root / "config" / "recovered_globals.csv",
    ]
    version, release = ghidra_env.expected_versions()
    return {
        "schema": PREP_SCHEMA_VERSION,
        "files": _fingerprint_files(paths),
        "ghidra": {"version": version, "release": release},
        "pyghidra": importlib.metadata.version("pyghidra"),
        "reccmp": _distribution_source(),
        "disabled_analyzers": list(DISABLED_ANALYZERS),
        "claims": _claims_payload(claims),
    }


def report_inputs(
    repo_root: Path,
    target: RecCmpTarget,
    claims: Sequence[Claim],
    prep_fingerprint: str,
) -> dict[str, Any]:
    paths = [
        repo_root / "vendor" / "ghidra" / "exports" / "Imperialism.gzf",
        repo_root / "ghidra.toml",
        target.recompiled_path.parent / "reccmp_report.json",
        repo_root / "config" / "reviewed_library_identities.csv",
        repo_root / "config" / "template_aliases.csv",
        Path(__file__),
    ]
    return {
        "schema": SCHEMA_VERSION,
        "prep_fingerprint": prep_fingerprint,
        "files": _fingerprint_files(paths),
        "claims": _claims_payload(claims),
        "target": target.target_id,
        # A precision-audit run deliberately bypasses reccmp's proof, so its rows
        # are not gate results.  Keeping the flag in the fingerprint stops such a
        # report from ever being mistaken for a fresh gate report.
        "precision_audit": os.environ.get(PRECISION_AUDIT_ENV) == "1",
    }


def row_context_inputs(repo_root: Path, target: RecCmpTarget) -> dict[str, Any]:
    """Everything a stored row's outcome depends on besides its own reuse record.

    A previous report's rows are eligible for reuse only when this fingerprint
    is unchanged: the original program, the comparator/normalizer code, the
    template-alias folding, and the analyzer configuration of the recomp cache.
    """
    paths = [
        repo_root / "vendor" / "ghidra" / "exports" / "Imperialism.gzf",
        repo_root / "ghidra.toml",
        repo_root / "config" / "original_entities.csv",
        repo_root / "config" / "reviewed_library_identities.csv",
        repo_root / "config" / "template_aliases.csv",
        Path(__file__),
    ]
    version, release = ghidra_env.expected_versions()
    return {
        "schema": SCHEMA_VERSION,
        "prep_schema": PREP_SCHEMA_VERSION,
        "files": _fingerprint_files(paths),
        "ghidra": {"version": version, "release": release},
        "pyghidra": importlib.metadata.version("pyghidra"),
        "reccmp": _distribution_source(),
        "disabled_analyzers": list(DISABLED_ANALYZERS),
        "target": target.target_id,
    }


def fingerprint(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def _java_iterator(values: Any) -> Iterator[Any]:
    iterator = values.iterator() if hasattr(values, "iterator") else values
    if hasattr(iterator, "hasNext"):
        while iterator.hasNext():
            yield iterator.next()
    else:
        yield from iterator


def _class_name(value: Any) -> str:
    try:
        return str(value.getClass().getSimpleName())
    except Exception:
        return type(value).__name__


def _contains_recurrence(value: Any) -> bool:
    if isinstance(value, list):
        if value and value[0] == "recurrence":
            return True
        return any(_contains_recurrence(item) for item in value)
    if isinstance(value, dict):
        return any(_contains_recurrence(item) for item in value.values())
    return False


class ExpressionNormalizer:
    """Convert a high-p-code SSA value into a cross-image structural value."""

    def __init__(
        self,
        program: Any,
        image_id: ImageId,
        entities: dict[int, tuple[int, int]],
        functions: dict[int, int],
        *,
        max_depth: int = 80,
        max_nodes: int = MAX_EXPRESSION_NODES,
    ):
        self.program = program
        self.image_id = image_id
        self.entities = entities
        self.functions = functions
        self.max_depth = max_depth
        self.max_nodes = max_nodes
        self.recorder: DepRecorder | None = None
        self._active: set[int] = set()
        self._memo: dict[int, Any] = {}
        self._nodes = 0
        try:
            memory = program.getMemory()
            self._image_min = int(memory.getMinAddress().getOffset())
            self._image_max = int(memory.getMaxAddress().getOffset())
        except Exception:
            # No mapped image (unit-test doubles): every constant stays numeric.
            self._image_min = 1
            self._image_max = 0

    def reset(self) -> None:
        self._active.clear()
        self._memo.clear()
        self._nodes = 0

    def normalize(self, varnode: Any, depth: int = 0) -> Any:
        if depth == 0:
            self._memo.clear()
        key = int(varnode.hashCode())
        if key in self._memo:
            return self._memo[key]
        normalized = self._normalize_uncached(varnode, depth)
        if not _contains_recurrence(normalized):
            self._memo[key] = normalized
        return normalized

    def _normalize_uncached(self, varnode: Any, depth: int) -> Any:
        self._nodes += 1
        if self._nodes > self.max_nodes:
            raise UnresolvedExpression("expression node limit exceeded")
        if depth > self.max_depth:
            raise UnresolvedExpression("expression depth limit exceeded")

        key = int(varnode.hashCode())
        if key in self._active:
            return ["recurrence", int(varnode.getSize())]

        if varnode.isConstant():
            return self._constant_value(
                int(varnode.getOffset()), int(varnode.getSize())
            )

        high = varnode.getHigh()
        high_class = _class_name(high) if high is not None else ""
        if high_class == "HighParam":
            return ["parameter", int(high.getSlot()), int(varnode.getSize())]

        definition = varnode.getDef()
        if definition is None:
            if varnode.isAddress():
                return self._address_value(int(varnode.getOffset()), varnode)
            if varnode.isRegister():
                register = self.program.getRegister(
                    varnode.getAddress(), int(varnode.getSize())
                )
                name = str(register.getName()).lower() if register is not None else "unknown"
                if name == "ecx":
                    # An UNDEFINED entry ecx is the thiscall receiver: MSVC5
                    # passes nothing else in ecx across a call boundary.  One
                    # image's decompiler binds it as parameter 0 (prototype
                    # imported) while the other leaves the raw register, and
                    # the same receiver then mismatches by construction.  A
                    # genuinely different receiver still fails: parameter 0
                    # never equals parameter 1 or a computed value.
                    return ["parameter", 0, int(varnode.getSize())]
                name = {
                    "esp": "stack_pointer",
                    "rsp": "stack_pointer",
                    "ebp": "frame_pointer",
                    "rbp": "frame_pointer",
                }.get(name, name)
                return ["register", name, int(varnode.getSize())]
            symbol = high.getSymbol() if high is not None else None
            if symbol is not None:
                if self.recorder is not None and self.image_id == ImageId.RECOMP:
                    self.recorder.mark_fragile()
                return [
                    "symbol",
                    str(symbol.getName()),
                    int(varnode.getSize()),
                ]
            raise UnresolvedExpression(
                f"unbound {_class_name(varnode)} value at 0x{int(varnode.getOffset()):x}"
            )

        mnemonic = str(definition.getMnemonic())
        inputs = [definition.getInput(index) for index in range(definition.getNumInputs())]
        if mnemonic in STRIP_OPS and len(inputs) == 1:
            return self.normalize(inputs[0], depth + 1)
        if mnemonic in {"INT_ZEXT", "INT_SEXT"} and len(inputs) == 1:
            if int(inputs[0].getSize()) == int(varnode.getSize()):
                return self.normalize(inputs[0], depth + 1)
        if mnemonic == "PTRSUB" and len(inputs) == 2 and inputs[1].isConstant():
            if int(inputs[1].getOffset()) == 0:
                return self.normalize(inputs[0], depth + 1)
        if mnemonic == "PTRADD" and len(inputs) == 3 and inputs[1].isConstant():
            if int(inputs[1].getOffset()) == 0:
                return self.normalize(inputs[0], depth + 1)
        if mnemonic == "PTRSUB" and len(inputs) == 2:
            normalized = [self.normalize(item, depth + 1) for item in inputs]
            return _canonical_arithmetic("INT_ADD", int(varnode.getSize()), normalized)
        if mnemonic == "PTRADD" and len(inputs) == 3:
            base = self.normalize(inputs[0], depth + 1)
            index = self.normalize(inputs[1], depth + 1)
            scale = self.normalize(inputs[2], depth + 1)
            offset = _canonical_arithmetic(
                "INT_MULT", int(varnode.getSize()), [index, scale]
            )
            return _canonical_arithmetic(
                "INT_ADD", int(varnode.getSize()), [base, offset]
            )
        if mnemonic == "LOAD":
            if not inputs:
                raise UnresolvedExpression("LOAD without pointer input")
            self._active.add(key)
            try:
                pointer = self.normalize(inputs[-1], depth + 1)
            finally:
                self._active.remove(key)
            return ["load", int(varnode.getSize()), pointer]
        if mnemonic in {"CALL", "CALLIND"}:
            self._active.add(key)
            try:
                if mnemonic == "CALL":
                    target_value = _direct_target(
                        self.program, inputs[0], self.functions, self.recorder
                    )
                else:
                    virtual = _virtual_target(inputs[0])
                    if virtual is not None:
                        receiver, slot = virtual
                        target_value = {
                            "virtual_slot": slot,
                            "receiver": self.normalize(receiver, depth + 1),
                        }
                    else:
                        target_value = self.normalize(inputs[0], depth + 1)
                        normalized_virtual = _normalized_virtual_target(target_value)
                        if normalized_virtual is not None:
                            receiver, slot = normalized_virtual
                            target_value = {
                                "virtual_slot": slot,
                                "receiver": receiver,
                            }
                arguments = [
                    self.normalize(item, depth + 1) for item in inputs[1:]
                ]
            finally:
                self._active.remove(key)
            return ["call_result", target_value, arguments, int(varnode.getSize())]
        if mnemonic not in SUPPORTED_OPS:
            raise UnresolvedExpression(f"unsupported p-code operation {mnemonic}")

        self._active.add(key)
        try:
            normalized = [self.normalize(item, depth + 1) for item in inputs]
        finally:
            self._active.remove(key)

        if mnemonic in {"INT_ADD", "INT_MULT"}:
            return _canonical_arithmetic(mnemonic, int(varnode.getSize()), normalized)
        if mnemonic in COMMUTATIVE_OPS or mnemonic == "MULTIEQUAL":
            normalized.sort(key=canonical_json)
        return [mnemonic.lower(), int(varnode.getSize()), *normalized]

    def _constant_value(self, offset: int, size: int) -> Any:
        """Map a pointer-valued immediate to its entity, not its raw address.

        A pointer handed to a call as an immediate (a string literal, a global,
        a function address) has a different numeric value in each image, so
        comparing the raw constant reports a difference for byte-identical code.
        The same entity/function maps that resolve address-typed varnodes resolve
        these, which makes the two images comparable instead of merely equal-
        looking.  Values outside the image keep their numeric identity, so real
        constant-argument differences still fail.
        """
        if self._image_min <= offset <= self._image_max:
            recorder = self.recorder
            if offset in self.entities:
                entity_type, original = self.entities[offset]
                if recorder is not None:
                    recorder.entity(self.image_id, offset, entity_type, original)
                return ["entity", entity_type, f"0x{original:x}", size]
            if offset in self.functions:
                if recorder is not None:
                    recorder.map_fn(self.image_id, offset, self.functions[offset])
                return ["function", f"0x{self.functions[offset]:x}"]
            if recorder is not None:
                recorder.miss(self.image_id, offset)
        return ["constant", size, offset]

    def _address_value(self, offset: int, varnode: Any) -> Any:
        recorder = self.recorder
        if offset in self.entities:
            entity_type, original = self.entities[offset]
            if recorder is not None:
                recorder.entity(self.image_id, offset, entity_type, original)
            return ["entity", entity_type, f"0x{original:x}", int(varnode.getSize())]
        if offset in self.functions:
            if recorder is not None:
                recorder.map_fn(self.image_id, offset, self.functions[offset])
            return ["function", f"0x{self.functions[offset]:x}"]
        address = varnode.getAddress()
        if not self.program.getMemory().contains(address):
            if recorder is not None:
                recorder.miss(self.image_id, offset)
                recorder.nonmem(self.image_id, offset)
            return ["address_literal", int(varnode.getSize()), offset]
        data = self.program.getListing().getDataAt(address)
        if data is not None and data.hasStringValue():
            if recorder is not None:
                recorder.miss(self.image_id, offset)
                recorder.data(self.image_id, offset)
            return ["string", str(data.getValue())]
        symbol = self.program.getSymbolTable().getPrimarySymbol(address)
        if symbol is not None:
            name = str(symbol.getName())
            if not name.startswith(("DAT_", "LAB_", "FUN_")):
                if recorder is not None:
                    recorder.miss(self.image_id, offset)
                    if self.image_id == ImageId.RECOMP:
                        recorder.mark_fragile()
                return ["named_address", name, int(varnode.getSize())]
        if recorder is not None:
            recorder.miss(self.image_id, offset)
            recorder.data(self.image_id, offset)
        raise UnresolvedExpression(f"unmapped image address 0x{offset:x}")


def _strip_transparent_pointer(varnode: Any) -> Any:
    while True:
        definition = varnode.getDef()
        if definition is None:
            return varnode
        mnemonic = str(definition.getMnemonic())
        inputs = [
            definition.getInput(index) for index in range(definition.getNumInputs())
        ]
        if mnemonic in STRIP_OPS and len(inputs) == 1:
            varnode = inputs[0]
            continue
        if mnemonic == "INDIRECT" and len(inputs) == 2:
            # Call-effect wrapper; the pointer value is input 0 (see the
            # dissolution rule in _canonical_call_value).
            varnode = inputs[0]
            continue
        if mnemonic == "PTRSUB" and len(inputs) == 2 and inputs[1].isConstant():
            if int(inputs[1].getOffset()) == 0:
                varnode = inputs[0]
                continue
        if mnemonic == "PTRADD" and len(inputs) == 3 and inputs[1].isConstant():
            if int(inputs[1].getOffset()) == 0:
                varnode = inputs[0]
                continue
        return varnode


def _offset_from_pointer(varnode: Any) -> tuple[Any, int] | None:
    varnode = _strip_transparent_pointer(varnode)
    definition = varnode.getDef()
    if definition is None:
        return None
    mnemonic = str(definition.getMnemonic())
    inputs = [definition.getInput(index) for index in range(definition.getNumInputs())]
    if mnemonic in {"INT_ADD", "PTRSUB"} and len(inputs) == 2:
        for index in (0, 1):
            if inputs[index].isConstant():
                return inputs[1 - index], int(inputs[index].getOffset())
    if mnemonic == "PTRADD" and len(inputs) == 3:
        if inputs[1].isConstant() and inputs[2].isConstant():
            return (
                inputs[0],
                int(inputs[1].getOffset()) * int(inputs[2].getOffset()),
            )
    return None


def _virtual_target(target: Any) -> tuple[Any, int] | None:
    target = _strip_transparent_pointer(target)
    target_definition = target.getDef()
    if target_definition is None or str(target_definition.getMnemonic()) != "LOAD":
        return None
    pointer = _strip_transparent_pointer(
        target_definition.getInput(target_definition.getNumInputs() - 1)
    )
    split = _offset_from_pointer(pointer)
    if split is None:
        return None
    vtable_value, slot = split
    vtable_value = _strip_transparent_pointer(vtable_value)
    vtable_definition = vtable_value.getDef()
    if vtable_definition is None or str(vtable_definition.getMnemonic()) != "LOAD":
        return None
    receiver = _strip_transparent_pointer(
        vtable_definition.getInput(vtable_definition.getNumInputs() - 1)
    )
    return receiver, slot


def _normalized_virtual_target(target: Any) -> tuple[Any, int] | None:
    """Recognize a vtable slot after pointer arithmetic has been normalized."""
    if not isinstance(target, list) or len(target) != 3 or target[0] != "load":
        return None
    pointer = target[2]
    if not isinstance(pointer, list) or len(pointer) < 4 or pointer[0] != "int_add":
        return None

    slot = None
    vtable = None
    for term in pointer[2:]:
        if isinstance(term, list) and len(term) == 3 and term[0] == "constant":
            if slot is not None:
                return None
            slot = int(term[2])
        elif isinstance(term, list) and len(term) == 3 and term[0] == "load":
            if vtable is not None:
                return None
            vtable = term
        else:
            return None
    if slot is None or vtable is None:
        return None
    return vtable[2], slot


def _canonical_call_value(value: Any) -> Any:
    """Remove decompiler-only width/filler wrappers from call contracts."""
    if isinstance(value, dict):
        return {key: _canonical_call_value(item) for key, item in value.items()}
    if not isinstance(value, list):
        return value

    # The INDIRECT-filler PIECE rule keys on the RAW child shape: INDIRECT
    # wrappers dissolve during child canonicalization below, so testing the
    # child after recursion would never see the ``indirect`` marker again.
    # (The subpiece/int_right stale-upper variant is checked after recursion
    # instead -- dissolution can EXPOSE that shape from under a wrapper.)
    if value and value[0] == "piece" and len(value) == 4:
        upper = value[2]
        if isinstance(upper, list) and bool(upper) and upper[0] == "indirect":
            return _canonical_call_value(value[3])

    normalized = [_canonical_call_value(item) for item in value]
    if not normalized:
        return normalized
    tag = normalized[0]
    if not isinstance(tag, str):
        return normalized
    if tag in {"int_add", "int_mult"} and len(normalized) >= 4:
        return _canonical_arithmetic(tag.upper(), int(normalized[1]), normalized[2:])
    if tag == "multiequal" and len(normalized) >= 4:
        operand_widths = {
            int(operand[1])
            for operand in normalized[2:]
            if isinstance(operand, list)
            and len(operand) >= 2
            and isinstance(operand[1], int)
        }
        if len(operand_widths) == 1:
            normalized[1] = operand_widths.pop()
    if tag in {item.lower() for item in COMMUTATIVE_OPS} | {"multiequal"}:
        return [*normalized[:2], *sorted(normalized[2:], key=canonical_json)]
    if tag == "call_result" and len(normalized) == 4:
        return normalized[:3]
    if tag == "piece" and len(normalized) == 4:
        upper = normalized[2]
        if (
            isinstance(upper, list)
            and len(upper) == 4
            and upper[0] == "subpiece"
            and isinstance(upper[2], list)
            and len(upper[2]) == 4
            and upper[2][0] == "int_right"
        ):
            # Stale upper-register filler around the value actually passed.
            return normalized[3]
    if tag == "indirect" and len(normalized) == 4:
        # Ghidra INDIRECT ops record "this value may have been changed by that
        # call/store".  The two images place them differently (one decompiler
        # proves no-clobber where the other does not), and the second operand is
        # an image-specific iop sequence pseudo-constant, so a surviving INDIRECT
        # node mismatches by construction.  Compare the underlying dataflow value
        # instead: a genuinely different value still differs after dissolution.
        # The corner this cannot see -- same pre-call value, actually modified at
        # runtime -- is machine behavior owned by reccmp's byte-level proof.
        return normalized[2]
    if tag == "subpiece" and len(normalized) == 4:
        offset = normalized[3]
        inner = normalized[2]
        if (
            isinstance(offset, list)
            and len(offset) == 3
            and offset[0] == "constant"
            and offset[2] == 0
            and isinstance(inner, list)
            and inner
            and inner[0] == "call_result"
        ):
            return inner
    if tag == "int_zext" and len(normalized) == 3:
        inner = normalized[2]
        if (
            isinstance(inner, list)
            and inner
            and inner[0]
            in {
                "bool_and",
                "bool_negate",
                "bool_or",
                "bool_xor",
                "int_equal",
                "int_less",
                "int_lessequal",
                "int_notequal",
                "int_sless",
                "int_slessequal",
            }
        ):
            return inner
    return normalized


def _erase_inference_widths(value: Any) -> Any:
    """Drop node widths that come from decompiler type inference, not codegen.

    The width of an immediate, of a formal parameter slot, and of an arithmetic
    result are all propagated types: the two images import different prototypes,
    so the same byte-identical expression is typed `short` in one and `int` in
    the other.  Comparing those widths reports differences that no machine-level
    difference backs.

    ``load`` widths are deliberately kept: how many bytes a call argument reads
    out of an object is a real contract difference and a live defect class in
    this project (a field modelled at the wrong width).  Same for PIECE/SUBPIECE,
    which encode an actual sub-register extraction rather than a declared type.
    """
    if isinstance(value, dict):
        return {key: _erase_inference_widths(item) for key, item in value.items()}
    if not isinstance(value, list) or not value:
        return value
    # Erase every element: a plain argument array has no leading string tag, and
    # skipping its first element would leave one argument's widths in place.
    normalized = [_erase_inference_widths(item) for item in value]
    tag = value[0]
    if not isinstance(tag, str):
        return normalized
    if tag == "constant" and len(normalized) == 3:
        return ["constant", normalized[2]]
    if tag == "parameter" and len(normalized) == 3:
        return ["parameter", normalized[1]]
    if tag == "entity" and len(normalized) == 4:
        # ["entity", type, original-address, width] -- identity is type+address.
        return normalized[:3]
    if tag in WIDTH_AGNOSTIC_OPS and len(normalized) >= 3:
        return [tag, *normalized[2:]]
    return normalized


def _frame_slot_offset(node: Any) -> int | None:
    """Signed offset of a frame-relative local address, or None.

    Matches the post-erasure shape ``["int_add", ["constant", c],
    ["register", stack_pointer|frame_pointer, w]]`` (canonical sorting puts the
    folded constant first).  Only negative offsets qualify: they address locals,
    whose placement is frame layout owned by ``just stackcmp``.  Positive
    offsets address the incoming-parameter area -- which incoming slot a call
    forwards IS contract, so those stay concrete.
    """
    if (
        isinstance(node, list)
        and len(node) == 3
        and node[0] == "int_add"
        and isinstance(node[1], list)
        and len(node[1]) == 2
        and node[1][0] == "constant"
        and isinstance(node[1][1], int)
        and isinstance(node[2], list)
        and len(node[2]) == 3
        and node[2][0] == "register"
        and node[2][1] in {"stack_pointer", "frame_pointer"}
    ):
        offset = node[1][1]
        signed = offset - (1 << 32) if offset >= (1 << 31) else offset
        if signed < 0:
            return signed
    return None


def _collect_frame_slots(value: Any, found: set[int]) -> None:
    if isinstance(value, dict):
        for item in value.values():
            _collect_frame_slots(item, found)
        return
    if not isinstance(value, list):
        return
    offset = _frame_slot_offset(value)
    if offset is not None:
        found.add(offset)
        return
    for item in value:
        _collect_frame_slots(item, found)


def _rewrite_frame_slots(value: Any, ranks: dict[int, int]) -> Any:
    if isinstance(value, dict):
        return {key: _rewrite_frame_slots(item, ranks) for key, item in value.items()}
    if not isinstance(value, list):
        return value
    offset = _frame_slot_offset(value)
    if offset is not None:
        return ["local_slot", ranks[offset]]
    return [_rewrite_frame_slots(item, ranks) for item in value]


def _normalize_frame_slots(calls: list[dict[str, Any]]) -> None:
    """Replace concrete frame offsets with per-image local-slot rank ordinals.

    A call argument that is the address of a local normalizes to
    ``int_add(constant, stack/frame pointer)``; which concrete slot the
    compiler picked is frame layout, not contract, so the same source compares
    unequal whenever the two frames differ in size.  Rank ordinals (ascending
    over the distinct offsets referenced by this function's calls, computed per
    image) erase the layout while keeping distinct locals distinct: swapped or
    merged locals still change a rank and still fail.  Accepted blind spot: a
    function whose only frame-relative argument points at the wrong local maps
    to rank 0 on both sides -- that class is owned by stackcmp and reccmp's
    machine-level proof.
    """
    found: set[int] = set()
    for call in calls:
        _collect_frame_slots(call.get("target"), found)
        _collect_frame_slots(call.get("arguments"), found)
    if not found:
        return
    ranks = {offset: rank for rank, offset in enumerate(sorted(found))}
    for call in calls:
        call["target"] = _rewrite_frame_slots(call["target"], ranks)
        call["arguments"] = _rewrite_frame_slots(call["arguments"], ranks)


def _external_identity(function: Any) -> dict[str, str] | None:
    try:
        if not function.isExternal():
            return None
        location = function.getExternalLocation()
        return {
            "library": str(location.getLibraryName()),
            "symbol": str(location.getLabel()),
        }
    except Exception:
        return None


def _is_scaffolding_call(program: Any, target: Any) -> bool:
    """True when a direct CALL's callee is compiler frame scaffolding.

    Resolved from the target varnode's address BEFORE ``_direct_target`` so an
    unpaired scaffolding callee cannot leak into ``unresolved`` (which counts
    toward the call multiplicity this exclusion removes it from).
    """
    try:
        address = target.getAddress()
        function = program.getFunctionManager().getFunctionAt(address)
        if function is not None:
            thunked = function.getThunkedFunction(True)
            if thunked is not None:
                function = thunked
            name = str(function.getName())
        else:
            symbol = program.getSymbolTable().getPrimarySymbol(address)
            if symbol is None:
                return False
            name = str(symbol.getName())
    except Exception:
        return False
    return name in SCAFFOLDING_CALLEE_NAMES


def _direct_target(
    program: Any,
    target: Any,
    function_map: dict[int, int],
    recorder: DepRecorder | None = None,
) -> dict[str, Any]:
    address = target.getAddress()
    function = program.getFunctionManager().getFunctionAt(address)
    if function is None:
        references = program.getReferenceManager().getReferencesFrom(address)
        for reference in _java_iterator(references):
            referenced = program.getFunctionManager().getFunctionAt(
                reference.getToAddress()
            )
            if referenced is not None:
                external = _external_identity(referenced)
                if external is not None:
                    return {"external": external}
                function = referenced
                break
    if function is None:
        symbol = program.getSymbolTable().getPrimarySymbol(address)
        block = program.getMemory().getBlock(address)
        if symbol is not None and block is not None:
            name = str(symbol.getName())
            if not name.startswith(("DAT_", "LAB_", "FUN_")):
                return {
                    "external": {
                        "library": "<import>",
                        "symbol": name.lstrip("_"),
                    }
                }
        if recorder is not None:
            recorder.mark_fragile()
        raise UnresolvedExpression(f"no function/import at direct target {address}")
    thunked = function.getThunkedFunction(True)
    if thunked is not None:
        function = thunked
    external = _external_identity(function)
    if external is not None:
        return {"external": external}
    entry = int(function.getEntryPoint().getOffset())
    original = function_map.get(entry)
    if original is None:
        if recorder is not None:
            recorder.pairs_dep()
        raise UnresolvedExpression(f"unpaired direct target 0x{entry:x}")
    if recorder is not None:
        recorder.fn_pair(original)
    return {"function": f"0x{original:x}"}


def _canonical_direct_arguments(
    target: dict[str, Any],
    arguments: list[Any],
    direct_call_abis: dict[int, DirectCallABI],
) -> list[Any]:
    """Remove Ghidra's optional auto-parameter for a direct thiscall receiver.

    Ghidra may expose the same ECX receiver as a leading CALL input in one
    program and omit it in the other, depending on whether the target prototype
    was imported before decompilation.  The original target's reviewed
    signature tells us when that leading input is an auto ``this`` parameter.
    Explicit arguments remain part of the contract.  Virtual receivers are
    represented separately by ``_virtual_target`` and are never removed here.
    """
    raw_address = target.get("function")
    if not isinstance(raw_address, str):
        return arguments
    abi = direct_call_abis.get(int(raw_address, 16))
    if abi is None or not abi.has_this:
        return arguments
    if len(arguments) == abi.parameter_count:
        return arguments[1:]
    return arguments


def _has_varargs_target(
    target: Any, direct_call_abis: dict[int, DirectCallABI]
) -> bool:
    if not isinstance(target, dict):
        return False
    raw_address = target.get("function")
    if not isinstance(raw_address, str):
        return False
    abi = direct_call_abis.get(int(raw_address, 16))
    return abi is not None and abi.has_varargs


def _direct_call_abis(
    original_program: Any, original_functions: dict[int, int]
) -> dict[int, DirectCallABI]:
    manager = original_program.getFunctionManager()
    factory = original_program.getAddressFactory()
    output: dict[int, DirectCallABI] = {}
    priorities: dict[int, tuple[bool, bool, int]] = {}
    for entry, original in original_functions.items():
        function = manager.getFunctionAt(factory.getAddress(hex(entry)))
        if function is None:
            continue
        thunked = function.getThunkedFunction(True)
        if thunked is not None:
            function = thunked
        parameters = list(function.getParameters())
        has_this = any(
            bool(parameter.isAutoParameter()) or str(parameter.getName()) == "this"
            for parameter in parameters
        )
        abi = DirectCallABI(
            parameter_count=len(parameters),
            has_this=has_this,
            has_varargs=bool(function.hasVarArgs()),
        )
        priority = (entry == original, has_this, len(parameters))
        if priority > priorities.get(original, (False, False, -1)):
            output[original] = abi
            priorities[original] = priority
    return output


def extract_calls(
    high_function: Any,
    program: Any,
    normalizer: ExpressionNormalizer,
    function_map: dict[int, int],
    direct_call_abis: dict[int, DirectCallABI],
    recorder: DepRecorder | None = None,
) -> ExtractedCalls:
    calls: list[dict[str, Any]] = []
    unresolved: list[str] = []
    normalizer.recorder = recorder
    for operation in _java_iterator(high_function.getPcodeOps()):
        mnemonic = str(operation.getMnemonic())
        if mnemonic not in {"CALL", "CALLIND"}:
            continue
        callsite = str(operation.getSeqnum().getTarget())
        normalizer.reset()
        try:
            target = operation.getInput(0)
            if mnemonic == "CALL" and _is_scaffolding_call(program, target):
                continue
            if mnemonic == "CALL":
                kind = "direct"
                target_value = _direct_target(program, target, function_map, recorder)
                external = target_value.get("external")
                if (
                    isinstance(external, dict)
                    and str(external.get("symbol", "")).lstrip("_")
                    in {name.lstrip("_") for name in SCAFFOLDING_CALLEE_NAMES}
                ):
                    continue
            else:
                virtual = _virtual_target(target)
                if virtual is not None:
                    receiver, slot = virtual
                    kind = "virtual"
                    target_value = {
                        "slot": slot,
                        "receiver": normalizer.normalize(receiver),
                    }
                else:
                    target_value = normalizer.normalize(target)
                    normalized_virtual = _normalized_virtual_target(target_value)
                    if normalized_virtual is not None:
                        receiver, slot = normalized_virtual
                        kind = "virtual"
                        target_value = {"slot": slot, "receiver": receiver}
                    else:
                        kind = "indirect"
            arguments = [
                normalizer.normalize(operation.getInput(index))
                for index in range(1, operation.getNumInputs())
            ]
            if mnemonic == "CALL":
                arguments = _canonical_direct_arguments(
                    target_value, arguments, direct_call_abis
                )
            target_value = _erase_inference_widths(
                _canonical_call_value(target_value)
            )
            arguments = [
                _erase_inference_widths(_canonical_call_value(argument))
                for argument in arguments
            ]
            call: dict[str, Any] = {
                "kind": kind,
                "target": target_value,
                "arguments": arguments,
            }
            if mnemonic == "CALL" and _has_varargs_target(
                target_value, direct_call_abis
            ):
                # Neither image declares formals for a variadic callee, so each
                # decompiler decides on its own whether the pushed values belong
                # to this call.  Flag it; the comparison downgrades a difference
                # that only involves such calls to inconclusive.
                call["varargs_target"] = True
            calls.append(call)
        except UnresolvedExpression as error:
            unresolved.append(f"{callsite}: {error}")
    _normalize_frame_slots(calls)
    return ExtractedCalls(calls=calls, unresolved=unresolved)


def _counter_rows(counter: Counter[str]) -> list[dict[str, Any]]:
    return [
        {"count": count, "call": json.loads(value)}
        for value, count in sorted(counter.items())
    ]


def _asymmetric_arity_targets(
    original_abis: dict[int, DirectCallABI],
    recompiled_abis: dict[int, DirectCallABI],
) -> frozenset[str]:
    """Original addresses whose two imported prototypes disagree on arity.

    The curated original prototype and the PDB-imported recompiled prototype
    each tell their decompiler how many arguments to attach to a call; when the
    declared arities differ, the argument lists disagree by construction and no
    behavioural difference backs it.  ``this`` is subtracted first so a mere
    auto-parameter representation difference does not flag.  Callees missing
    from either map are NOT flagged: without both prototypes there is no proven
    asymmetry.
    """
    flagged: set[str] = set()
    for address, original in original_abis.items():
        recompiled = recompiled_abis.get(address)
        if recompiled is None:
            continue
        original_arity = original.parameter_count - int(original.has_this)
        recompiled_arity = recompiled.parameter_count - int(recompiled.has_this)
        if (
            original_arity != recompiled_arity
            or original.has_varargs != recompiled.has_varargs
        ):
            flagged.add(f"0x{address:x}")
    return frozenset(flagged)


def _erase_asymmetric_nested(value: Any, asymmetric_targets: frozenset[str]) -> Any:
    """Erase argument lists of nested call_result nodes with asymmetric arity.

    A prototype disagreement surfaces inside expressions too: the recompiled
    decompiler attaches an extra receiver/argument to a nested call whose
    curated original prototype declares fewer formals, and the wrapped value
    then differs everywhere it is used (including virtual receivers).
    """
    if isinstance(value, dict):
        return {
            key: _erase_asymmetric_nested(item, asymmetric_targets)
            for key, item in value.items()
        }
    if not isinstance(value, list):
        return value
    normalized = [
        _erase_asymmetric_nested(item, asymmetric_targets) for item in value
    ]
    if (
        normalized
        and normalized[0] == "call_result"
        and len(normalized) >= 3
        and isinstance(normalized[1], dict)
        and normalized[1].get("function") in asymmetric_targets
    ):
        return ["call_result", normalized[1], "<arity_asymmetry>"]
    return normalized


def _without_undeclared_arguments(
    call: dict[str, Any], asymmetric_targets: frozenset[str] = frozenset()
) -> dict[str, Any]:
    """Drop argument lists that the two images' prototypes disagree about.

    Variadic callees: neither image declares formals, so each decompiler
    independently decides whether the pushes belong to the call.  Asymmetric
    declared arity: the two prototypes force different argument counts.  Both
    keep the call's kind, target, and multiplicity in the contract.
    """
    stripped = dict(call)
    if asymmetric_targets:
        stripped = _erase_asymmetric_nested(stripped, asymmetric_targets)
    if call.get("varargs_target"):
        stripped["arguments"] = "<varargs>"
        return stripped
    target = stripped.get("target")
    if (
        isinstance(target, dict)
        and target.get("function") in asymmetric_targets
    ):
        stripped["arguments"] = "<arity_asymmetry>"
    return stripped


def _prefix_pairs_only(
    missing: Sequence[dict[str, Any]], extra: Sequence[dict[str, Any]]
) -> bool:
    """True when every remaining diff pairs same-target calls by argument prefix.

    Virtual slots and unmapped callees have no prototype pair to consult, so an
    arity disagreement there shows up directly as one side attaching more
    trailing arguments to the same call.  Pair each missing call with an extra
    call of identical kind, target, and receiver whose argument list strictly
    extends (or is extended by) its own; anything that does not pair this way
    keeps the mismatch.  A genuinely different argument at a shared position,
    a different target, a different receiver, or a multiplicity change never
    pairs.
    """
    if not missing or len(missing) != len(extra):
        return False
    used = [False] * len(extra)
    for candidate in missing:
        matched = False
        for index, other in enumerate(extra):
            if used[index]:
                continue
            if candidate.get("kind") != other.get("kind"):
                continue
            if canonical_json(candidate.get("target")) != canonical_json(
                other.get("target")
            ):
                continue
            left = candidate.get("arguments")
            right = other.get("arguments")
            if not isinstance(left, list) or not isinstance(right, list):
                continue
            if len(left) == len(right):
                continue
            short, long = (left, right) if len(left) < len(right) else (right, left)
            if [canonical_json(item) for item in short] == [
                canonical_json(item) for item in long[: len(short)]
            ]:
                used[index] = True
                matched = True
                break
        if not matched:
            return False
    return True


def _contains_stack_variable_symbol(value: Any) -> bool:
    """True when a value tree references a decompiler-named stack local.

    ``["symbol", "iStack_c", 4]`` style nodes are Ghidra's bound stack
    variables; whether a merge value renders as such a symbol or as the
    equivalent SSA expression is a per-image decompiler-model choice, so a
    difference that involves one on either side is not provable in either
    direction from the call contract alone.  ``in_stack_...`` names are the
    unbound-input variant: one image's function lacks a declared prototype, so
    a parameter-area read renders as a raw stack input instead of the other
    image's ``parameter`` node.  The repair for those is curating the missing
    prototype, which the inconclusive reason keeps visible.
    """
    if isinstance(value, dict):
        return any(_contains_stack_variable_symbol(item) for item in value.values())
    if not isinstance(value, list):
        return False
    if (
        len(value) >= 2
        and value[0] == "symbol"
        and isinstance(value[1], str)
        and (
            value[1].startswith("local_")
            or value[1].startswith("in_stack_")
            or "Stack_" in value[1]
        )
    ):
        return True
    return any(_contains_stack_variable_symbol(item) for item in value)


def _call_identity(call: dict[str, Any]) -> str:
    """Callee identity with the receiver excluded (it may be the artifact)."""
    kind = call.get("kind")
    target = call.get("target")
    if isinstance(target, dict):
        if "slot" in target:
            return canonical_json([kind, "slot", target["slot"]])
        detail = {
            key: target[key] for key in ("function", "external") if key in target
        }
        if detail:
            return canonical_json([kind, detail])
    return canonical_json([kind, target])


def _local_variable_model_only(
    missing: Sequence[dict[str, Any]], extra: Sequence[dict[str, Any]]
) -> bool:
    """True when every remaining diff pairs same-callee calls via a stack symbol.

    Each missing entry must pair with an extra entry of identical kind and
    callee identity, and at least one member of the pair must involve a
    stack-variable (or unbound ``in_stack`` input) symbol -- the tell that the
    two decompiler variable models diverged.  Downgrades to inconclusive,
    never pass: rows stay non-passing and the reason names the cause.  A
    different callee, a multiplicity change, or a diff with no variable-model
    involvement anywhere in the pair still fails.
    """
    if not missing or len(missing) != len(extra):
        return False
    used = [False] * len(extra)
    for candidate in missing:
        matched = False
        for index, other in enumerate(extra):
            if used[index]:
                continue
            if _call_identity(candidate) != _call_identity(other):
                continue
            if not (
                _contains_stack_variable_symbol(candidate)
                or _contains_stack_variable_symbol(other)
            ):
                continue
            used[index] = True
            matched = True
            break
        if not matched:
            return False
    return True


def _arity_asymmetry_only(
    original: Sequence[dict[str, Any]],
    recompiled: Sequence[dict[str, Any]],
    asymmetric_targets: frozenset[str] = frozenset(),
) -> bool:
    """True when the contracts agree once undeclared argument lists are erased.

    Multiplicity, kind, target, and every unflagged call's arguments are still
    compared exactly.  This never yields a pass -- callers downgrade to
    ``inconclusive``/``prototype_arity_asymmetry``, which stays non-passing and
    doubles as the prototype-harmonization worklist.
    """
    left = Counter(
        canonical_json(_without_undeclared_arguments(call, asymmetric_targets))
        for call in original
    )
    right = Counter(
        canonical_json(_without_undeclared_arguments(call, asymmetric_targets))
        for call in recompiled
    )
    if left == right:
        # The exact counters already disagreed, so equality here proves an
        # erasure absorbed the whole difference.
        return True
    missing = [json.loads(value) for value in (left - right).elements()]
    extra = [json.loads(value) for value in (right - left).elements()]
    return _prefix_pairs_only(missing, extra)


def compare_extracted_calls(
    original: ExtractedCalls,
    recompiled: ExtractedCalls,
    asymmetric_arity_targets: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "original_call_count": len(original.calls) + len(original.unresolved),
        "recompiled_call_count": len(recompiled.calls) + len(recompiled.unresolved),
    }
    result["call_count_status"] = (
        "pass"
        if result["original_call_count"] == result["recompiled_call_count"]
        else "mismatch"
    )
    if result["original_call_count"] != result["recompiled_call_count"]:
        original_counter = Counter(canonical_json(call) for call in original.calls)
        recompiled_counter = Counter(canonical_json(call) for call in recompiled.calls)
        result.update(
            status="mismatch",
            reason="call_count",
            missing=_counter_rows(original_counter - recompiled_counter),
            extra=_counter_rows(recompiled_counter - original_counter),
        )
        if original.unresolved:
            result["original_unresolved"] = original.unresolved
        if recompiled.unresolved:
            result["recompiled_unresolved"] = recompiled.unresolved
        return result
    if original.unresolved or recompiled.unresolved:
        result.update(
            status="inconclusive",
            reason="unresolved_call_contract",
            original_unresolved=original.unresolved,
            recompiled_unresolved=recompiled.unresolved,
        )
        return result

    original_counter = Counter(canonical_json(call) for call in original.calls)
    recompiled_counter = Counter(canonical_json(call) for call in recompiled.calls)
    if original_counter == recompiled_counter:
        result.update(status="pass", reason="call_contract_equal")
        return result
    if _arity_asymmetry_only(
        original.calls, recompiled.calls, asymmetric_arity_targets
    ):
        result.update(
            status="inconclusive",
            reason="prototype_arity_asymmetry",
            missing=_counter_rows(original_counter - recompiled_counter),
            extra=_counter_rows(recompiled_counter - original_counter),
        )
        return result
    missing_calls = [
        json.loads(value)
        for value in (original_counter - recompiled_counter).elements()
    ]
    extra_calls = [
        json.loads(value)
        for value in (recompiled_counter - original_counter).elements()
    ]
    if _local_variable_model_only(missing_calls, extra_calls):
        result.update(
            status="inconclusive",
            reason="local_variable_model",
            missing=_counter_rows(original_counter - recompiled_counter),
            extra=_counter_rows(recompiled_counter - original_counter),
        )
        return result
    result.update(
        status="mismatch",
        reason="call_contract",
        missing=_counter_rows(original_counter - recompiled_counter),
        extra=_counter_rows(recompiled_counter - original_counter),
    )
    return result


def _reccmp_proves_call_contract(status: dict[str, Any] | None) -> bool:
    """Use reccmp's completed machine-level proof before heuristic p-code.

    Set SEMANTIC_AUDIT_PRECISION=1 to run the p-code comparison on these rows
    anyway.  reccmp has already proved their machine code semantically equal, so
    every mismatch the comparison then reports is a false positive of this
    module's normalization -- that is the audit's whole point, and it is why the
    flag must never be set for a gate run.
    """
    if os.environ.get(PRECISION_AUDIT_ENV) == "1":
        return False
    return status is not None and status.get("status") in {"exact", "effective"}


def _augment_original_library_functions(
    original_functions: dict[int, int],
    aliases: dict[int, int],
    identities: Sequence[ReviewedIdentity],
    decorated_symbols: dict[int, str],
) -> dict[int, int]:
    """Map reviewed library copies and wrappers to one paired ABI identity."""
    augmented = dict(original_functions)

    changed = True
    while changed:
        changed = False
        for alias, canonical in aliases.items():
            if alias not in augmented and canonical in augmented:
                augmented[alias] = augmented[canonical]
                changed = True

    reviewed_symbols = {identity.symbol for identity in identities if identity.symbol}
    paired_by_symbol: dict[str, set[int]] = {}
    for address, symbol in decorated_symbols.items():
        if symbol in reviewed_symbols and address in augmented:
            paired_by_symbol.setdefault(symbol, set()).add(augmented[address])
    for identity in identities:
        candidates = paired_by_symbol.get(identity.symbol, set())
        if identity.symbol and len(candidates) == 1:
            augmented.setdefault(identity.address, next(iter(candidates)))
    return augmented


def _build_maps(
    compare: Compare,
    repo_root: Path | None = None,
) -> tuple[
    dict[int, FunctionPair],
    dict[int, int],
    dict[int, int],
    dict[int, tuple[int, int]],
    dict[int, tuple[int, int]],
]:
    pairs: dict[int, FunctionPair] = {}
    original_functions: dict[int, int] = {}
    recompiled_functions: dict[int, int] = {}
    for match in compare.get_functions():
        pair = FunctionPair(
            original=match.orig_addr,
            recompiled=match.recomp_addr,
        )
        pairs[match.orig_addr] = pair
        original_functions[match.orig_addr] = match.orig_addr
        recompiled_functions[match.recomp_addr] = match.orig_addr

    folded_aliases, alias_errors = load_aliases(
        equivalence_class=CLASS_FOLDED_SYMBOL_GROUP
    )
    library_aliases, library_alias_errors = load_aliases(
        equivalence_class=CLASS_LIBRARY_CALLEE_ALIAS
    )
    alias_errors.extend(library_alias_errors)
    if alias_errors:
        raise RuntimeError("invalid template aliases: " + "; ".join(alias_errors))
    aliases = dict(folded_aliases)
    aliases.update(library_aliases)

    def canonical_function(address: int) -> int:
        seen: set[int] = set()
        while address in aliases and address not in seen:
            seen.add(address)
            address = aliases[address]
        return address

    original_functions = {
        address: canonical_function(original)
        for address, original in original_functions.items()
    }
    recompiled_functions = {
        address: canonical_function(original)
        for address, original in recompiled_functions.items()
    }
    root = repo_root or repo_root_from_file(__file__, 1)
    original_functions = _augment_original_library_functions(
        original_functions,
        aliases,
        load_reviewed_identities(root / "config" / "reviewed_library_identities.csv"),
        load_decorated_symbols(),
    )

    original_entities: dict[int, tuple[int, int]] = {}
    recompiled_entities: dict[int, tuple[int, int]] = {}
    for entity in compare.get_all():
        if not isinstance(entity, ReccmpMatch):
            continue
        entity_type = int(entity.entity_type or 0)
        original_entities[entity.orig_addr] = (entity_type, entity.orig_addr)
        recompiled_entities[entity.recomp_addr] = (entity_type, entity.orig_addr)
    return (
        pairs,
        original_functions,
        recompiled_functions,
        original_entities,
        recompiled_entities,
    )


def _disable_unneeded_analyzers(program: Any) -> None:
    from ghidra.program.model.listing import Program

    options = program.getOptions(Program.ANALYSIS_PROPERTIES)
    registered = {str(name) for name in options.getOptionNames()}
    for analyzer in DISABLED_ANALYZERS:
        if analyzer in registered:
            options.setBoolean(analyzer, False)


def _short_sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


class ReuseContext:
    """Fresh cross-run state a stored row's reuse record is validated against.

    ``read`` is a callable ``(vaddr, size) -> bytes | None`` over the current
    recompiled image; lookups are memoized because rows share callees/globals.
    """

    def __init__(
        self,
        pairs: dict[int, FunctionPair],
        original_functions: dict[int, int],
        recompiled_functions: dict[int, int],
        original_entities: dict[int, tuple[int, int]],
        recompiled_entities: dict[int, tuple[int, int]],
        identities: dict[int, str],
        sizes: dict[int, int],
        read: Any,
    ) -> None:
        self.pairs = pairs
        self.original_functions = original_functions
        self.recompiled_functions = recompiled_functions
        self.original_entities = original_entities
        self.recompiled_entities = recompiled_entities
        self.identities = identities
        self.sizes = sizes
        self.pairs_fp = _short_sha(
            canonical_json(sorted(f"0x{addr:x}" for addr in pairs)).encode()
        )
        self._read = read
        self._probe_memo: dict[tuple[int, int], bytes | None] = {}
        self._body_memo: dict[int, bytes | None] = {}

    def probe(self, offset: int, length: int) -> bytes | None:
        key = (offset, length)
        if key not in self._probe_memo:
            self._probe_memo[key] = self._read(offset, length)
        return self._probe_memo[key]

    def body(self, original: int) -> bytes | None:
        if original not in self._body_memo:
            pair = self.pairs.get(original)
            size = self.sizes.get(original)
            if pair is None or not size:
                self._body_memo[original] = None
            else:
                self._body_memo[original] = self._read(pair.recompiled, size)
        return self._body_memo[original]


def _image_reader(image: Any) -> Any:
    def read(vaddr: int, size: int) -> bytes | None:
        try:
            data = image.read(vaddr, size)
        except Exception:
            return None
        if data is None or len(data) != size:
            return None
        return bytes(data)

    return read


def _entity_identities(compare: Compare) -> dict[int, str]:
    """Digest of the reccmp-side identity a callee's imported prototype follows."""
    output: dict[int, str] = {}
    for entity in compare.get_all():
        if not isinstance(entity, ReccmpMatch):
            continue
        kvstore = getattr(entity, "_kvstore", None) or {}
        payload = canonical_json(
            {
                "name": entity.name,
                "symbol": kvstore.get("symbol"),
                "type": entity.entity_type,
                "size": entity.size(ImageId.RECOMP),
            }
        )
        output[entity.orig_addr] = _short_sha(payload.encode())
    return output


def _function_sizes(compare: Compare) -> dict[int, int]:
    return {
        match.orig_addr: int(match.size(ImageId.RECOMP) or 0)
        for match in compare.get_functions()
    }


def _encode_dep(event: tuple[Any, ...], ctx: ReuseContext) -> list[Any] | None:
    """Serialize one recorded dependency, or None when the row cannot be reused."""
    kind = event[0]
    if kind == "entity":
        _, tag, offset, entity_type, original = event
        return ["entity", tag, f"0x{offset:x}", entity_type, f"0x{original:x}"]
    if kind == "map_fn":
        _, tag, offset, mapped = event
        return ["map_fn", tag, f"0x{offset:x}", f"0x{mapped:x}"]
    if kind == "miss":
        _, tag, offset = event
        return ["miss", tag, f"0x{offset:x}"]
    if kind == "data":
        _, tag, offset = event
        for length in (DATA_PROBE_BYTES, DATA_PROBE_FALLBACK_BYTES):
            blob = ctx.probe(offset, length)
            if blob is not None:
                return ["data", tag, f"0x{offset:x}", length, _short_sha(blob)]
        return None
    if kind == "nonmem":
        _, tag, offset = event
        if ctx.probe(offset, 1) is not None:
            return None
        return ["nonmem", tag, f"0x{offset:x}"]
    if kind == "fn_pair":
        _, original = event
        identity = ctx.identities.get(original)
        body = ctx.body(original)
        if identity is None or body is None:
            return None
        return ["fn_pair", f"0x{original:x}", identity, _short_sha(body)]
    if kind == "pairs_fp":
        return ["pairs_fp", ctx.pairs_fp]
    return None


def _dep_matches(dep: Any, ctx: ReuseContext) -> bool:
    if not isinstance(dep, list) or not dep:
        return False
    kind = dep[0]
    try:
        if kind == "entity":
            _, tag, offset, entity_type, original = dep
            table = (
                ctx.original_entities if tag == "orig" else ctx.recompiled_entities
            )
            return table.get(int(offset, 16)) == (entity_type, int(original, 16))
        if kind == "map_fn":
            _, tag, offset, mapped = dep
            table = (
                ctx.original_functions if tag == "orig" else ctx.recompiled_functions
            )
            return table.get(int(offset, 16)) == int(mapped, 16)
        if kind == "miss":
            _, tag, offset = dep
            value = int(offset, 16)
            if tag == "orig":
                return (
                    value not in ctx.original_entities
                    and value not in ctx.original_functions
                )
            return (
                value not in ctx.recompiled_entities
                and value not in ctx.recompiled_functions
            )
        if kind == "data":
            _, _tag, offset, length, digest = dep
            blob = ctx.probe(int(offset, 16), int(length))
            return blob is not None and _short_sha(blob) == digest
        if kind == "nonmem":
            _, _tag, offset = dep
            return ctx.probe(int(offset, 16), 1) is None
        if kind == "fn_pair":
            _, original, identity, body_sha = dep
            value = int(original, 16)
            if ctx.identities.get(value) != identity:
                return False
            body = ctx.body(value)
            return body is not None and _short_sha(body) == body_sha
        if kind == "pairs_fp":
            return dep[1] == ctx.pairs_fp
    except (TypeError, ValueError):
        return False
    return False


def _attach_reuse_records(
    rows: list[dict[str, Any]], ctx: ReuseContext
) -> None:
    """Stamp freshly computed rows with the record a later run revalidates."""
    for row in rows:
        recorder = row.pop("_recorder", None)
        if not isinstance(recorder, DepRecorder) or recorder.fragile:
            continue
        if row.get("status") == "inconclusive" and row.get("reason") == "decompilation":
            continue
        original = int(row["original"], 16)
        identity = ctx.identities.get(original)
        size = ctx.sizes.get(original)
        body = ctx.body(original)
        if identity is None or not size or body is None:
            continue
        deps: list[list[Any]] = []
        encodable = True
        for event in sorted(recorder.events):
            dep = _encode_dep(event, ctx)
            if dep is None:
                encodable = False
                break
            deps.append(dep)
        if not encodable:
            continue
        row["reuse"] = {
            "claim_identity": identity,
            "recomp_size": size,
            "recomp_sha": _short_sha(body),
            "deps": deps,
        }


def _row_reusable(row: dict[str, Any], ctx: ReuseContext) -> bool:
    reuse = row.get("reuse")
    if not isinstance(reuse, dict):
        return False
    try:
        original = int(row["original"], 16)
    except (KeyError, TypeError, ValueError):
        return False
    if reuse.get("claim_identity") != ctx.identities.get(original):
        return False
    if reuse.get("recomp_size") != ctx.sizes.get(original):
        return False
    body = ctx.body(original)
    if body is None or _short_sha(body) != reuse.get("recomp_sha"):
        return False
    deps = reuse.get("deps")
    if not isinstance(deps, list):
        return False
    return all(_dep_matches(dep, ctx) for dep in deps)


def _analyze(program: Any) -> None:
    from ghidra.app.script import GhidraScriptUtil
    from ghidra.app.plugin.core.analysis import AutoAnalysisManager
    from ghidra.program.util import GhidraProgramUtilities
    from ghidra.util.task import TaskMonitor

    # Retain the returned reference until analysis releases the bundle host.
    _host_reference = GhidraScriptUtil.acquireBundleHostReference()
    transaction = program.startTransaction("semantic-recomp-analysis")
    try:
        manager = AutoAnalysisManager.getAnalysisManager(program)
        manager.initializeOptions()
        _disable_unneeded_analyzers(program)
        manager.reAnalyzeAll(None)
        manager.startAnalysis(TaskMonitor.DUMMY)
        GhidraProgramUtilities.markProgramAnalyzed(program)
    finally:
        program.endTransaction(transaction, True)
        GhidraScriptUtil.releaseBundleHostReference()


def _seed_required_functions(
    program: Any, claims: Sequence[Claim], pairs: dict[int, FunctionPair]
) -> list[str]:
    """Install PDB/reccmp entry points before analysis can merge them away."""
    from ghidra.program.flatapi import FlatProgramAPI

    api = FlatProgramAPI(program)
    manager = program.getFunctionManager()
    factory = program.getAddressFactory()
    failures: list[str] = []
    for claim in claims:
        pair = pairs.get(claim.address)
        if pair is None:
            continue
        address = factory.getAddress(hex(pair.recompiled))
        if manager.getFunctionAt(address) is not None:
            continue
        try:
            api.disassemble(address)
            created = api.createFunction(
                address, f"semantic_seed_{claim.address:08x}"
            )
            if created is None:
                failures.append(
                    f"0x{claim.address:x}->0x{pair.recompiled:x}: createFunction returned null"
                )
        except Exception as error:
            failures.append(
                f"0x{claim.address:x}->0x{pair.recompiled:x}: {error}"
            )
    return failures


def _validate_recompiled_functions(
    program: Any, claims: Sequence[Claim], pairs: dict[int, FunctionPair]
) -> list[str]:
    missing: list[str] = []
    manager = program.getFunctionManager()
    factory = program.getAddressFactory()
    for claim in claims:
        pair = pairs.get(claim.address)
        if pair is None:
            continue
        address = factory.getAddress(hex(pair.recompiled))
        if manager.getFunctionAt(address) is None:
            missing.append(f"0x{claim.address:x}->0x{pair.recompiled:x}")
    return missing


def _create_cache(
    destination: Path,
    target: RecCmpTarget,
    claims: Sequence[Claim],
    pairs: dict[int, FunctionPair],
    manifest: dict[str, Any],
) -> None:
    from java.lang import Object as JavaObject
    from ghidra.app.util.importer import ProgramLoader
    from ghidra.base.project import GhidraProject
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.util.task import TaskMonitor
    from reccmp.ghidra.importer.importer import import_target_into_ghidra

    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir()
    wrapper = GhidraProject.createProject(str(destination), PROJECT_NAME, False)
    project = wrapper.getProject()
    consumer = JavaObject()
    program = None
    timings: dict[str, float] = {}
    stage_started = time.monotonic()

    def mark(stage: str) -> None:
        nonlocal stage_started
        now = time.monotonic()
        timings[stage] = round(now - stage_started, 3)
        stage_started = now

    try:
        loaded = (
            ProgramLoader.builder()
            .source(str(target.recompiled_path))
            .project(project)
            .load()
        )
        program = loaded.getPrimaryDomainObject(consumer)
        mark("load")
        # Seed and import before the single analysis pass: the reccmp importer
        # creates/annotates its own function objects, and analysis then runs
        # once with every name, body, and prototype already in place.
        transaction = program.startTransaction("semantic-function-seeds")
        try:
            seed_failures = _seed_required_functions(program, claims, pairs)
        finally:
            program.endTransaction(transaction, True)
        mark("seed")

        transaction = program.startTransaction("semantic-reccmp-import")
        try:
            import_target_into_ghidra(
                target, FlatProgramAPI(program), image_id=ImageId.RECOMP
            )
        finally:
            program.endTransaction(transaction, True)
        mark("reccmp_import")

        transaction = program.startTransaction("semantic-missing-function-seeds")
        try:
            seed_failures.extend(_seed_required_functions(program, claims, pairs))
        finally:
            program.endTransaction(transaction, True)
        mark("reseed")
        _analyze(program)
        mark("analyze")

        missing = _validate_recompiled_functions(program, claims, pairs)
        manifest["missing_required_functions"] = missing
        manifest["function_seed_failures"] = seed_failures
        folder = project.getProjectData().getRootFolder()
        folder.createFile(PROGRAM_NAME, program, TaskMonitor.DUMMY)
        mark("save")
        manifest["timings"] = timings
    finally:
        if program is not None:
            program.release(consumer)
        project.close()

    atomic_json(destination / "manifest.json", manifest)


def _prune_stale_caches(cache_root: Path, keep_fingerprint: str) -> None:
    """Drop all but the newest CACHE_KEEP_COUNT cache projects (lock held)."""
    candidates = sorted(
        (entry for entry in cache_root.iterdir() if entry.is_dir()),
        key=lambda entry: entry.stat().st_mtime,
        reverse=True,
    )
    keep = {keep_fingerprint}
    for entry in candidates:
        if len(keep) >= CACHE_KEEP_COUNT:
            break
        keep.add(entry.name)
    log_dir = cache_root.parent / "semantic"
    for entry in candidates:
        if entry.name in keep:
            continue
        shutil.rmtree(entry, ignore_errors=True)
        (log_dir / f"cache-{entry.name}.log").unlink(missing_ok=True)


def _prune_targeted_reports(semantic_dir: Path) -> None:
    cutoff = time.time() - TARGETED_REPORT_MAX_AGE_SECONDS
    for entry in semantic_dir.glob("semantic_report.targeted-*.json"):
        try:
            if entry.stat().st_mtime < cutoff:
                entry.unlink(missing_ok=True)
        except OSError:
            continue


def ensure_cache(
    cache_root: Path,
    target: RecCmpTarget,
    claims: Sequence[Claim],
    pairs: dict[int, FunctionPair],
    inputs: dict[str, Any],
) -> tuple[Path, str, dict[str, Any]]:
    prep_fingerprint = fingerprint(inputs)
    destination = cache_root / prep_fingerprint
    manifest_path = destination / "manifest.json"
    cache_root.mkdir(parents=True, exist_ok=True)
    with (cache_root / ".lock").open("a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if manifest_path.is_file():
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            if manifest.get("fingerprint") == prep_fingerprint:
                return destination, prep_fingerprint, manifest
        manifest = {"fingerprint": prep_fingerprint, "inputs": inputs}
        _create_cache(destination, target, claims, pairs, manifest)
        _prune_stale_caches(cache_root, prep_fingerprint)
        return destination, prep_fingerprint, manifest


def ensure_cache_subprocess(
    build_dir: Path,
    target_id: str,
    inputs: dict[str, Any],
) -> tuple[Path, str, dict[str, Any]]:
    """Build a missing project in a short-lived JVM so its lock is released."""
    prep_fingerprint = fingerprint(inputs)
    cache_dir = build_dir / "ghidra-semantic" / prep_fingerprint
    manifest_path = cache_dir / "manifest.json"
    if manifest_path.is_file():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest.get("fingerprint") == prep_fingerprint:
            return cache_dir, prep_fingerprint, manifest

    log_path = build_dir / "semantic" / f"cache-{prep_fingerprint}.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    print(f"preparing recomp Ghidra cache {prep_fingerprint[:12]}...", file=sys.stderr)
    command = [
        sys.executable,
        "-m",
        "tools.semantic_calls",
        "--target",
        target_id,
        "--build-dir",
        str(build_dir),
        "_prepare-cache",
    ]
    with log_path.open("w", encoding="utf-8") as log:
        result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
    if result.returncode != 0:
        tail = "\n".join(log_path.read_text(encoding="utf-8").splitlines()[-40:])
        raise RuntimeError(f"recomp Ghidra cache preparation failed; see {log_path}\n{tail}")
    if not manifest_path.is_file():
        raise RuntimeError(f"cache preparation did not write {manifest_path}")
    return (
        cache_dir,
        prep_fingerprint,
        json.loads(manifest_path.read_text(encoding="utf-8")),
    )


def _open_cached_program(cache_dir: Path) -> tuple[Any, Any, Any]:
    import pyghidra
    from java.lang import Object as JavaObject

    project = pyghidra.open_project(str(cache_dir), PROJECT_NAME, create=False)
    domain_file = project.getProjectData().getFile(f"/{PROGRAM_NAME}")
    if domain_file is None:
        project.close()
        raise FileNotFoundError(f"Missing cached Ghidra Program in {cache_dir}")
    consumer = JavaObject()
    program = domain_file.getReadOnlyDomainObject(
        consumer, -1, pyghidra.task_monitor()
    )
    return project, consumer, program


def _decompiler(program: Any) -> Any:
    from ghidra.app.decompiler import DecompInterface, DecompileOptions

    interface = DecompInterface()
    options = DecompileOptions()
    options.grabFromProgram(program)
    interface.setOptions(options)
    interface.toggleCCode(False)
    interface.toggleSyntaxTree(True)
    interface.setSimplificationStyle("decompile")
    if not interface.openProgram(program):
        raise RuntimeError("failed to open Program in the Ghidra decompiler")
    return interface


def _decompile_function(
    interface: Any, program: Any, address: int, timeout: int
) -> tuple[Any | None, str | None]:
    from ghidra.util.task import TaskMonitor

    ghidra_address = program.getAddressFactory().getAddress(hex(address))
    function = program.getFunctionManager().getFunctionAt(ghidra_address)
    if function is None:
        return None, "missing_function"
    result = interface.decompileFunction(function, timeout, TaskMonitor.DUMMY)
    if not result.decompileCompleted():
        return None, str(result.getErrorMessage() or "decompilation_failed")
    high = result.getHighFunction()
    if high is None:
        return None, "missing_high_function"
    return high, None


def _reccmp_statuses(
    build_dir: Path, evidence_inputs: Sequence[Path] = ()
) -> dict[int, dict[str, Any]]:
    path = build_dir / "reccmp_report.json"
    if not path.is_file():
        return {}
    report = json.loads(path.read_text(encoding="utf-8"))
    timestamp = report.get("timestamp")
    existing_inputs = [item for item in evidence_inputs if item.is_file()]
    if existing_inputs and (
        not isinstance(timestamp, (int, float))
        or float(timestamp) < max(item.stat().st_mtime for item in existing_inputs)
    ):
        raise RuntimeError(
            "stale reccmp_report.json predates the recompiled EXE/PDB; run `just stats`"
        )
    rows = report.get("data", [])
    output: dict[int, dict[str, Any]] = {}
    for row in rows:
        comparison = row.get("comparison")
        if isinstance(comparison, dict):
            output[int(row["address"], 16)] = comparison
    return output


def compare_programs(
    original_program: Any,
    recompiled_program: Any,
    claims: Sequence[Claim],
    pairs: dict[int, FunctionPair],
    original_functions: dict[int, int],
    recompiled_functions: dict[int, int],
    original_entities: dict[int, tuple[int, int]],
    recompiled_entities: dict[int, tuple[int, int]],
    reccmp_statuses: dict[int, dict[str, Any]],
    timeout: int,
    jobs: int,
    orig_calls_cache: dict[str, Any] | None = None,
    orig_calls_fresh: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    direct_call_abis = _direct_call_abis(original_program, original_functions)
    # The recompiled map iterates (entry -> original) pairs the same way; its
    # ``entry == original`` priority term is simply never true there.
    recompiled_call_abis = _direct_call_abis(recompiled_program, recompiled_functions)
    asymmetric_arity_targets = _asymmetric_arity_targets(
        direct_call_abis, recompiled_call_abis
    )
    local = threading.local()
    context_lock = threading.Lock()
    contexts: list[tuple[Any, Any, ExpressionNormalizer, ExpressionNormalizer]] = []

    def context():
        value = getattr(local, "semantic_context", None)
        if value is None:
            value = (
                _decompiler(original_program),
                _decompiler(recompiled_program),
                ExpressionNormalizer(
                    original_program,
                    ImageId.ORIG,
                    original_entities,
                    original_functions,
                ),
                ExpressionNormalizer(
                    recompiled_program,
                    ImageId.RECOMP,
                    recompiled_entities,
                    recompiled_functions,
                ),
            )
            local.semantic_context = value
            with context_lock:
                contexts.append(value)
        return value

    def compare_one(claim: Claim) -> dict[str, Any]:
        (
            original_decompiler,
            recompiled_decompiler,
            original_normalizer,
            recompiled_normalizer,
        ) = context()
        row: dict[str, Any] = {
            "original": f"0x{claim.address:x}",
            "name": claim.name,
            "source": f"{claim.file}:{claim.line}",
            "reccmp": reccmp_statuses.get(claim.address),
        }
        pair = pairs.get(claim.address)
        if pair is None:
            row.update(status="unpaired", reason="missing_reccmp_pair")
            return row
        row["recompiled"] = f"0x{pair.recompiled:x}"
        if _reccmp_proves_call_contract(row["reccmp"]):
            row.update(
                status="pass",
                reason="reccmp_proven",
                call_count_status="pass",
            )
            return row
        cached_entry = (
            orig_calls_cache.get(row["original"]) if orig_calls_cache else None
        )
        original_high = original_error = None
        if cached_entry is None:
            original_high, original_error = _decompile_function(
                original_decompiler, original_program, claim.address, timeout
            )
        recompiled_high, recompiled_error = _decompile_function(
            recompiled_decompiler, recompiled_program, pair.recompiled, timeout
        )
        if original_error or recompiled_error:
            row.update(
                status="inconclusive",
                reason="decompilation",
                original_error=original_error,
                recompiled_error=recompiled_error,
            )
            return row
        recorder = DepRecorder()
        if cached_entry is not None:
            original_calls = _restore_orig_calls(cached_entry, recorder)
        else:
            original_calls = extract_calls(
                original_high,
                original_program,
                original_normalizer,
                original_functions,
                direct_call_abis,
                recorder,
            )
            if orig_calls_fresh is not None:
                orig_calls_fresh[row["original"]] = _orig_calls_entry(
                    original_calls, recorder
                )
        recompiled_calls = extract_calls(
            recompiled_high,
            recompiled_program,
            recompiled_normalizer,
            recompiled_functions,
            direct_call_abis,
            recorder,
        )
        row.update(
            compare_extracted_calls(
                original_calls, recompiled_calls, asymmetric_arity_targets
            )
        )
        if row.get("reason") == "prototype_arity_asymmetry":
            # The relaxation consulted the recompiled image's imported
            # prototypes, which no per-row dependency fingerprints; a reused
            # row could keep the downgrade after prototypes are harmonized.
            # (A prototype newly diverging leaves a stale ``mismatch`` reason
            # on an untouched row until it recomputes -- both states are
            # non-passing, so the gate outcome cannot go stale.)
            recorder.mark_fragile()
        row["_recorder"] = recorder
        return row

    try:
        worker_count = max(1, min(jobs, len(claims)))
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=worker_count, thread_name_prefix="semantic-pcode"
        ) as executor:
            rows = []
            for index, row in enumerate(executor.map(compare_one, claims), 1):
                rows.append(row)
                claim = claims[index - 1]
                if index == 1 or index % 100 == 0 or index == len(claims):
                    print(
                        f"semantic p-code: {index}/{len(claims)} 0x{claim.address:x}",
                        file=sys.stderr,
                    )
    finally:
        for original_decompiler, recompiled_decompiler, _, _ in contexts:
            original_decompiler.dispose()
            recompiled_decompiler.dispose()
    return rows


def _summary(rows: Sequence[dict[str, Any]]) -> dict[str, Any]:
    counts = Counter(str(row["status"]) for row in rows)
    total = len(rows)
    passed = counts.get("pass", 0)
    call_count_passed = sum(
        row.get("call_count_status") == "pass" for row in rows
    )
    return {
        "required": total,
        "pass": passed,
        "mismatch": counts.get("mismatch", 0),
        "inconclusive": counts.get("inconclusive", 0),
        "unpaired": counts.get("unpaired", 0),
        "coverage_pct": 0.0 if total == 0 else round(passed * 100.0 / total, 4),
        "call_count_pass": call_count_passed,
        "call_count_coverage_pct": (
            0.0
            if total == 0
            else round(call_count_passed * 100.0 / total, 4)
        ),
    }


def _select_claims(
    claims: Sequence[Claim], addresses: Sequence[str], files: Sequence[str]
) -> list[Claim]:
    selected_addresses = {int(value, 0) for value in addresses}
    selected_files = {Path(value).as_posix() for value in files}
    if not selected_addresses and not selected_files:
        return list(claims)
    selected = [
        claim
        for claim in claims
        if claim.address in selected_addresses or claim.file in selected_files
    ]
    missing = selected_addresses - {claim.address for claim in selected}
    if missing:
        raise ValueError(
            "addresses are not manual FUNCTION claims: "
            + ", ".join(f"0x{value:x}" for value in sorted(missing))
        )
    return selected


def _report_output_path(
    build_dir: Path, selected: Sequence[Claim], full: bool
) -> Path:
    if full:
        return build_dir / _full_report_relative_path()
    selection_fingerprint = fingerprint([claim.address for claim in selected])[:12]
    return (
        build_dir
        / "semantic"
        / f"semantic_report.targeted-{selection_fingerprint}.json"
    )


def run_compare(args: argparse.Namespace) -> tuple[dict[str, Any], Path]:
    repo_root = repo_root_from_file(__file__, 1)
    build_dir = Path(args.build_dir).resolve()
    project = RecCmpProject.from_directory(build_dir)
    target = project.get(args.target)
    claims = required_claims(repo_root)
    selected = _select_claims(claims, args.address, args.file)
    prep_inputs = cache_inputs(repo_root, target, claims)
    prep_fingerprint = fingerprint(prep_inputs)
    inputs = report_inputs(repo_root, target, claims, prep_fingerprint)
    full = len(selected) == len(claims)
    full_output = build_dir / _full_report_relative_path()
    output = _report_output_path(build_dir, selected, full)
    if not args.force and output.is_file():
        previous = json.loads(output.read_text(encoding="utf-8"))
        if (
            previous.get("scope") == ("all" if full else "targeted")
            and previous.get("fingerprint") == fingerprint(inputs)
        ):
            return previous, output

    phase_started = time.monotonic()
    compare = Compare.from_target(target)
    (
        pairs,
        original_functions,
        recompiled_functions,
        original_entities,
        recompiled_entities,
    ) = _build_maps(compare, repo_root)
    reccmp_statuses = _reccmp_statuses(
        build_dir, (target.recompiled_path, target.recompiled_pdb)
    )
    ctx = ReuseContext(
        pairs,
        original_functions,
        recompiled_functions,
        original_entities,
        recompiled_entities,
        _entity_identities(compare),
        _function_sizes(compare),
        _image_reader(compare.recomp_bin),
    )
    context_fp = fingerprint(row_context_inputs(repo_root, target))
    orig_calls_path = build_dir / ORIG_CALLS_CACHE_RELATIVE_PATH
    orig_cache_key = fingerprint(
        {
            "row_context": context_fp,
            "original_functions": sorted(original_functions.items()),
            "original_entities": sorted(
                (offset, list(value)) for offset, value in original_entities.items()
            ),
            "timeout": args.timeout,
        }
    )
    # --force (and the reuse kill switch) recomputes the original side too, so
    # `just semantic-verify` remains a from-scratch ground-truth check of both
    # this cache and the row-reuse records.  Fresh extractions are still saved.
    orig_calls_cache: dict[str, Any] = {}
    if not args.force and os.environ.get(REUSE_DISABLE_ENV) != "1":
        orig_calls_cache = _load_orig_calls_cache(orig_calls_path, orig_cache_key)
    orig_calls_fresh: dict[str, Any] = {}
    maps_seconds = round(time.monotonic() - phase_started, 3)

    previous_rows: dict[str, dict[str, Any]] = {}
    previous_output = output if output.is_file() else full_output
    if (
        not args.force
        and os.environ.get(REUSE_DISABLE_ENV) != "1"
        and previous_output.is_file()
    ):
        previous = json.loads(previous_output.read_text(encoding="utf-8"))
        if (
            previous.get("schema") == SCHEMA_VERSION
            and previous.get("scope") in {"all", "targeted"}
            and previous.get("row_context") == context_fp
        ):
            previous_rows = {
                row["original"]: row for row in previous.get("functions", [])
            }

    resolved: dict[int, dict[str, Any]] = {}
    stale: list[Claim] = []
    reused = 0
    for claim in selected:
        row: dict[str, Any] = {
            "original": f"0x{claim.address:x}",
            "name": claim.name,
            "source": f"{claim.file}:{claim.line}",
            "reccmp": reccmp_statuses.get(claim.address),
        }
        pair = pairs.get(claim.address)
        if pair is None:
            row.update(status="unpaired", reason="missing_reccmp_pair")
            resolved[claim.address] = row
            continue
        row["recompiled"] = f"0x{pair.recompiled:x}"
        if _reccmp_proves_call_contract(row["reccmp"]):
            row.update(
                status="pass", reason="reccmp_proven", call_count_status="pass"
            )
            resolved[claim.address] = row
            continue
        previous_row = previous_rows.get(row["original"])
        if previous_row is not None and _row_reusable(previous_row, ctx):
            refreshed = dict(previous_row)
            refreshed.update(row)
            resolved[claim.address] = refreshed
            reused += 1
            continue
        stale.append(claim)

    cache_seconds = 0.0
    compare_seconds = 0.0
    manifest: dict[str, Any] = {}
    prep_fingerprint = fingerprint(prep_inputs)
    computed: dict[int, dict[str, Any]] = {}
    if stale:
        phase_started = time.monotonic()
        cache_dir, prep_fingerprint, manifest = ensure_cache_subprocess(
            build_dir, target.target_id, prep_inputs
        )
        cache_seconds = round(time.monotonic() - phase_started, 3)
        original_project = ghidra_env.open_project()
        original_consumer = original_program = None
        recompiled_project = recompiled_consumer = recompiled_program = None
        try:
            original_consumer, original_program = ghidra_env.open_program(
                original_project
            )
            recompiled_project, recompiled_consumer, recompiled_program = (
                _open_cached_program(cache_dir)
            )
            phase_started = time.monotonic()
            computed_rows = compare_programs(
                original_program,
                recompiled_program,
                stale,
                pairs,
                original_functions,
                recompiled_functions,
                original_entities,
                recompiled_entities,
                reccmp_statuses,
                args.timeout,
                args.jobs,
                orig_calls_cache,
                orig_calls_fresh,
            )
        finally:
            if recompiled_program is not None:
                recompiled_program.release(recompiled_consumer)
            if recompiled_project is not None:
                recompiled_project.close()
            if original_program is not None:
                original_program.release(original_consumer)
            original_project.close()
        compare_seconds = round(time.monotonic() - phase_started, 3)
        _attach_reuse_records(computed_rows, ctx)
        computed = {
            int(item["original"], 16): item for item in computed_rows
        }
        if orig_calls_fresh:
            merged = _load_orig_calls_cache(orig_calls_path, orig_cache_key)
            merged.update(orig_calls_fresh)
            atomic_json(
                orig_calls_path,
                {"key": orig_cache_key, "rows": merged},
                indent=None,
            )

    rows = [
        resolved[claim.address]
        if claim.address in resolved
        else computed[claim.address]
        for claim in selected
    ]
    report = {
        "schema": SCHEMA_VERSION,
        "fingerprint": fingerprint(inputs),
        "inputs": inputs,
        "row_context": context_fp,
        "scope": "all" if full else "targeted",
        "summary": _summary(rows),
        "reuse": {
            "reused": reused,
            "recomputed": len(stale),
            "cheap": len(resolved) - reused,
        },
        "timings": {
            "cache_seconds": cache_seconds,
            "maps_seconds": maps_seconds,
            "compare_seconds": compare_seconds,
            "rows_compared": len(selected),
            "cache_stages": manifest.get("timings"),
            "orig_cache": {
                "hits": sum(
                    1
                    for claim in stale
                    if f"0x{claim.address:x}" in orig_calls_cache
                ),
                "fresh": len(orig_calls_fresh),
            },
        },
        "cache": {
            "fingerprint": prep_fingerprint,
            "missing_required_functions": manifest.get(
                "missing_required_functions", []
            ),
            "function_seed_failures": manifest.get("function_seed_failures", []),
        },
        "excluded": {
            "rule": "only kind=FUNCTION, origin=marker is required",
            "ownership_counts": ownership_counts(repo_root),
        },
        "functions": rows,
    }
    atomic_json(output, report, indent=None)
    _prune_targeted_reports(build_dir / "semantic")
    return report, output


def load_fresh_report(args: argparse.Namespace) -> tuple[dict[str, Any], Path]:
    repo_root = repo_root_from_file(__file__, 1)
    build_dir = Path(args.build_dir).resolve()
    path = build_dir / _full_report_relative_path()
    if not path.is_file() and getattr(args, "generate_if_stale", False):
        compare_args = argparse.Namespace(
            build_dir=str(build_dir),
            target=args.target,
            address=[],
            file=[],
            timeout=args.timeout,
            force=False,
            jobs=args.jobs,
        )
        return run_compare(compare_args)
    if not path.is_file():
        raise RuntimeError(f"missing semantic report: {path}")
    report = json.loads(path.read_text(encoding="utf-8"))
    project = RecCmpProject.from_directory(build_dir)
    target = project.get(args.target)
    claims = required_claims(repo_root)
    prep = fingerprint(cache_inputs(repo_root, target, claims))
    expected = fingerprint(report_inputs(repo_root, target, claims, prep))
    if report.get("scope") != "all" or report.get("fingerprint") != expected:
        if getattr(args, "generate_if_stale", False):
            compare_args = argparse.Namespace(
                build_dir=str(build_dir),
                target=args.target,
                address=[],
                file=[],
                timeout=args.timeout,
                force=False,
                jobs=args.jobs,
            )
            return run_compare(compare_args)
        raise RuntimeError("semantic report is stale or targeted; run semantic-compare")
    return report, path


def print_stats(report: dict[str, Any], path: Path) -> None:
    summary = report["summary"]
    print(f"semantic report: {path}")
    print(
        "required={required} pass={pass} mismatch={mismatch} "
        "inconclusive={inconclusive} unpaired={unpaired} coverage={coverage_pct:.4f}%".format(
            **summary
        )
    )
    print(
        "call-count pass={call_count_pass}/{required} "
        "coverage={call_count_coverage_pct:.4f}%".format(**summary)
    )


def _baseline_path() -> Path:
    return repo_root_from_file(__file__, 1) / BASELINE_RELATIVE_PATH


def contract_fingerprint(row: dict[str, Any]) -> str:
    """Bind an accepted equivalence to one exact observed contract difference."""
    payload = {
        key: row.get(key)
        for key in (
            "status",
            "reason",
            "call_count_status",
            "missing",
            "extra",
            "original_unresolved",
            "recompiled_unresolved",
            "reccmp",
        )
    }
    return hashlib.sha256(canonical_json(payload).encode()).hexdigest()


def accepted_equivalence_errors(
    report: dict[str, Any], baseline: dict[str, Any]
) -> tuple[set[str], list[str]]:
    """Validate narrow reviewed equivalences and return the addresses they cover."""
    rows = {row["original"]: row for row in report["functions"]}
    accepted: set[str] = set()
    errors: list[str] = []
    seen: set[str] = set()
    for entry in baseline.get("accepted_equivalences", []):
        if not isinstance(entry, dict):
            errors.append("accepted equivalence entry is not an object")
            continue
        address = entry.get("address")
        if not isinstance(address, str) or address in seen:
            errors.append(f"invalid or duplicate accepted equivalence address: {address}")
            continue
        seen.add(address)
        missing_metadata = [
            key
            for key in (
                "reason",
                "evidence_class",
                "evidence_reference",
                "machine_status",
            )
            if not isinstance(entry.get(key), str) or not entry[key].strip()
        ]
        if missing_metadata:
            errors.append(
                f"accepted equivalence {address} lacks metadata: "
                + ", ".join(missing_metadata)
            )
            continue
        row = rows.get(address)
        if row is None:
            errors.append(f"accepted equivalence address is not required: {address}")
            continue
        if row.get("status") == "pass":
            errors.append(f"accepted equivalence resolved; remove it: {address}")
            continue
        machine_status = (row.get("reccmp") or {}).get("status")
        if entry.get("machine_status") != machine_status:
            errors.append(
                f"accepted equivalence machine status drifted: {address} "
                f"expected={entry.get('machine_status')} actual={machine_status}"
            )
            continue
        actual = contract_fingerprint(row)
        if entry.get("contract_fingerprint") != actual:
            errors.append(
                f"accepted equivalence drifted: {address} "
                f"expected={entry.get('contract_fingerprint')} actual={actual}"
            )
            continue
        accepted.add(address)
    return accepted, errors


def check_gate(report: dict[str, Any], baseline: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    rows = {row["original"]: row for row in report["functions"]}
    required = set(rows)
    baseline_required = set(baseline.get("required", []))
    debt = set(baseline.get("debt", []))
    if required != baseline_required:
        added = sorted(required - baseline_required)
        removed = sorted(baseline_required - required)
        errors.append(f"denominator changed: added={added} removed={removed}")
    accepted, acceptance_errors = accepted_equivalence_errors(report, baseline)
    errors.extend(acceptance_errors)
    nonpassing = {
        address
        for address, row in rows.items()
        if row["status"] != "pass" and address not in accepted
    }
    protected_regressions = sorted(nonpassing - debt)
    if protected_regressions:
        errors.append("protected functions regressed: " + ", ".join(protected_regressions))
    resolved = sorted(debt - nonpassing)
    if resolved:
        errors.append(
            "semantic debt resolved; run semantic-gate-update: "
            + ", ".join(resolved)
        )
    if baseline.get("mode") == "hard" and nonpassing:
        errors.append("hard mode requires every manual FUNCTION to pass")
    return errors


def update_baseline(report: dict[str, Any], path: Path) -> None:
    required = sorted(row["original"] for row in report["functions"])
    previous: dict[str, Any] = {}
    if path.is_file():
        previous = json.loads(path.read_text(encoding="utf-8"))
    accepted, acceptance_errors = accepted_equivalence_errors(report, previous)
    if acceptance_errors:
        raise RuntimeError("; ".join(acceptance_errors))
    debt = sorted(
        row["original"]
        for row in report["functions"]
        if row["status"] != "pass" and row["original"] not in accepted
    )
    if path.is_file():
        previous_debt = set(previous.get("debt", []))
        regressions = set(debt) - previous_debt
        if regressions:
            raise RuntimeError(
                "refusing to baseline protected regressions: "
                + ", ".join(sorted(regressions))
            )
        if previous.get("mode") == "hard" and debt:
            raise RuntimeError("hard semantic gate cannot be downgraded")
    baseline = {
        "schema": BASELINE_SCHEMA_VERSION,
        "mode": "hard" if not debt else "ratchet",
        "required": required,
        "debt": debt,
        "accepted_equivalences": previous.get("accepted_equivalences", []),
    }
    atomic_json(path, baseline)
    print(
        f"wrote {path}: mode={baseline['mode']} required={len(required)} debt={len(debt)}"
    )


def _diff_reports(
    previous: dict[str, Any], current: dict[str, Any]
) -> list[str]:
    """Row-level behavior diff used to prove a pipeline change is neutral."""
    fields = ("status", "reason", "call_count_status")
    previous_rows = {row["original"]: row for row in previous.get("functions", [])}
    current_rows = {row["original"]: row for row in current.get("functions", [])}
    diffs: list[str] = []
    for address in sorted(previous_rows.keys() - current_rows.keys()):
        diffs.append(f"{address}: removed from report")
    for address in sorted(current_rows.keys() - previous_rows.keys()):
        diffs.append(f"{address}: added to report")
    for address in sorted(previous_rows.keys() & current_rows.keys()):
        before = previous_rows[address]
        after = current_rows[address]
        changed = [
            f"{field}: {before.get(field)} -> {after.get(field)}"
            for field in fields
            if before.get(field) != after.get(field)
        ]
        if changed:
            diffs.append(f"{address}: " + "; ".join(changed))
    return diffs


def run_verify(args: argparse.Namespace) -> int:
    build_dir = Path(args.build_dir).resolve()
    path = build_dir / _full_report_relative_path()
    if not path.is_file():
        raise RuntimeError(f"missing semantic report to verify against: {path}")
    previous = json.loads(path.read_text(encoding="utf-8"))
    compare_args = argparse.Namespace(
        build_dir=str(build_dir),
        target=args.target,
        address=[],
        file=[],
        timeout=args.timeout,
        force=True,
        jobs=args.jobs,
    )
    report, report_path = run_compare(compare_args)
    diffs = _diff_reports(previous, report)
    print_stats(report, report_path)
    if diffs:
        for diff in diffs:
            print(f"semantic-verify: {diff}", file=sys.stderr)
        print(f"semantic-verify: {len(diffs)} row(s) changed", file=sys.stderr)
        return 1
    print(f"semantic-verify: {len(report['functions'])} rows identical")
    return 0


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    repo_root = repo_root_from_file(__file__, 1)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="IMPERIALISM")
    parser.add_argument("--build-dir", default=str(repo_root / "build-msvc500"))
    commands = parser.add_subparsers(dest="command", required=True)

    compare_parser = commands.add_parser("compare")
    compare_parser.add_argument("address", nargs="*")
    compare_parser.add_argument("--file", action="append", default=[])
    compare_parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_SECONDS)
    compare_parser.add_argument("--force", action="store_true")
    compare_parser.add_argument("--jobs", type=int, default=_default_jobs())

    commands.add_parser("stats")
    gate_parser = commands.add_parser("gate")
    gate_parser.add_argument("--generate-if-stale", action="store_true")
    gate_parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_SECONDS)
    gate_parser.add_argument("--jobs", type=int, default=_default_jobs())
    verify_parser = commands.add_parser("verify")
    verify_parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_SECONDS)
    verify_parser.add_argument("--jobs", type=int, default=_default_jobs())
    commands.add_parser("update-baseline")
    commands.add_parser("_prepare-cache")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.command == "compare":
            report, path = run_compare(args)
            print_stats(report, path)
            return 0
        if args.command == "stats":
            args.generate_if_stale = False
            report, path = load_fresh_report(args)
            print_stats(report, path)
            return 0
        if args.command == "gate":
            if os.environ.get(PRECISION_AUDIT_ENV) == "1":
                print(
                    f"semantic-gate: refusing to gate with {PRECISION_AUDIT_ENV}=1 "
                    "(that mode bypasses reccmp's proof and is for auditing only)",
                    file=sys.stderr,
                )
                return 1
            report, path = load_fresh_report(args)
            print_stats(report, path)
            baseline_path = _baseline_path()
            if not baseline_path.is_file():
                print(f"missing semantic gate baseline: {baseline_path}", file=sys.stderr)
                return 1
            errors = check_gate(
                report, json.loads(baseline_path.read_text(encoding="utf-8"))
            )
            if errors:
                for error in errors:
                    print(f"semantic-gate: {error}", file=sys.stderr)
                return 1
            print("semantic-gate: PASS")
            return 0
        if args.command == "verify":
            return run_verify(args)
        if args.command == "update-baseline":
            args.generate_if_stale = False
            report, _ = load_fresh_report(args)
            update_baseline(report, _baseline_path())
            return 0
        if args.command == "_prepare-cache":
            repo_root = repo_root_from_file(__file__, 1)
            build_dir = Path(args.build_dir).resolve()
            target = RecCmpProject.from_directory(build_dir).get(args.target)
            claims = required_claims(repo_root)
            compare = Compare.from_target(target)
            pairs = _build_maps(compare)[0]
            ghidra_env._evict_daemon_if_running()  # pylint: disable=protected-access
            ghidra_env.start()
            ensure_cache(
                build_dir / "ghidra-semantic",
                target,
                claims,
                pairs,
                cache_inputs(repo_root, target, claims),
            )
            return 0
    except (OSError, RuntimeError, ValueError) as error:
        print(f"semantic-calls: {error}", file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
