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
from tools.common.template_aliases import CLASS_FOLDED_SYMBOL_GROUP, load_aliases
from tools.source_model import Claim, build_model

SCHEMA_VERSION = 2
PREP_SCHEMA_VERSION = 1
DEFAULT_TIMEOUT_SECONDS = 30
PROJECT_NAME = "recompiled-semantic"
PROGRAM_NAME = "Imperialism.exe"
REPORT_RELATIVE_PATH = Path("semantic") / "semantic_report.json"
BASELINE_RELATIVE_PATH = (
    Path("config") / "baselines" / "semantic_call_contract_baseline.json"
)

STRIP_OPS = frozenset({"COPY", "CAST"})
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


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = path.stat().st_mode & 0o777 if path.exists() else 0o644
    fd, raw_temp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temp = Path(raw_temp)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
        temp.chmod(mode)
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


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
        Path(__file__),
    ]
    return {
        "schema": SCHEMA_VERSION,
        "prep_fingerprint": prep_fingerprint,
        "files": _fingerprint_files(paths),
        "claims": _claims_payload(claims),
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
        max_nodes: int = 500,
    ):
        self.program = program
        self.image_id = image_id
        self.entities = entities
        self.functions = functions
        self.max_depth = max_depth
        self.max_nodes = max_nodes
        self._active: set[int] = set()
        self._nodes = 0

    def reset(self) -> None:
        self._active.clear()
        self._nodes = 0

    def normalize(self, varnode: Any, depth: int = 0) -> Any:
        self._nodes += 1
        if self._nodes > self.max_nodes:
            raise UnresolvedExpression("expression node limit exceeded")
        if depth > self.max_depth:
            raise UnresolvedExpression("expression depth limit exceeded")

        key = int(varnode.hashCode())
        if key in self._active:
            return ["recurrence", int(varnode.getSize())]

        if varnode.isConstant():
            return ["constant", int(varnode.getSize()), int(varnode.getOffset())]

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
                name = {
                    "esp": "stack_pointer",
                    "rsp": "stack_pointer",
                    "ebp": "frame_pointer",
                    "rbp": "frame_pointer",
                }.get(name, name)
                return ["register", name, int(varnode.getSize())]
            symbol = high.getSymbol() if high is not None else None
            if symbol is not None:
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
                        self.program, inputs[0], self.functions
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

    def _address_value(self, offset: int, varnode: Any) -> Any:
        if offset in self.entities:
            entity_type, original = self.entities[offset]
            return ["entity", entity_type, f"0x{original:x}", int(varnode.getSize())]
        if offset in self.functions:
            return ["function", f"0x{self.functions[offset]:x}"]
        address = varnode.getAddress()
        if not self.program.getMemory().contains(address):
            return ["address_literal", int(varnode.getSize()), offset]
        data = self.program.getListing().getDataAt(address)
        if data is not None and data.hasStringValue():
            return ["string", str(data.getValue())]
        symbol = self.program.getSymbolTable().getPrimarySymbol(address)
        if symbol is not None:
            name = str(symbol.getName())
            if not name.startswith(("DAT_", "LAB_", "FUN_")):
                return ["named_address", name, int(varnode.getSize())]
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
        stale_upper = isinstance(upper, list) and upper and upper[0] == "indirect"
        if (
            isinstance(upper, list)
            and len(upper) == 4
            and upper[0] == "subpiece"
            and isinstance(upper[2], list)
            and len(upper[2]) == 4
            and upper[2][0] == "int_right"
        ):
            stale_upper = True
        if stale_upper:
            return normalized[3]
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


def _direct_target(
    program: Any, target: Any, function_map: dict[int, int]
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
        raise UnresolvedExpression(f"unpaired direct target 0x{entry:x}")
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
) -> ExtractedCalls:
    calls: list[dict[str, Any]] = []
    unresolved: list[str] = []
    for operation in _java_iterator(high_function.getPcodeOps()):
        mnemonic = str(operation.getMnemonic())
        if mnemonic not in {"CALL", "CALLIND"}:
            continue
        callsite = str(operation.getSeqnum().getTarget())
        normalizer.reset()
        try:
            target = operation.getInput(0)
            if mnemonic == "CALL":
                kind = "direct"
                target_value = _direct_target(program, target, function_map)
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
            target_value = _canonical_call_value(target_value)
            arguments = [_canonical_call_value(argument) for argument in arguments]
            calls.append(
                {
                    "kind": kind,
                    "target": target_value,
                    "arguments": arguments,
                }
            )
        except UnresolvedExpression as error:
            unresolved.append(f"{callsite}: {error}")
    return ExtractedCalls(calls=calls, unresolved=unresolved)


def _counter_rows(counter: Counter[str]) -> list[dict[str, Any]]:
    return [
        {"count": count, "call": json.loads(value)}
        for value, count in sorted(counter.items())
    ]


def compare_extracted_calls(
    original: ExtractedCalls, recompiled: ExtractedCalls
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
    result.update(
        status="mismatch",
        reason="call_contract",
        missing=_counter_rows(original_counter - recompiled_counter),
        extra=_counter_rows(recompiled_counter - original_counter),
    )
    return result


def _reccmp_proves_call_contract(status: dict[str, Any] | None) -> bool:
    """Use reccmp's completed machine-level proof before heuristic p-code."""
    return status is not None and status.get("status") in {"exact", "effective"}


def _build_maps(
    compare: Compare,
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

    aliases, alias_errors = load_aliases(
        equivalence_class=CLASS_FOLDED_SYMBOL_GROUP
    )
    if alias_errors:
        raise RuntimeError("invalid template aliases: " + "; ".join(alias_errors))

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
    try:
        loaded = (
            ProgramLoader.builder()
            .source(str(target.recompiled_path))
            .project(project)
            .load()
        )
        program = loaded.getPrimaryDomainObject(consumer)
        transaction = program.startTransaction("semantic-function-seeds")
        try:
            seed_failures = _seed_required_functions(program, claims, pairs)
        finally:
            program.endTransaction(transaction, True)
        _analyze(program)

        transaction = program.startTransaction("semantic-reccmp-import")
        try:
            import_target_into_ghidra(
                target, FlatProgramAPI(program), image_id=ImageId.RECOMP
            )
        finally:
            program.endTransaction(transaction, True)

        transaction = program.startTransaction("semantic-missing-function-seeds")
        try:
            seed_failures.extend(_seed_required_functions(program, claims, pairs))
        finally:
            program.endTransaction(transaction, True)
        _analyze(program)

        missing = _validate_recompiled_functions(program, claims, pairs)
        manifest["missing_required_functions"] = missing
        manifest["function_seed_failures"] = seed_failures
        folder = project.getProjectData().getRootFolder()
        folder.createFile(PROGRAM_NAME, program, TaskMonitor.DUMMY)
    finally:
        if program is not None:
            program.release(consumer)
        project.close()

    atomic_json(destination / "manifest.json", manifest)


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


def _reccmp_statuses(build_dir: Path) -> dict[int, dict[str, Any]]:
    path = build_dir / "reccmp_report.json"
    if not path.is_file():
        return {}
    rows = json.loads(path.read_text(encoding="utf-8")).get("data", [])
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
) -> list[dict[str, Any]]:
    direct_call_abis = _direct_call_abis(original_program, original_functions)
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
        original_calls = extract_calls(
            original_high,
            original_program,
            original_normalizer,
            original_functions,
            direct_call_abis,
        )
        recompiled_calls = extract_calls(
            recompiled_high,
            recompiled_program,
            recompiled_normalizer,
            recompiled_functions,
            direct_call_abis,
        )
        row.update(compare_extracted_calls(original_calls, recompiled_calls))
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
    full_output = build_dir / REPORT_RELATIVE_PATH
    if full and not args.force and full_output.is_file():
        previous = json.loads(full_output.read_text(encoding="utf-8"))
        if (
            previous.get("scope") == "all"
            and previous.get("fingerprint") == fingerprint(inputs)
        ):
            return previous, full_output

    cache_dir, prep_fingerprint, manifest = ensure_cache_subprocess(
        build_dir, target.target_id, prep_inputs
    )
    compare = Compare.from_target(target)
    (
        pairs,
        original_functions,
        recompiled_functions,
        original_entities,
        recompiled_entities,
    ) = _build_maps(compare)

    original_project = ghidra_env.open_project()
    original_consumer = original_program = None
    recompiled_project = recompiled_consumer = recompiled_program = None
    try:
        original_consumer, original_program = ghidra_env.open_program(original_project)
        recompiled_project, recompiled_consumer, recompiled_program = (
            _open_cached_program(cache_dir)
        )
        rows = compare_programs(
            original_program,
            recompiled_program,
            selected,
            pairs,
            original_functions,
            recompiled_functions,
            original_entities,
            recompiled_entities,
            _reccmp_statuses(build_dir),
            args.timeout,
            args.jobs,
        )
    finally:
        if recompiled_program is not None:
            recompiled_program.release(recompiled_consumer)
        if recompiled_project is not None:
            recompiled_project.close()
        if original_program is not None:
            original_program.release(original_consumer)
        original_project.close()

    report = {
        "schema": SCHEMA_VERSION,
        "fingerprint": fingerprint(inputs),
        "inputs": inputs,
        "scope": "all" if full else "targeted",
        "summary": _summary(rows),
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
    if full:
        output = full_output
    else:
        selection_fingerprint = fingerprint(
            [claim.address for claim in selected]
        )[:12]
        output = (
            build_dir
            / "semantic"
            / f"semantic_report.targeted-{selection_fingerprint}.json"
        )
    atomic_json(output, report)
    return report, output


def load_fresh_report(args: argparse.Namespace) -> tuple[dict[str, Any], Path]:
    repo_root = repo_root_from_file(__file__, 1)
    build_dir = Path(args.build_dir).resolve()
    path = build_dir / REPORT_RELATIVE_PATH
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
    nonpassing = {address for address, row in rows.items() if row["status"] != "pass"}
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
    debt = sorted(
        row["original"]
        for row in report["functions"]
        if row["status"] != "pass"
    )
    if path.is_file():
        previous = json.loads(path.read_text(encoding="utf-8"))
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
        "schema": SCHEMA_VERSION,
        "mode": "hard" if not debt else "ratchet",
        "required": required,
        "debt": debt,
    }
    atomic_json(path, baseline)
    print(
        f"wrote {path}: mode={baseline['mode']} required={len(required)} debt={len(debt)}"
    )


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
    compare_parser.add_argument(
        "--jobs", type=int, default=min(8, os.cpu_count() or 1)
    )

    commands.add_parser("stats")
    gate_parser = commands.add_parser("gate")
    gate_parser.add_argument("--generate-if-stale", action="store_true")
    gate_parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_SECONDS)
    gate_parser.add_argument("--jobs", type=int, default=min(8, os.cpu_count() or 1))
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
