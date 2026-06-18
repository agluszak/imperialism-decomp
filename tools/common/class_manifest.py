#!/usr/bin/env python3
"""Per-class manifest: the single source of truth for class recovery.

A manifest lives at ``config/classes/<Class>.yml`` and has two regions:

  * ``generated:`` — refreshed from Ghidra by ``just dump-manifests``; never
    hand-edited. Carries ``vtable_addr``, ``object_size``, the ``base`` /
    ``ancestry`` / ``root`` recovered from the MFC ``CRuntimeClass`` chain, and the
    raw per-slot facts (``target``, ``kind``, ``is_thunk``, ``is_null``,
    ``ghidra_name``, ``size``, ``prototype``).
  * ``curated:`` — human judgment that survives refreshes: per-slot ``method``
    name + ``confidence`` / ``evidence``, ``fields`` semantics, and ``layout``
    (``base_offset`` / ``status``).

On refresh the ``generated:`` region is replaced wholesale from Ghidra while the
``curated:`` region is preserved verbatim (curated always wins — exactly the rule
``merge_curated_symbols.py`` uses for symbols, but keyed by slot index here).

This module owns the schema, a *deterministic* YAML emitter (so re-dumping an
unchanged class is a no-op diff), and a loader that normalizes hex back to a
canonical spelling. It is pure-Python and Ghidra-free so the codegen / projection
/ gate consumers stay unit-testable.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

# --------------------------------------------------------------------------- #
# Canonical hex spelling
# --------------------------------------------------------------------------- #
# Full code/data addresses are zero-padded to 8 hex digits (e.g. 0x004b44d0);
# small quantities (slot index, byte offset, object/field offsets, object size)
# use a minimum width of 2 (0x04, 0x1d, 0x278) to match the existing CSVs.


def _as_int(value: Any) -> int:
    if isinstance(value, bool):  # bool is an int subclass; reject it explicitly
        raise TypeError("expected hex value, got bool")
    if isinstance(value, int):
        return value
    text = str(value).strip()
    return int(text, 16)


def hex8(value: Any) -> str:
    return f"0x{_as_int(value):08x}"


def hex2(value: Any) -> str:
    return f"0x{_as_int(value):02x}"


# Which keys hold a full address vs. a small offset/index, per manifest region.
_ADDR_FIELDS = {"vtable_addr", "target", "immediate_base_vtable"}
_SMALL_FIELDS = {"index", "byte", "object_size", "base_offset", "offset", "slot_index"}


def _normalize_scalar(key: str, value: Any) -> Any:
    """Re-canonicalize a hex-bearing scalar; pass everything else through."""
    if value is None:
        return None
    if key in _ADDR_FIELDS:
        return hex8(value)
    if key in _SMALL_FIELDS:
        return hex2(value)
    return value


def _normalize_mapping(mapping: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in mapping.items():
        if isinstance(value, dict):
            out[key] = _normalize_mapping(value)
        elif isinstance(value, list):
            out[key] = [
                _normalize_mapping(item) if isinstance(item, dict) else item for item in value
            ]
        else:
            out[key] = _normalize_scalar(key, value)
    return out


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #


def load_manifest(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{path}: manifest root must be a mapping")
    return _normalize_mapping(data)


def loads_manifest(text: str) -> dict[str, Any]:
    data = yaml.safe_load(text) or {}
    if not isinstance(data, dict):
        raise ValueError("manifest root must be a mapping")
    return _normalize_mapping(data)


def classes_dir(repo_root: Path) -> Path:
    return repo_root / "config" / "classes"


def load_all_manifests(repo_root: Path) -> dict[str, dict[str, Any]]:
    """Load every ``config/classes/<Class>.yml`` keyed by class name."""
    out: dict[str, dict[str, Any]] = {}
    cdir = classes_dir(repo_root)
    if not cdir.is_dir():
        return out
    for path in sorted(cdir.glob("*.yml")):
        manifest = load_manifest(path)
        name = manifest.get("class") or path.stem
        out[name] = manifest
    return out


def curated_layout(manifest: dict[str, Any]) -> dict[str, Any]:
    return (manifest.get("curated") or {}).get("layout") or {}


# --------------------------------------------------------------------------- #
# Deterministic emitter
# --------------------------------------------------------------------------- #
# We emit by hand (not yaml.dump) so the layout is fixed and diff-friendly:
#   * a stable key order per region,
#   * hex values as bare words (0x004b44d0), free text double-quoted,
#   * each slot/field as a single-line flow mapping.

_GENERATED_KEY_ORDER = ["vtable_addr", "object_size", "base", "ancestry", "root", "slots"]
_SLOT_KEY_ORDER = [
    "index",
    "byte",
    "target",
    "kind",
    "is_thunk",
    "is_null",
    "ghidra_name",
    "size",
    "prototype",
]
_CURATED_SLOT_KEY_ORDER = ["index", "method", "mac_method", "confidence", "evidence"]
_FIELD_KEY_ORDER = ["offset", "type", "name", "source", "evidence"]
_LAYOUT_KEY_ORDER = [
    "base_offset",
    "base_class",
    "status",
    "header",
    "size_verified",
    "note",
    "base_note",
]

_BAREWORD_HEX = _ADDR_FIELDS | _SMALL_FIELDS


def _scalar(key: str, value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    text = str(value)
    if key in _BAREWORD_HEX:
        # already canonical hex string
        return text
    # Bareword identifiers (class/method names, simple kinds) need no quoting;
    # everything else (free-text evidence, prototypes, types with punctuation,
    # anything YAML would re-read as a non-string) is double-quoted and escaped.
    if _is_safe_plain(text):
        return text
    escaped = text.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


_YAML_KEYWORDS = {"true", "false", "null", "yes", "no", "on", "off", "~", ""}


def _is_safe_plain(text: str) -> bool:
    """True if ``text`` re-loads as itself unquoted (a bareword identifier).

    Must start with a letter/underscore (so digit-leading tokens like hex
    ``0x..`` or numbers stay quoted) and contain only identifier characters, and
    must not collide with a YAML bool/null keyword.
    """
    if text.lower() in _YAML_KEYWORDS:
        return False
    if not (text[0].isalpha() or text[0] == "_"):
        return False
    return all(c.isalnum() or c in "_:" for c in text)


def _flow_mapping(mapping: dict[str, Any], order: list[str]) -> str:
    keys = [k for k in order if k in mapping] + [k for k in mapping if k not in order]
    parts = [f"{k}: {_scalar(k, mapping[k])}" for k in keys]
    return "{" + ", ".join(parts) + "}"


def _emit_list(out: list[str], indent: str, items: list[dict[str, Any]], order: list[str]) -> None:
    for item in items:
        out.append(f"{indent}- {_flow_mapping(item, order)}")


def dump_manifest(manifest: dict[str, Any]) -> str:
    manifest = _normalize_mapping(manifest)
    out: list[str] = []
    out.append(f"class: {manifest['class']}")

    gen = manifest.get("generated") or {}
    out.append("generated:")
    for key in _GENERATED_KEY_ORDER:
        if key not in gen:
            continue
        value = gen[key]
        if key == "slots":
            out.append("  slots:")
            _emit_list(out, "    ", value, _SLOT_KEY_ORDER)
        elif key == "ancestry":
            inner = ", ".join(str(v) for v in value)
            out.append(f"  ancestry: [{inner}]")
        else:
            out.append(f"  {key}: {_scalar(key, value)}")

    cur = manifest.get("curated") or {}
    out.append("curated:")
    layout = cur.get("layout") or {}
    if layout:
        out.append(f"  layout: {_flow_mapping(layout, _LAYOUT_KEY_ORDER)}")
    if cur.get("slots"):
        out.append("  slots:")
        _emit_list(out, "    ", cur["slots"], _CURATED_SLOT_KEY_ORDER)
    if cur.get("fields"):
        out.append("  fields:")
        _emit_list(out, "    ", cur["fields"], _FIELD_KEY_ORDER)

    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------- #
# Refresh merge (curated wins)
# --------------------------------------------------------------------------- #


def merge_refresh(existing: dict[str, Any] | None, fresh_generated: dict[str, Any], class_name: str) -> dict[str, Any]:
    """Build the manifest to write: fresh ``generated`` + preserved ``curated``.

    The ``generated`` region is replaced wholesale (it is all Ghidra-derived).
    The ``curated`` region is carried over verbatim from ``existing`` (curated
    always wins; refreshing Ghidra never clobbers human judgment).
    """
    curated = (existing or {}).get("curated") or {}
    return {"class": class_name, "generated": fresh_generated, "curated": curated}


def curated_slot_methods(manifest: dict[str, Any]) -> dict[int, dict[str, Any]]:
    """Map slot index -> curated slot record (method/confidence/evidence)."""
    out: dict[int, dict[str, Any]] = {}
    for rec in (manifest.get("curated") or {}).get("slots") or []:
        if "index" in rec:
            out[_as_int(rec["index"])] = rec
    return out


def write_manifest(path: Path, manifest: dict[str, Any]) -> bool:
    """Write the manifest deterministically. Returns True if the file changed."""
    text = dump_manifest(manifest)
    if path.exists() and path.read_text(encoding="utf-8") == text:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return True
