#!/usr/bin/env python3
"""Distinct-type inventory for TypeResolver's remaining weak pointer/value grades.

`TypeResolver.resolve_quality` (apply_source_signatures.py) grades every source
parameter/return type string; `ambiguous_simple_name` and `opaque_by_value` are
already driven to zero (the prior dedup/hygiene work), but `opaque_pointee`,
`generic_pointer_fallback`, and `unresolved` still occur across the source
signature set. This tool collects every DISTINCT type-text hitting one of those
three grades (not per-function — a `CDataExchange*` used in 20 different
`DoDataExchange` overrides is ONE inventory row) and classifies each one:

  canonical_game_class_exists          — the pointee is already a modeled game
                                          class (record_model.json); Ghidra just
                                          hasn't been told about it yet (or the
                                          text doesn't match the DTM's spelling).
  canonical_mfc_type_exists            — a well-known MFC class Ghidra's DTM
                                          hasn't been given a real layout for yet
                                          (or has it, opaquely) — see
                                          apply_mfc_datatypes.py's MFC_MODELS,
                                          the canonical place to add a verified one.
  typedef_or_namespace_spelling_mismatch — a real project-local typedef/alias
                                          (e.g. nation_domain_types.h) with zero
                                          DTM representation; the fix is a
                                          resolver-side alias table entry
                                          (_SCALAR_TYPEDEF_ALIASES /
                                          _POINTER_ALIASES), not a DB mutation.
  missing_external_opaque_type         — a genuine external (Win32/CRT/OLE) type
                                          with no game or MFC ownership; staying
                                          opaque/void* is CORRECT, not a defect.
  stale_duplicate                      — multiple DTM datatypes still share this
                                          simple name after TypeResolver's own
                                          disposable-placeholder exclusions (a
                                          REAL ambiguity, not a stub artifact).
  genuinely_unknown                    — none of the above; an actual class-
                                          recovery or type-modelling gap.

READ-ONLY: opens the program `writable=False`. Writes
build-msvc500/evidence/weak_pointer_type_inventory.csv.

  just weak-pointer-type-inventory
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from tools.common import ghidra_env
from tools.common.repo import repo_root_from_file
from tools.ghidra.apply_source_signatures import (
    _is_placeholder_return,
    _SCALAR_TYPEDEF_ALIASES,
    TypeResolver,
    parse_prototype,
)
from tools.source_model import build_model

_WEAK_GRADES = ("opaque_pointee", "generic_pointer_fallback", "unresolved")

_DEFAULT_RECORD_MODEL = "build-msvc500/generated/record_model.json"
_DEFAULT_OUT = "build-msvc500/evidence/weak_pointer_type_inventory.csv"

# Well-known MFC 4.2 classes (beyond apply_mfc_datatypes.py's currently-modeled
# set) — a genuinely finite, documented framework, not project guesswork. A
# pointee matching one of these has a real, findable layout (vendor/msvc500/
# headers/mfc/include/*.h); it just isn't in MFC_MODELS yet.
_KNOWN_MFC_TYPES = {
    "cobject", "cwnd", "ccmdtarget", "cdc", "cview", "cdocument", "cdataexchange",
    "cframewnd", "cdialog", "cwinapp", "cwinthread", "cfile", "cfont", "cmenu",
    "cscrollbar", "coledataobject", "cprintinfo", "cexception", "cstring",
    "cstringdata", "cruntimeclass", "cptrlist", "carchive", "cdumpcontext",
    "ctypelibcache", "cpreviewview", "csplitterwnd", "cdocmanager",
    "ccommandlineinfo", "cbitmap", "cpen", "cbrush", "cpalette", "cgdiobject",
    "crect", "cpoint", "csize", "ctypedptrlist", "cobarray", "cobject",
    "ccomboBox", "clistbox", "cedit", "cbutton", "cstatic", "ctoolbar",
    "cstatusbar", "ctoolbarctrl", "cimagelist",
}

# Genuine external (Win32 API / CRT / OLE) types with no MFC or game ownership —
# staying opaque/void* is the CORRECT model, not a gap (see the module
# docstring's `missing_external_opaque_type` definition).
_KNOWN_EXTERNAL_SDK_TYPES = {
    "createstruct", "tagcreatestructa", "waveformatex", "afx_msgmap",
    "afx_cmdhandlerinfo", "afx_dispmap", "afx_eventsinkmap",
    "_afx_occ_dialog_info", "itypelib", "_crt_double", "_crt_float", "_ldbl12",
}


def _strip_elaborated(text: str) -> str:
    text = text.replace("const", " ").replace("volatile", " ")
    text = re.sub(r"\b(class|struct|union|enum)\b", " ", text).strip()
    return text


def _base_type_name(type_text: str) -> str:
    """The bare pointee/value name: strip elaborated-type keywords, trailing
    `*`/`&`, and any `Namespace::` qualifier (only the last segment matters for
    a simple-name DTM lookup)."""
    text = _strip_elaborated(type_text)
    while text.endswith("*") or text.endswith("&"):
        text = text[:-1].strip()
    if "::" in text:
        text = text.rsplit("::", 1)[1].strip()
    return text


def classify_weak_pointer_type(
    base_name: str,
    *,
    game_classes: set[str],
    name_count: int,
) -> tuple[str, str]:
    """Pure: classify one distinct weak-graded type by its bare base name.

    `game_classes` is the lowercase set of already-modeled game class names
    (from record_model.json). `name_count` is TypeResolver's own
    `_name_count.get(base_name, 0)` — > 1 after its disposable-placeholder
    exclusions means a REAL duplicate, not a stub artifact.
    """
    key = base_name.strip().lower()
    if name_count > 1:
        return "stale_duplicate", (
            f"{name_count} distinct DTM datatypes still share the simple name "
            f"'{base_name}' after excluding bare FunctionDefinitions and "
            "/Demangler stubs -- a genuine collision, not a placeholder artifact."
        )
    if key in game_classes:
        return "canonical_game_class_exists", (
            f"'{base_name}' is already a modeled game class (record_model.json); "
            "Ghidra's DTM doesn't have a matching datatype yet, or under a "
            "different exact spelling."
        )
    if key in _KNOWN_MFC_TYPES:
        return "canonical_mfc_type_exists", (
            f"'{base_name}' is a well-known MFC 4.2 class; add its verified "
            "layout to tools/ghidra/apply_mfc_datatypes.py's MFC_MODELS (measure "
            "it from vendor/msvc500/headers/mfc/include first)."
        )
    if key in _KNOWN_EXTERNAL_SDK_TYPES:
        return "missing_external_opaque_type", (
            f"'{base_name}' is a genuine external Win32/CRT/OLE type with no "
            "game or MFC ownership; staying opaque/void* is correct here."
        )
    if key in _SCALAR_TYPEDEF_ALIASES:
        # Already resolved by the alias table -- should not appear as weak
        # anymore, but keep the classification available for a future addition
        # that hasn't been wired into the resolver yet.
        return "typedef_or_namespace_spelling_mismatch", (
            f"'{base_name}' is a known project-local typedef alias; verify it is "
            "wired into _SCALAR_TYPEDEF_ALIASES/_POINTER_ALIASES."
        )
    return "genuinely_unknown", (
        f"'{base_name}' matches none of the known game-class/MFC/external-SDK/"
        "typedef sets -- a real class-recovery or type-modelling gap."
    )


def load_game_class_names(repo_root: Path, record_model_path: str) -> set[str]:
    p = Path(record_model_path)
    if not p.is_absolute():
        p = repo_root / p
    if not p.exists():
        return set()
    data = json.loads(p.read_text(encoding="utf-8"))
    names = set()
    for qualified_name in data:
        simple = qualified_name.rsplit("::", 1)[-1]
        names.add(simple.strip().lower())
    return names


def collect_weak_type_occurrences(program, model) -> dict[tuple[str, str], dict]:
    """Ghidra-touching: (quality, base_name) -> {count, example, name_count}."""
    resolver = TypeResolver(program)
    occurrences: dict[tuple[str, str], dict] = {}

    def note(quality: str, raw_text: str, claim_name: str) -> None:
        base = _base_type_name(raw_text)
        key = (quality, base)
        row = occurrences.setdefault(
            key, {"count": 0, "example": claim_name,
                  "name_count": resolver._name_count.get(base, 0)})
        row["count"] += 1

    for _addr, claim in sorted(model.functions.items()):
        if claim.kind not in ("FUNCTION", "LIBRARY") or not claim.prototype:
            continue
        parsed = parse_prototype(claim.prototype)
        if parsed is None:
            continue
        _cc, ret_str, param_strs, _kind = parsed
        if param_strs and param_strs[-1].strip() == "...":
            param_strs = param_strs[:-1]  # varargs marker, not a real type
        for t in param_strs:
            _dt, q = resolver.resolve_quality(t)
            if q in _WEAK_GRADES:
                note(q, t, claim.name)
        if not _is_placeholder_return(ret_str):
            _dt, q = resolver.resolve_quality(ret_str)
            if q in _WEAK_GRADES:
                note(q, ret_str, claim.name)
    return occurrences


def build_inventory_rows(
    occurrences: dict[tuple[str, str], dict], game_classes: set[str],
) -> list[dict]:
    rows = []
    for (quality, base_name), info in occurrences.items():
        classification, note = classify_weak_pointer_type(
            base_name, game_classes=game_classes, name_count=info["name_count"])
        rows.append({
            "type_text": base_name, "quality": quality,
            "occurrence_count": info["count"], "example_function": info["example"],
            "classification": classification, "note": note,
        })
    rows.sort(key=lambda r: (-r["occurrence_count"], r["type_text"]))
    return rows


_COLUMNS = ["type_text", "quality", "occurrence_count", "example_function",
            "classification", "note"]


def write_inventory(rows: list[dict], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    lines = ["|".join(_COLUMNS)]
    for row in rows:
        lines.append("|".join(str(row[c]).replace("|", "/").replace("\n", " ")
                              for c in _COLUMNS))
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--out", default=_DEFAULT_OUT)
    p.add_argument("--record-model", default=_DEFAULT_RECORD_MODEL)
    args = p.parse_args()

    repo_root = repo_root_from_file(__file__, levels_up=2)
    model = build_model(repo_root, "IMPERIALISM")
    game_classes = load_game_class_names(repo_root, args.record_model)

    project = ghidra_env.open_project()
    consumer = program = None
    try:
        consumer, program = ghidra_env.open_program(project, writable=False)
        occurrences = collect_weak_type_occurrences(program, model)
    finally:
        if program is not None:
            program.release(consumer)
        project.close()

    rows = build_inventory_rows(occurrences, game_classes)
    out_path = Path(args.out)
    if not out_path.is_absolute():
        out_path = repo_root / out_path
    write_inventory(rows, out_path)

    by_class: dict[str, int] = {}
    for r in rows:
        by_class[r["classification"]] = by_class.get(r["classification"], 0) + 1
    print(f"[WEAK POINTER TYPE INVENTORY] {len(rows)} distinct type(s) -> {out_path}")
    print("  by classification: " + ", ".join(f"{k}={v}" for k, v in sorted(by_class.items())))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
