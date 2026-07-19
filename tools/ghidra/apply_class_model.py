#!/usr/bin/env python3
"""Project the verified class model into Ghidra: real layouts replace 1-byte stubs.

Consumes the three `just generate-type-model` artifacts:
  - record_model.json   (semantic: bases/fields — Clang AST)
  - layout_oracle.json  (physical: sizes/offsets — measured by real MSVC500)
  - class_model_audit.csv (verdict per record vs the binary's RTTI object size)

Eligibility is the audit's verdict — the projector NEVER silently chooses between
disagreeing models:
  verified / no_rtti          -> projected
  source_incomplete / source_oversized -> BLOCKED (queued with the size delta)

Projection (one transaction; verify-then-commit):
  Phase A  create/replace every eligible record as a structure of its EXACT
           oracle size (undefined-filled). Existing same-name datatypes — the
           1-byte stubs and partial RTTI shells — are REPLACED, which rewrites
           all references to them in one step.
  Phase B  populate components:
           - game bases: flattened recursively at their oracle base offsets
             (better decompiler expressions than nested base.field chains);
           - external (MFC) bases: one component of the DB's MFC datatype when
             its length matches the oracle EXTBASE size, else left undefined;
           - own fields at exact oracle offsets; the semantic type is used only
             when it resolves at exactly the oracle size, else undefined bytes —
             PHYSICAL TRUTH WINS;
           - vptr at 0 for polymorphic roots (void** until vtable structs are
             wired), inherited vptrs arrive via base flattening.
  Verify   every projected structure's DB length equals the oracle size; abort
           the whole transaction on any mismatch.

  just apply-class-model            # dry-run report
  just apply-class-model --apply    # project (MUTATES the DB)
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from tools.common import ghidra_env
from tools.common.repo import repo_root_from_file

_PRIM_SIZES = {
    "void": 0, "bool": 1, "char": 1, "signed char": 1, "unsigned char": 1,
    "short": 2, "unsigned short": 2, "int": 4, "unsigned int": 4,
    "long": 4, "unsigned long": 4, "float": 4, "double": 8,
}


def plan_components(qn: str, model: dict, layouts: dict, ext_bases: dict,
                    _depth: int = 0):
    """Pure planning: -> (size, [(offset, size, kind, name, type_text)], notes).

    kind is one of: vptr | base_ext | field | field_array. Game bases are
    flattened recursively (their planned components shifted by the base offset);
    the vptr of a polymorphic root is emitted once at offset 0 and inherited
    through flattening. Components never overlap by construction: base regions
    and field offsets come from the same single MSVC500 layout.
    """
    if _depth > 16:
        return None, [], [f"base_cycle:{qn}"]
    lay = layouts.get(qn)
    rec = model.get(qn)
    if lay is None or rec is None or lay.get("size") is None:
        return None, [], [f"no_layout:{qn}"]
    comps: list = []
    notes: list = []

    base_types = {b["type"] for b in rec.get("bases", [])}
    for base, boff in sorted(lay.get("bases", {}).items(), key=lambda kv: kv[1]):
        if base in model:
            bsz, bcomps, bnotes = plan_components(base, model, layouts, ext_bases, _depth + 1)
            notes += bnotes
            comps += [(boff + off, sz, kind, name, tt) for off, sz, kind, name, tt in bcomps]
        elif base in ext_bases:
            comps.append((boff, ext_bases[base], "base_ext", f"base_{base}", base))
        else:
            notes.append(f"unknown_base:{base}")
    # Polymorphic ROOT: own virtuals and no polymorphic base chain below us —
    # cheap approximation: no component claims offset 0 yet.
    if rec.get("has_own_virtuals") and not any(off == 0 for off, *_ in comps):
        comps.append((0, 4, "vptr", "vfptr", "void**"))

    fields = lay.get("fields", {})
    for f in rec.get("fields", []):
        fl = fields.get(f["name"])
        if fl is None:
            continue  # skipped by the oracle (bitfield/reference) — stays undefined
        if fl["size"] == 0:
            continue  # zero-length pad array
        kind = "field_array" if f.get("array_count") else "field"
        comps.append((fl["offset"], fl["size"], kind, f["name"], f["type"]))
    comps.sort(key=lambda c: c[0])
    # Drop overlapping duplicates defensively (e.g. a base component and an own
    # field both claiming an offset would indicate an evidence bug — note it).
    pruned: list = []
    watermark = -1
    for c in comps:
        if c[0] < watermark:
            notes.append(f"overlap:{c[3]}@{c[0]:#x}")
            continue
        pruned.append(c)
        watermark = c[0] + c[1]
    if watermark > lay["size"]:
        notes.append(f"exceeds_size:{watermark:#x}>{lay['size']:#x}")
    return lay["size"], pruned, notes


def load_artifacts(repo_root: Path, args):
    model = json.loads((repo_root / args.model).read_text())
    lay = json.loads((repo_root / args.layout).read_text())
    verdicts = {}
    with open(repo_root / args.audit, newline="") as fh:
        for row in csv.DictReader(fh):
            verdicts[row["name"]] = row["verdict"]
    return model, lay["layouts"], lay.get("external_bases", {}), verdicts


def run(program, args, model, layouts, ext_bases, verdicts):
    from ghidra.program.model.data import (
        ArrayDataType, CategoryPath, DataTypeConflictHandler, PointerDataType,
        StructureDataType, Undefined1DataType,
    )
    import pyghidra

    dtm = program.getDataTypeManager()

    # Simple-name index of existing datatypes (for replace + semantic field types).
    named: dict = {}
    for dt in dtm.getAllDataTypes():
        named.setdefault(dt.getName(), dt)

    def resolve_semantic(type_text: str, want_size: int):
        """DataType matching the spelling at EXACTLY want_size bytes, else None."""
        import re
        t = re.sub(r"\b(class|struct|union|enum|const|volatile)\b", " ", type_text).strip()
        ptr = 0
        while t.endswith("*") or t.endswith("&"):
            ptr += 1
            t = t[:-1].strip()
        t = re.sub(r"\[.*\]", "", t).strip()  # element type of arrays
        if ptr:
            base = named.get(t)
            from ghidra.program.model.data import VoidDataType
            base = base if base is not None else VoidDataType.dataType
            dt = PointerDataType(base, dtm)
            return dt if dt.getLength() == want_size or want_size == 4 else None
        if t in _PRIM_SIZES:
            prim = named.get(t) or named.get(t.replace("unsigned ", "u"))
            if prim is not None and prim.getLength() == want_size:
                return prim
            return None
        dt = named.get(t)
        if dt is not None and dt.getLength() == want_size:
            return dt
        return None

    eligible = sorted(qn for qn, v in verdicts.items()
                      if v in ("verified", "no_rtti") and qn in layouts and qn in model)
    blocked = sorted((qn, v) for qn, v in verdicts.items()
                     if v in ("source_incomplete", "source_oversized"))

    plans = {}
    queue: list = []
    for qn in eligible:
        size, comps, notes = plan_components(qn, model, layouts, ext_bases)
        if size is None:
            queue.append((qn, "plan_failed:" + ";".join(notes)))
            continue
        hard = [n for n in notes if n.startswith(("overlap", "exceeds_size", "base_cycle"))]
        if hard:
            queue.append((qn, "plan_conflict:" + ";".join(hard)))
            continue
        plans[qn] = (size, comps, notes)

    if not args.apply:
        return {"projected": len(plans), "queued": queue, "blocked": blocked,
                "replaced": 0, "created": 0}

    tx = program.startTransaction("apply class model")
    commit = False
    replaced = created = 0
    try:
        # Phase A: sized shells (replace stubs so references rewrite).
        shells = {}
        for qn, (size, _c, _n) in plans.items():
            simple = qn.split("::")[-1]
            s = StructureDataType(CategoryPath.ROOT, simple, size, dtm)
            existing = named.get(simple)
            if existing is not None and existing.getClass().getSimpleName() in (
                    "StructureDB", "StructureDataType"):
                new_dt = dtm.replaceDataType(existing, s, True)
                replaced += 1
            else:
                new_dt = dtm.addDataType(s, DataTypeConflictHandler.REPLACE_HANDLER)
                created += 1
            named[simple] = new_dt
            shells[qn] = new_dt

        # Phase B: populate components at exact offsets.
        for qn, (size, comps, _n) in plans.items():
            st = shells[qn]
            for off, sz, kind, name, type_text in comps:
                dt = None
                if kind == "vptr":
                    from ghidra.program.model.data import VoidDataType
                    dt = PointerDataType(PointerDataType(VoidDataType.dataType, dtm), dtm)
                elif kind == "base_ext":
                    cand = named.get(type_text)
                    if cand is not None and cand.getLength() == sz:
                        dt = cand
                elif kind in ("field", "field_array"):
                    dt = resolve_semantic(type_text, sz)
                    if dt is None and kind == "field_array":
                        # element-wise array when the element resolves
                        import re
                        m = re.search(r"\[(\d+)\]", type_text)
                        if m:
                            n = int(m.group(1))
                            if n > 0 and sz % n == 0:
                                el = resolve_semantic(type_text, sz // n)
                                if el is not None:
                                    dt = ArrayDataType(el, n, sz // n, dtm)
                if dt is None:
                    if sz == 1:
                        dt = Undefined1DataType.dataType
                    else:
                        dt = ArrayDataType(Undefined1DataType.dataType, sz, 1, dtm)
                try:
                    st.replaceAtOffset(off, dt, sz, name, None)
                except Exception as exc:  # noqa: BLE001
                    raise RuntimeError(f"{qn}.{name}@{off:#x}: {exc}") from exc

        # Verify: exact sizes survived population.
        bad = [(qn, shells[qn].getLength(), plans[qn][0])
               for qn in plans if shells[qn].getLength() != plans[qn][0]]
        if bad:
            raise RuntimeError(f"size drift after population: {bad[:5]}")
        commit = True
    finally:
        program.endTransaction(tx, commit)
    if commit:
        program.save("apply class model", pyghidra.task_monitor())
    return {"projected": len(plans), "queued": queue, "blocked": blocked,
            "replaced": replaced, "created": created}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--apply", action="store_true", help="Project (default: dry-run report).")
    p.add_argument("--model", default="build-msvc500/generated/record_model.json")
    p.add_argument("--layout", default="build-msvc500/generated/layout_oracle.json")
    p.add_argument("--audit", default="build-msvc500/evidence/class_model_audit.csv")
    p.add_argument("--queue-out", default="build-msvc500/evidence/class_model_queue.csv")
    args = p.parse_args()

    repo_root = repo_root_from_file(__file__, levels_up=2)
    model, layouts, ext_bases, verdicts = load_artifacts(repo_root, args)

    project = ghidra_env.open_project()
    consumer = program = None
    try:
        consumer, program = ghidra_env.open_program(project, writable=bool(args.apply))
        result = run(program, args, model, layouts, ext_bases, verdicts)
    finally:
        if program is not None:
            program.release(consumer)
        project.close()

    out = repo_root / args.queue_out
    out.parent.mkdir(parents=True, exist_ok=True)
    lines = ["name|reason"]
    lines += [f"{qn}|{r}" for qn, r in result["queued"]]
    lines += [f"{qn}|blocked_{v}" for qn, v in result["blocked"]]
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")

    mode = "APPLIED" if args.apply else "DRY RUN"
    print(f"[{mode}] class model: projected={result['projected']} "
          f"(replaced={result['replaced']}, created={result['created']}) "
          f"queued={len(result['queued'])} blocked={len(result['blocked'])}")
    print(f"  queue -> {out}")
    for qn, r in result["queued"][:8]:
        print(f"    {qn}: {r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
