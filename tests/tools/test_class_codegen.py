#!/usr/bin/env python3
"""Self-contained checks for tools.workflow.class_codegen (no Ghidra).
Exercises the pure codegen/classification/CSV-merge half with a synthetic
TUnitOrderState-shaped fixture (base = TObject).
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from tools.ghidra.vtable_slots import is_rtti_getter
from tools.workflow import class_codegen as bc


def slot(index, target, *, null=False, name=None, proto=None, size=0, decomp=None, thunk=False):
    return {
        "index": index,
        "byte_offset": index * 4,
        "slot_label": f"0x{index * 4:02x}",
        "entry_addr": "0x00000000" if null else f"0x{target:08x}",
        "target_addr": "0x00000000" if null else f"0x{target:08x}",
        "is_null": null,
        "is_thunk": thunk,
        "ghidra_name": name,
        "prototype": proto,
        "size": size,
        **({"decompiled_c": decomp} if decomp else {}),
    }


def make_fixture():
    # base TObject targets at each index
    base = [
        slot(0, 0x401000),  # GetRuntimeClass
        slot(1, 0x401100),  # dtor slot (base scalar dtor)
        slot(2, 0x485E90),  # Serialize (inherited unchanged below)
        slot(3, 0x4798D0),  # ShallowClone
        slot(4, 0x415CE0),  # ShallowFree
        slot(5, 0x402000),  # WriteTo (base)
    ]
    # class TUnitOrderState
    cls = [
        slot(0, 0x5C2490, name="GetRuntimeClass", proto="CRuntimeClass* __thiscall GetRuntimeClass() const"),
        slot(1, 0x5C24E0),  # scalar deleting destructor (named via symbols)
        slot(2, 0x485E90),  # Serialize inherited unchanged
        slot(3, 0x4798D0),  # ShallowClone inherited unchanged
        slot(4, 0, null=True),  # null abstract slot
        slot(5, 0x5C27D0, name="WriteTo", proto="void __thiscall WriteTo(TStream* stream)",
             decomp="void WriteTo(TStream* s){ /* ... */ }"),
        slot(6, 0x5C2630, name="SetOrderModeSlot34",
             proto="void __thiscall SetOrderModeSlot34(int mode, int payload)"),
    ]
    symbols = {
        "5c24e0": bc.SymbolRow(
            name="TUnitOrderState::`scalar deleting destructor'",
            size="30",
            type="function",
            prototype="void* __thiscall `scalar deleting destructor'(unsigned int)",
        ),
        "5c2490": bc.SymbolRow(
            name="TUnitOrderState::GetRuntimeClass", size="6", type="function",
            prototype="CRuntimeClass* __thiscall GetRuntimeClass() const"),
        "5c27d0": bc.SymbolRow(
            name="TUnitOrderState::WriteTo", size="40", type="function",
            prototype="void __thiscall WriteTo(TStream* stream)"),
    }
    return cls, base, symbols


def check(name, cond):
    if not cond:
        raise AssertionError(f"FAILED: {name}")
    print(f"  ok: {name}")


def main() -> int:
    cls, base, symbols = make_fixture()
    slots = bc.classify_slots(cls, base, symbols)
    kinds = {s.index: s.kind for s in slots}

    check("slot0 GetRuntimeClass is override", kinds[0] == "override")
    check("slot1 is scalar_dtor", kinds[1] == "scalar_dtor")
    check("slot2 Serialize inherited", kinds[2] == "inherited")
    check("slot3 ShallowClone inherited", kinds[3] == "inherited")
    check("slot4 null", kinds[4] == "null")
    check("slot5 WriteTo override", kinds[5] == "override")
    check("slot6 SetOrderModeSlot34 new", kinds[6] == "new")

    # prototype parsing
    sig = bc.parse_prototype("CRuntimeClass* __thiscall GetRuntimeClass() const", "x")
    check("parse ret", sig.ret == "CRuntimeClass*")
    check("parse name", sig.name == "GetRuntimeClass")
    check("parse const", sig.const == " const")
    sig2 = bc.parse_prototype("void __thiscall SetOrderModeSlot34(int mode, int payload)", "x")
    check("parse args", sig2.args == "int mode, int payload")
    check("parse void args empty", bc.parse_prototype("void __thiscall F(void)", "x").args == "")

    header = bc.render_header("TUnitOrderState", "TObject", "0x0066ee18", slots)
    check("header has VTABLE marker", "// VTABLE: IMPERIALISM 0x0066ee18" in header)
    check("header has base", "class TUnitOrderState : public TObject {" in header)
    check("header GetRuntimeClass override", "CRuntimeClass* GetRuntimeClass() const override; // slot 0x00" in header)
    check("header dtor", "~TUnitOrderState() override; // slot 0x04" in header)
    check("header inherited comment", "inherited from TObject unchanged (0x485e90)" in header)
    check("header null comment", "slot 0x10 (null in original table)" in header)
    check("header new virtual", "virtual void SetOrderModeSlot34(int mode, int payload); // slot 0x18" in header)

    cpp = bc.render_cpp("TUnitOrderState", slots)
    check("cpp synthetic marker", "// SYNTHETIC: IMPERIALISM 0x5c24e0" in cpp)
    check("cpp synthetic name", "// TUnitOrderState::`scalar deleting destructor'" in cpp)
    check("cpp FUNCTION markers ascending",
          cpp.index("0x5c2490") < cpp.index("0x5c24e0") < cpp.index("0x5c27d0"))
    check("cpp decompile seed inlined", "Ghidra decompile seed" in cpp)
    check("cpp RTTI placeholder", 'extern "C" char g_pClassDescTUnitOrderState = 0;' in cpp)

    owned = [s for s in slots if s.kind in ("override", "new", "scalar_dtor")]

    with tempfile.TemporaryDirectory() as td:
        sym_path = Path(td) / "symbols.csv"
        # one address already present (5c2490) to exercise de-dup
        sym_path.write_text(
            "address|name|size|type|prototype\n"
            "5c2490|TUnitOrderState::GetRuntimeClass|6|function|x\n"
        )
        sym_plan = bc.plan_symbols(sym_path, owned, "TUnitOrderState")
        new_addrs = {r["address"] for r in sym_plan.new_rows}
        check("symbols de-dups existing 5c2490", "5c2490" not in new_addrs)
        check("symbols adds scalar dtor row", "5c24e0" in new_addrs)
        scalar_row = next(r for r in sym_plan.new_rows if r["address"] == "5c24e0")
        check("scalar dtor backtick name",
              scalar_row["name"] == "TUnitOrderState::`scalar deleting destructor'")
        merged = sym_plan.merged_text()
        check("merged keeps header", merged.startswith("address|name|size|type|prototype"))
        check("merged inserts 5c24e0 before 5c27d0",
              merged.index("5c24e0|") < merged.index("5c27d0|"))

        own_path = Path(td) / "ownership.csv"
        own_path.write_text(
            "address|target_cpp|ownership|note\n"
            "5c2490|src/game/Other.cpp|manual|marker_sync\n"
            "5c27d0|src/game/TUnitOrderState.cpp|manual|marker_sync\n"
        )
        owned[0].target_addr = "005c2490"
        own_plan = bc.plan_ownership(own_path, owned, "src/game/TUnitOrderState.cpp")
        check("ownership flags collision", any("5c2490" in c for c in own_plan.collisions))
        own_addrs = {r["address"] for r in own_plan.new_rows}
        check("ownership skips collided addr", "5c2490" not in own_addrs)
        check("ownership does not duplicate same-owner addr", "5c27d0" not in own_addrs)

    # ILT-thunk slots are never owned (no body / symbol / ownership row)
    thunk_cls = [
        slot(0, 0x5C2490, name="GetRuntimeClass",
             proto="CRuntimeClass* __thiscall GetRuntimeClass() const"),
        slot(1, 0x401234, name="thunk_Foo", proto="void __thiscall Foo()", thunk=True),
    ]
    tslots = bc.classify_slots(thunk_cls, [], {})
    check("thunk slot classified ilt_thunk", tslots[1].kind == "ilt_thunk")
    check("thunk slot not owned",
          not any(s.kind in ("override", "new", "scalar_dtor") for s in tslots if s.index == 1))
    t_cpp = bc.render_cpp("TFoo", tslots)
    check("thunk slot no FUNCTION marker", "0x401234" not in t_cpp)
    t_hdr = bc.render_header("TFoo", "TObject", "0x1", tslots)
    check("thunk slot header comment", "ILT/linker thunk (0x401234)" in t_hdr)

    # RTTI-recovered base edge is cited in the header (vs. unverified TODO)
    rtti = {
        "class_name": "TUnitOrderState",
        "ancestry": ["TUnitOrderState", "TObject", "CObject"],
        "root": "TObject",
        "immediate_base": "TObject",
    }
    h_rtti = bc.render_header("TUnitOrderState", "TObject", "0x0066ee18", slots, rtti=rtti)
    check("rtti header cites chain", "recovered from RTTI CRuntimeClass chain" in h_rtti)
    check("rtti header shows ancestry", "TUnitOrderState -> TObject -> CObject" in h_rtti)
    h_nortti = bc.render_header("TUnitOrderState", "TObject", "0x0066ee18", slots)
    check("no-rtti header keeps verify TODO", "confirm the base edge" in h_nortti)

    # deleting-destructor-bridge detection (flag, don't reclassify)
    check("dtor suspect AndMaybeFree",
          bc.looks_like_deleting_dtor("TTransFocusAnimation::DestructTTransFocusAnimationAndMaybeFree"))
    check("dtor suspect ??_G", bc.looks_like_deleting_dtor("TFoo::??_G"))
    check("dtor suspect rejects Serialize", not bc.looks_like_deleting_dtor("Serialize"))
    check("dtor suspect rejects none", not bc.looks_like_deleting_dtor(None))
    suspect_slots = [s for s in slots if s.dtor_suspect]
    check("scalar_dtor slot not double-flagged", all(s.kind != "scalar_dtor" for s in suspect_slots))
    cpp_warns = "WARNING(manifest): this slot's name looks like a deleting-destructor" in cpp
    dtor_slot = next((s for s in slots if bc.looks_like_deleting_dtor(s.qualified_name)
                      and s.kind in ("override", "new")), None)
    check("dtor suspect warning emitted iff suspect present",
          cpp_warns == (dtor_slot is not None))

    # auto-detect boundary helper (next-vtable RTTI getter)
    check("rtti getter ClassNamePointer", is_rtti_getter("GetTAnimatorClassNamePointer"))
    check("rtti getter GetRuntimeClass", is_rtti_getter("GetRuntimeClass"))
    check("rtti getter rejects method", not is_rtti_getter("Serialize"))
    check("rtti getter rejects none", not is_rtti_getter(None))

    print("\nALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
