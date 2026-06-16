#!/usr/bin/env python3
"""Self-contained checks for tools.workflow.bootstrap_class (no pytest, no Ghidra).

Run: uv run python -m tools.workflow.bootstrap_class_test
Exercises the pure codegen/classification/CSV-merge half with a synthetic
TUnitOrderState-shaped fixture (base = TObject).
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from tools.workflow import bootstrap_class as bc


def slot(index, target, *, null=False, name=None, proto=None, size=0, decomp=None):
    return {
        "index": index,
        "byte_offset": index * 4,
        "slot_label": f"0x{index * 4:02x}",
        "entry_addr": "0x00000000" if null else f"0x{target:08x}",
        "target_addr": "0x00000000" if null else f"0x{target:08x}",
        "is_null": null,
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
        )
        own_plan = bc.plan_ownership(own_path, owned, "src/game/TUnitOrderState.cpp")
        check("ownership flags collision", any("5c2490" in c for c in own_plan.collisions))
        own_addrs = {r["address"] for r in own_plan.new_rows}
        check("ownership skips collided addr", "5c2490" not in own_addrs)
        check("ownership adds 5c27d0", "5c27d0" in own_addrs)

    print("\nALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
