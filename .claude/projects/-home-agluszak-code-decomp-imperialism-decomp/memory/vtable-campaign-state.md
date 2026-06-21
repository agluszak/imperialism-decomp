---
name: vtable-campaign-state
description: Vtable-not-matching reduction campaign — progress, method, and remaining targets
metadata:
  type: project
---

Driving `just vtable` "Vtables not matching" DOWN. Started 156 (2026-06-21), at **95**.
Method: source-only (edit header/cpp → `just build` → `just vtable`), ignore manifests
& generated metadata, don't chase function similarity, commit every few fixes, skip gates.

**Defect pattern 6 — sibling shares a body (HIGHEST yield so far, 119→95 in one fix):**
A slot-body address is owned by the WRONG sibling class, so the real introducing base
+ all its descendants get an unmarked stub at that slot and never pair. Tell: the diff
shows `(orig / recompA) : SiblingClass::Foo` on the left and `(no orig / recompB) :
BaseClass::Foo` on the right for MANY classes at the same byte offset. Fix: move the
`// FUNCTION:` marker + `function_ownership.csv` row + `symbols.csv` name from the
sibling to the real base (verify by address locality — the body usually sits in the
base's own address range). Descendants inherit it → all cascade. The losing sibling
keeps an unmarked stub for its own slot (it was already not-100%, so no count regression).
Done: 0x572bb0 UniversityDialogMethod_00405623 moved TNumberedItem→TNoHilitePicture,
cascaded to ~24 picture/view classes (TBackgroundPicture, TColorKey*, TGameSetup*,
TBuildingView family, TNetSelect*, dialogs, etc.). Also 0x4b5180 (Mac Produce / slot
0x3c) moved TCityOrderItem→TProductionOrder, cascaded to 7 Order classes (TExpansion/
TFoodProcessing/TItem/TOrItem/TPopGrowth/TPowerPlant/TTrainingOrder). 119→95→88.

Remaining families are all the HARD type (no quick cascade left):
- **Cluster** (~21: TCluster base + clusters) — has a SECONDARY embedded vtable at
  byte 0x228+ (TObject/TEventHandler/TControl subobject) plus ~50 junk new-virtuals;
  needs real multi-vtable reconstruction, not a rename. Biggest lever but hardest.
- **TCountry/GreatPower** (~8) — scrambled/oversized base vtable, slots in wrong order
  + many appended new-virtuals; needs slot-by-slot reorder. See [[tcountry-intermediate-base]].
- **Minister** city-minister family (~6) — oversized, dedup+reorder per minister-recipe.
- **Zone** (TZone/TPortZone/TOcean/TOceanDialog) — wrong-base: TOcean slot 0x1c points
  at a TPortZone body → TOcean is TPortZone-derived not TObject. Reparent cascade.
- **Stream** (TFileStream/TCountingStream/THandleStream) — TStream base tail (byte
  0x70,0xa8-0xc0) unbound + missing 3 slots; 0x489070/0x489030 wrongly owned by
  TFileStream (sibling-share of base slots). Mechanical but multi-step.
- **Thunk-resolution 1-slot wins** (TIconBar/TCreditsPicture 0x1c, TGameSetupDialog/
  TPlaceCityDialog 0xa0): orig slot = ILT jmp thunk that reccmp won't auto-follow.
  TPlaceCityDialog's 0x4d1e60 IS claimed (stubs_part013 + symbols.csv) → un-import per
  [[imported-thunks-block-vtable-resolution]]. The others (0x409a20/0x401e6a/0x402289)
  are unclaimed yet still unresolved — needs investigation (maybe not detected as thunk).

`override` is `#define override` empty (compat.h) → MSVC500 matches overrides by
name+signature; the 5 recurring defects + the fix recipes are in
`.claude/skills/decomp-loop/heuristics.md` §12b. See [[ghidra-names-provisional]].

Done so far (all committed): MFC list audit L1-L7; TPtrList base slots 0x64-0x78
(TArmyStackList/TTaskList); TSortedPtrList dup-dtor symbol; TBehavior dup virtuals;
TCommand→TObject; TStream→TObject; TAnimation phantom de-virtualize; TStaticText
5 missing slots (TRadioText/TSelectoText); TMinisterView + 3 view classes slot-0x48
signature (CPoint*,int,int,int).

Also done (2nd session): TDefenseMinister dedup+reorder + its 5 personalities
(slot-0x60 override rename DefenseSlot18→CreateTDefenseMinisterInstance).

Confirmed-tractable recipe for minister-style cascades: base has duplicate empty
decls shadowing real bodies + new virtuals in wrong order → remove dups, rename
the real slot-0x28 body to the TMinister base slot name (MinisterSlot0A) so it
overrides, order new virtuals by byte. Derived leaves: rename their slot override
to the base's real slot name + matching return type (`undefined`, not `void`).

Highest-leverage remaining (per-class, laborious — junk-named/wrong-sig overrides &
reordered new-virtuals):
- **City-minister family** (TCityInteriorMinister base + TSteel/TShipBuilder/TEven/
  TRailCityMinister) — TCityInteriorMinister has ~30 junk CityInteriorSlot1A..34
  names + reorder; big but cascades to 5.
- **Order family** (TCityOrderItem/TProductionOrder/TItemOrder → TCapacity/TExpansion/
  TFoodProcessing/TPowerPlant/TTraining/TPopGrowth/TUnit/TOrItem/TItemOrder) — slot
  0x3c is one body 0x4b5180 named Produce (TCityOrderItem) vs
  InitializeCityOrderItemWorkingBuffers (TProductionOrder); TProductionOrder:TObject
  not TCityOrderItem. TExpansion/TFoodProcessing are 1-slot (0x3c) each.
- **TWindow** (→ TDlgWindow/TGameWindow/dialogs): slot 0x40 DispatchUiCommandToHandler
  override sig mismatch + missing/extra TView slots 0x190-0x198 + phantom 0x1dc tail.
- **Cluster family** (~25: TCluster base + TToolBarCluster/TTradeCluster/… ) — TCluster
  overrides named Free/OwnerPanel/etc. instead of the TView ancestor slot name.
- **Great-power family** (TCountry base + TGreatPower/TMinor/TAutoGreatPower/THost…/TRemote…).
- **Minister data family** (TDefenseMinister + Napoleon/Bismarck/Pirate/… ) — reorder.
- **City-minister family** (TCityInteriorMinister/TSteelCityMinister/… ).
- **Zone family** (TZone scrambled order; TPortZone/TOcean/TOceanDialog mis-based — TOcean
  slot 0x1c points at a TPortZone body, so TOcean is really TPortZone-derived, not TObject).
- **Stream subclasses** (TFileStream/TCountingStream/THandleStream) — junk-named overrides
  + base streamSlot signature mismatches (e.g. streamSlotA8() vs char(char*)); base also
  missing tail slots 0xb8/0xbc/0xc0 (0x488ff0/0x488b10/0x488e00, unowned).
- TToggleButton/TBoycottButton: slot 0x1cc IsSelected modeled inconsistently w/ generated
  metadata — needs ghidra ground-truth on whether IsSelected is new vs override.

Quick scan for cheap wins: `awk '/`+"`"+`vftable. : orig/{if(n)print c,n;n=$1;c=0;next}/not annotated|no orig|-\(0x/{c++}END{print c,n}' /tmp/vt.txt | sort -n`
