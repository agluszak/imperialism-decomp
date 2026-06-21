---
name: vtable-campaign-state
description: Vtable-not-matching reduction campaign — progress, method, and remaining targets
metadata:
  type: project
---

Driving `just vtable` "Vtables not matching" DOWN. Started 156 (2026-06-21), at **128**.
Method: source-only (edit header/cpp → `just build` → `just vtable`), ignore manifests
& generated metadata, don't chase function similarity, commit every few fixes, skip gates.

`override` is `#define override` empty (compat.h) → MSVC500 matches overrides by
name+signature; the 5 recurring defects + the fix recipes are in
`.claude/skills/decomp-loop/heuristics.md` §12b. See [[ghidra-names-provisional]].

Done so far (all committed): MFC list audit L1-L7; TPtrList base slots 0x64-0x78
(TArmyStackList/TTaskList); TSortedPtrList dup-dtor symbol; TBehavior dup virtuals;
TCommand→TObject; TStream→TObject; TAnimation phantom de-virtualize; TStaticText
5 missing slots (TRadioText/TSelectoText); TMinisterView + 3 view classes slot-0x48
signature (CPoint*,int,int,int).

Highest-leverage remaining (per-class, laborious — junk-named/wrong-sig overrides &
reordered new-virtuals):
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
