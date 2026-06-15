---
name: vtable-easy-wins-session
description: 2026-06-15 vtable-matching pass — 8 classes driven to 100% (84→76 mismatches); patterns + what remains
metadata:
  type: project
---

2026-06-15 session driving `just vtable` matches up. Took "Vtables not matching" 84→76.

**Fixed (commits on main):**
- TStatusButton (HandleEvent override), CObject (SYNTHETIC scalar dtor @0x415f00),
  CPtrList (real GetRuntimeClass @0x623b3a + classCPtrList descriptor).
- TButton (GetRuntimeClass @0x48eaf0 + PTR_s_TButton_00649618 + SYNTHETIC scalar dtor @0x492de0),
  TTownMarker (GetRuntimeClass @0x5b6c40 replacing provisional virtual).
- TIndustryAmtBar / TRailAmtBar / TShipAmtBar: DoPostCreate→NoOpUiLifecycleHook(int) override
  (slot 0xdc), DrawAmt→RenderPrimarySurfaceOverlayPanelWithClipCache override (slot 0x1a8).
  NOTE: Industry/Rail DrawAmt // FUNCTION markers were at WRONG addresses (0x589dd0, 0x58a1c0);
  Ghidra ground truth is 0x589340 / 0x58a1b0 — corrected.

**Reusable patterns confirmed this session:**
- Slot-0 GetRuntimeClass mismatch (recomp = inherited base): add real `GetRuntimeClass() override`
  at the orig addr returning a `CRuntimeClass PTR_s_<Class>_<descaddr>` global (descriptors live in
  `src/game/global_data_tables.cpp`, no GLOBAL marker needed). Update symbols.csv name. Ghidra often
  mislabels these as `T<Other>::GetT<Other>ClassNamePointer`.
- Scalar dtor pairing: `// SYNTHETIC: <addr>` + `Class::\`scalar deleting destructor'` in symbols.csv;
  the orig addr is usually a `WrapperFor_FreeHeapBufferIfNotNull_At<addr>`. Needs polymorphic class.
- "Ported but non-virtual": method exists with descriptive name but no `override`; rename to the BASE
  virtual's exact name+signature and add `override` (e.g. AmtBar leaf overrides).
- After removing a long member line, clang-format re-aligns trailing comments — run the formatter.

**Remaining harder (need reconstruction, NOT quick wins):**
- Picture-button family (TAlwaysPictureButton/T2PictureButton/TClosePicture): slot 0x11c all share
  override @0x570900, slot 0x1c0 {T2Pic,TClosePic}@0x570870 vs TAlways@0x570a70 — implies a missing
  INTERMEDIATE base between TPictureButton and these leaves (TPictureButton itself is 100%). One func
  address shared across 3 vtable slots ⇒ must be defined once on a common base.
- Cluster family (TUberCluster/TAmtBarCluster/TTradeCluster/TProductionCluster/...): TUberCluster vtable
  extent is bloated (recomp emits vmethod_0115/ApplyMoveValue/... at 0x1ec as `no orig`); slot 0x3c
  override lives on TUberCluster. See [[cluster-vtable-ground-truth]].
- TArmyPlacard: slot 0x110 is a clean rename (RenderRightAlignedNumericOverlayWithShadow→ApplyRectSlot110
  override; internal call becomes TPictureResourceEntryBase::ApplyRectSlot110). slot 0x3c needs porting
  new func @0x58c140 (HandleEvent) which does a vtable call at slot 0x1cc — that slot is beyond modeled
  TControl/TView virtuals, so needs vtable-extent work first.
- TCluster: slot 0x00 GetRuntimeClass (easy) + slot 0x3c is an ILT thunk @0x4023ab (un-import case).
- ApplicationUiRootEmbeddedList/Controller slot 0: should resolve to CObject::GetRuntimeClass (0x606fba)
  not TBehavior's — an inheritance-modeling issue, not a simple override add.

Related: [[ui-vtable-hierarchy-ground-truth]] [[ghidra-names-provisional]] [[ctor-field-init-placement]]
