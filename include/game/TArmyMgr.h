#pragma once

#include "game/TObject.h"
#include "game/mfc.h"

// Forward declarations for types referenced by generated signatures.
class TStream;
class TSortedList;

// TODO(manifest): describe TArmyMgr and its role. Base edge (TObject) recovered from RTTI CRuntimeClass chain: TArmyMgr -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x0064c928
class TArmyMgr : public TObject {
public:
  // === BEGIN GENERATED DECLS (TArmyMgr) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TArmyMgr)
  virtual ~TArmyMgr(); // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  virtual void WriteTo(TStream* stream) override;  // slot 0x05 0x4a1dd0
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x4a1b80
  virtual void Free() override;                    // slot 0x07 0x4a1a00
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual undefined OrphanCallChain_C4_I26_004a1e40();                 // slot 0x0a 0x4a1e40
  virtual undefined ProcessTileUnitListsAndApplyRandomStatusUpdates(); // slot 0x0b 0x4a1f80
  virtual undefined OrphanCallChain_C12_I108_004a2390();               // slot 0x0c 0x4a2390
  virtual undefined IterateLinkedListCursorAndClearPerTileByte0F();    // slot 0x0d 0x4a2500
  virtual undefined TryCreateTacticalBattleViewForTileArmies();        // slot 0x0e 0x4a3200
  // unitQueue is the same head/cursor node-queue shape as
  // ResetAndRelocateUnitOrderQueue_004a37b0's param_1 (concrete class unrecovered, Hard
  // Rule 12); tileIndex indexes g_pGlobalMapState->cityScoreTable. Picks a random
  // adjacent region matching the queue's head unit's field_18 tag and relocates every
  // movable unit there (TUnit::SetOrderModeSlot34), or resets them if none qualifies.
  virtual undefined
  RedistributeUnitOrderQueueToRandomAdjacentRegion(void* unitQueue,
                                                   short tileIndex); // slot 0x0f 0x4a35e0
  // Ground truth doesn't touch `this` at all -- param_1 is a small {targetProvinceId
  // @+0x10, head node @+0x14, cursor node @+0x18} queue of {TUnit*, next} nodes; the
  // concrete owning class isn't recovered (only reached via vtable dispatch in Ghidra's
  // xrefs), so it stays void* rather than a guessed type (Hard Rule 12).
  virtual undefined ResetAndRelocateUnitOrderQueue_004a37b0(void* param_1); // slot 0x10 0x4a37b0
  virtual undefined UpdateDualLinkedEntryMetersAndBlinkState();             // slot 0x11 0x4a3830
  virtual undefined
  WrapperFor_IsNationSlotEligibleForEventProcessing_At004a3bc0(); // slot 0x12 0x4a3bc0
  // Ground truth (RET 0x8, 2 stack args) proves the previous 1-arg declaration was a
  // poison-pill arity mismatch. actionKind selects between the slot-0x14/0x15 dispatch
  // (1/4 -> SelectMovableUnitOnCurrentTileAndPlaySfx, 7 -> CommitCityActionGateCostIfAffordable)
  // before the shared tile-unit tail runs.
  virtual undefined DispatchTileActionByKind_004a3d90(int contextArg,
                                                      short actionKind); // slot 0x13 0x4a3d90
  // Ground truth (RET 0x4) proves the previous 0-arg declaration was a poison-pill arity
  // mismatch; contextArg is forwarded as TUnit::SetOrderModeSlot34's payload. Returns
  // whether a movable unit was found and commanded (BL in the ground truth, matching
  // TCivMgr's directly-analogous HandleCivilianTileSelectionOrReportClick/
  // HandleCivilianTileOrderAction shape) -- not a meaningless `undefined` stub value.
  virtual bool SelectMovableUnitOnCurrentTileAndPlaySfx(int contextArg); // slot 0x14 0x4a3e50
  // Ground truth (RET 0x4) proves the previous 0-arg declaration was a poison-pill arity
  // mismatch. Returns whether the tile's unit-move cost was affordable and committed
  // (AL in the ground truth) -- not a meaningless `undefined` stub value.
  virtual bool CommitCityActionGateCostIfAffordable(int contextArg); // slot 0x15 0x4a3f30
  virtual undefined OrphanCallChain_C1_I34_004a4260(int mode);       // slot 0x16 0x4a4260
  virtual undefined HandleMapClickByComputedCursorState();           // slot 0x17 0x4a4870
  virtual undefined HandleMapClickByCivilianCursorState();           // slot 0x18 0x4a4ad0
  // === END GENERATED DECLS (TArmyMgr) ===
  // TODO(manifest): add data members from the object slice (`just slice-discovery TArmyMgr 0xCTOR`).

  // Object size 0x3a8 confirmed by RTTI. Only +0x31c is confirmed so far (read from three
  // independent call sites: TArmyPlacard::HandleEvent, TArmyToolbar's equivalent, and
  // TWorldView::RenderMapContextOverlayWithScopedClipAndSurface) -- a pending map-order/
  // action index, -1 when none selected, otherwise used both as a tile index
  // (ActivateFirstActiveTacticalUnitByCategoryAtTile) and as an index into the terrain
  // descriptor table (g_pGlobalMapState-relative), so it is genuinely a shared "current
  // selection" slot rather than two coincidentally-aliased meanings.
  // NOTE: TObject's own vptr occupies the object's first 4 bytes (ASSERT_SIZE(TObject,
  // 0x4)), so every "+0xNN" comment below is an absolute this-relative offset and this
  // pad must be 4 bytes short of its target to land the next field correctly.
  unsigned char pad04[0x08];
  // +0x0c -- a TSortedList (GetCountSlot48/GetEntryByOrdinalSlot4C evidence from
  // ProcessTileUnitListsAndApplyRandomStatusUpdates's ground truth); freed at the top of
  // IterateLinkedListCursorAndClearPerTileByte0F via FreePayloadsSlot54.
  TSortedList* pendingUnitPool0c;
  // +0x10 -- set to 1 by OrphanCallChain_C4_I26_004a1e40's non-turn-3 branch right before
  // calling OrphanCallChain_C12_I108_004a2390; role not pinned down beyond that write site.
  int pendingRebuildFlag10;
  unsigned char pad18[0x1c - 0x14];
  // +0x1c -- per-region affinity/eligibility lookup indexed by adjacent region id, read
  // via raw offset arithmetic in ground truth (Helper_Uses_GenerateThreadLocalRandom15_
  // At004a35e0, 0x4a35e0: `*(short*)(&this->field_0x1c + regionId*2)`); true array bound
  // unconfirmed, so this models only the base element rather than asserting a size.
  short regionAffinityTable1c;
  unsigned char pad14[0x31c - 0x1e];
  short pendingMapActionIndex; // +0x31c
  unsigned char pad31e[0x3a8 - 0x31e];

  TArmyMgr();
};

// === BEGIN GENERATED (TArmyMgr) — refreshed by `just gen-class TArmyMgr`; do not hand-edit ===
// clang-format off
// vtable @ 0x0064c928 (25 slots), object size 0x3a8, base TObject
//   slot 0x00  byte 0x00  0x004a1850  override  GetRuntimeClass
//   slot 0x01  byte 0x04  0x004a18a0  scalar_dtor (scalar deleting destructor)
//   slot 0x02  byte 0x08  0x00485e90  inherited Serialize
//   slot 0x03  byte 0x0c  0x00412bf0  inherited AssertValid
//   slot 0x04  byte 0x10  0x00412c10  inherited Dump
//   slot 0x05  byte 0x14  0x004a1dd0  override  WriteTo
//   slot 0x06  byte 0x18  0x004a1b80  override  ReadFrom
//   slot 0x07  byte 0x1c  0x004a1a00  override  Free
//   slot 0x08  byte 0x20  0x004798d0  inherited ShallowClone
//   slot 0x09  byte 0x24  0x00415ce0  inherited ShallowFree
//   slot 0x0a  byte 0x28  0x004a1e40  override  OrphanCallChain_C4_I26_004a1e40
//   slot 0x0b  byte 0x2c  0x004a1f80  override  ProcessTileUnitListsAndApplyRandomStatusUpdates
//   slot 0x0c  byte 0x30  0x004a2390  override  OrphanCallChain_C12_I108_004a2390
//   slot 0x0d  byte 0x34  0x004a2500  override  IterateLinkedListCursorAndClearPerTileByte0F
//   slot 0x0e  byte 0x38  0x004a3200  override  TryCreateTacticalBattleViewForTileArmies
//   slot 0x0f  byte 0x3c  0x004a35e0  override  Helper_Uses_GenerateThreadLocalRandom15_At004a35e0
//   slot 0x10  byte 0x40  0x004a37b0  override  OrphanCallChain_C2_I40_004a37b0
//   slot 0x11  byte 0x44  0x004a3830  override  UpdateDualLinkedEntryMetersAndBlinkState
//   slot 0x12  byte 0x48  0x004a3bc0  override  WrapperFor_IsNationSlotEligibleForEventProcessing_At004a3bc0
//   slot 0x13  byte 0x4c  0x004a3d90  override  OrphanCallChain_C3_I52_004a3d90
//   slot 0x14  byte 0x50  0x004a3e50  override  SelectMovableUnitOnCurrentTileAndPlaySfx
//   slot 0x15  byte 0x54  0x004a3f30  override  CommitCityActionGateCostIfAffordable
//   slot 0x16  byte 0x58  0x004a4260  override  OrphanCallChain_C1_I34_004a4260
//   slot 0x17  byte 0x5c  0x004a4870  override  HandleMapClickByComputedCursorState
//   slot 0x18  byte 0x60  0x004a4ad0  override  HandleMapClickByCivilianCursorState
// object size 0x3a8 (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TArmyMgr) ===
