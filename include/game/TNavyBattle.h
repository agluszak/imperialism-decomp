#pragma once

#include "game/TTacticalBattle.h"
#include "game/mfc.h"

// TODO(manifest): describe TNavyBattle and its role. Base edge (TTacticalBattle) recovered from RTTI CRuntimeClass chain: TNavyBattle -> TTacticalBattle -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x0066a140
class TNavyBattle : public TTacticalBattle {
public:
// === BEGIN GENERATED DECLS (TNavyBattle) — refreshed by recover-class; do not hand-edit ===
  virtual CRuntimeClass* GetRuntimeClass() const override; // slot 0x00 0x5a5520
  virtual ~TNavyBattle(); // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  // slot 0x07 Free inherited unchanged (0x59fb50)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual undefined ComputeTacticalReachableTileCostsByUnitCategory() override; // slot 0x0a 0x5a59f0
  // slot 0x0b PropagateTileAccessibilityStrengthLevels inherited unchanged (0x5a02e0)
  virtual undefined OrphanRetStub_0059f710() override; // slot 0x0c 0x5a55c0
  virtual undefined MoveTacticalUnitAndQueueEvent232AIfNoAdjacentReachableTarget() override; // slot 0x0d 0x5a5c50
  // slot 0x0e WrapperFor_thunk_ComputeHexNeighborTileIndices_At005a1400 inherited unchanged (0x5a1400)
  virtual undefined ExecuteTacticalActionAndQueueEventIfNoAdjacentValidTarget() override; // slot 0x0f 0x5a5bc0
  virtual undefined EvaluateAndResolveTacticalActionAgainstTileOccupant() override; // slot 0x10 0x5a5730
  // slot 0x11 OrphanCallChain_C4_I30_005a2700 inherited unchanged (0x5a2700)
  virtual undefined CreateTTacticalBattleInstance() override; // slot 0x12 0x5a5b70
  // slot 0x13 MarkTacticalTileStateQueuedAndMaybeDispatchPacket inherited unchanged (0x5a3190)
  // slot 0x14 AdvanceOrResetTacticalTileStateRunAndMaybeDispatchPacket inherited unchanged (0x5a3210)
  // slot 0x15 ClearTacticalTileStateRunByStride inherited unchanged (0x5a3320)
  // slot 0x16 ComputeRallyStrengthAndQueueTacticalRallyCommand inherited unchanged (0x5a3810)
  // slot 0x17 ExecuteTacticalMineActionAndQueuePacket inherited unchanged (0x5a34d0)
  // slot 0x18 ExecuteTacticalDigActionAndConsumeUnitActionPoints inherited unchanged (0x5a3640)
// === END GENERATED DECLS (TNavyBattle) ===
  // TODO(manifest): add data members from the object slice (`just slice-discovery TNavyBattle 0xCTOR`).

  TNavyBattle();
};

// === BEGIN GENERATED (TNavyBattle) — refreshed by `just gen-class TNavyBattle`; do not hand-edit ===
// clang-format off
// vtable @ 0x0066a140 (25 slots), object size 0x94, base TTacticalBattle
//   slot 0x00  byte 0x00  0x005a5520  override  GetTTacticalBattleClassNamePointer
//   slot 0x01  byte 0x04  0x005a54d0  override  WrapperFor_FreeHeapBufferIfNotNull_At005a54d0
//   slot 0x02  byte 0x08  0x00485e90  inherited Serialize
//   slot 0x03  byte 0x0c  0x00412bf0  inherited AssertValid
//   slot 0x04  byte 0x10  0x00412c10  inherited Dump
//   slot 0x05  byte 0x14  0x00485f70  inherited WriteTo
//   slot 0x06  byte 0x18  0x00485f90  inherited ReadFrom
//   slot 0x07  byte 0x1c  0x0059fb50  inherited WrapperFor_FreeHeapBufferIfNotNull_At0059fb50
//   slot 0x08  byte 0x20  0x004798d0  inherited ShallowClone
//   slot 0x09  byte 0x24  0x00415ce0  inherited ShallowFree
//   slot 0x0a  byte 0x28  0x005a59f0  override  ComputeTacticalReachableTileCostsByUnitCategory
//   slot 0x0b  byte 0x2c  0x005a02e0  inherited PropagateTileAccessibilityStrengthLevels
//   slot 0x0c  byte 0x30  0x005a55c0  override  OrphanRetStub_0059f710
//   slot 0x0d  byte 0x34  0x005a5c50  override  MoveTacticalUnitAndQueueEvent232AIfNoAdjacentReachableTarget
//   slot 0x0e  byte 0x38  0x005a1400  inherited WrapperFor_thunk_ComputeHexNeighborTileIndices_At005a1400
//   slot 0x0f  byte 0x3c  0x005a5bc0  override  ExecuteTacticalActionAndQueueEventIfNoAdjacentValidTarget
//   slot 0x10  byte 0x40  0x005a5730  override  EvaluateAndResolveTacticalActionAgainstTileOccupant
//   slot 0x11  byte 0x44  0x005a2700  inherited OrphanCallChain_C4_I30_005a2700
//   slot 0x12  byte 0x48  0x005a5b70  override  CreateTTacticalBattleInstance
//   slot 0x13  byte 0x4c  0x005a3190  inherited MarkTacticalTileStateQueuedAndMaybeDispatchPacket
//   slot 0x14  byte 0x50  0x005a3210  inherited AdvanceOrResetTacticalTileStateRunAndMaybeDispatchPacket
//   slot 0x15  byte 0x54  0x005a3320  inherited ClearTacticalTileStateRunByStride
//   slot 0x16  byte 0x58  0x005a3810  inherited ComputeRallyStrengthAndQueueTacticalRallyCommand
//   slot 0x17  byte 0x5c  0x005a34d0  inherited ExecuteTacticalMineActionAndQueuePacket
//   slot 0x18  byte 0x60  0x005a3640  inherited ExecuteTacticalDigActionAndConsumeUnitActionPoints
// object size 0x94 (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TNavyBattle) ===
