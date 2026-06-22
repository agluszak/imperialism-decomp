#pragma once

#include "game/TObject.h"
#include "game/mfc.h"

// TODO(manifest): describe TTacticalBattle and its role. Base edge (TObject) recovered from RTTI CRuntimeClass chain: TTacticalBattle -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x0066a088
class TTacticalBattle : public TObject {
public:
// === BEGIN GENERATED DECLS (TTacticalBattle) — refreshed by recover-class; do not hand-edit ===
  virtual CRuntimeClass* GetRuntimeClass() const override; // slot 0x00 0x59f750
  virtual ~TTacticalBattle(); // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  virtual void Free() override; // slot 0x07 0x59fb50
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual undefined ComputeTacticalReachableTileCostsByUnitCategory(int param_1); // slot 0x0a 0x59ff20
  virtual undefined PropagateTileAccessibilityStrengthLevels(char * param_1); // slot 0x0b 0x5a02e0
  virtual undefined OrphanRetStub_0059f710(); // slot 0x0c 0x59f710
  virtual undefined MoveTacticalUnitAndQueueEvent232AIfNoAdjacentReachableTarget(int param_1, undefined4 param_2); // slot 0x0d 0x5a1bd0
  virtual undefined WrapperFor_thunk_ComputeHexNeighborTileIndices_At005a1400(undefined4 param_1, int param_2, char param_3); // slot 0x0e 0x5a1400
  virtual undefined ExecuteTacticalActionAndQueueEventIfNoAdjacentValidTarget(int param_1); // slot 0x0f 0x5a1ca0
  virtual undefined EvaluateAndResolveTacticalActionAgainstTileOccupant(int * param_1, int param_2); // slot 0x10 0x5a1ee0
  virtual undefined OrphanCallChain_C4_I30_005a2700(int param_1); // slot 0x11 0x5a2700
  virtual undefined CreateTTacticalBattleInstance(); // slot 0x12 0x59f730
  virtual undefined MarkTacticalTileStateQueuedAndMaybeDispatchPacket(int * param_1, int param_2); // slot 0x13 0x5a3190
  virtual undefined AdvanceOrResetTacticalTileStateRunAndMaybeDispatchPacket(int param_1); // slot 0x14 0x5a3210
  virtual undefined ClearTacticalTileStateRunByStride(int param_1); // slot 0x15 0x5a3320
  virtual undefined ComputeRallyStrengthAndQueueTacticalRallyCommand(int param_1); // slot 0x16 0x5a3810
  virtual undefined ExecuteTacticalMineActionAndQueuePacket(int param_1, int param_2); // slot 0x17 0x5a34d0
  virtual undefined ExecuteTacticalDigActionAndConsumeUnitActionPoints(int * param_1, undefined4 param_2); // slot 0x18 0x5a3640
// === END GENERATED DECLS (TTacticalBattle) ===
  // TODO(manifest): add data members from the object slice (`just slice-discovery TTacticalBattle 0xCTOR`).

  TTacticalBattle();
};

// === BEGIN GENERATED (TTacticalBattle) — refreshed by `just gen-class TTacticalBattle`; do not hand-edit ===
// clang-format off
// vtable @ 0x0066a088 (25 slots), object size 0x78, base TObject
//   slot 0x00  byte 0x00  0x0059f750  override  GetRuntimeClass
//   slot 0x01  byte 0x04  0x0059f7a0  scalar_dtor (scalar deleting destructor)
//   slot 0x02  byte 0x08  0x00485e90  inherited Serialize
//   slot 0x03  byte 0x0c  0x00412bf0  inherited AssertValid
//   slot 0x04  byte 0x10  0x00412c10  inherited Dump
//   slot 0x05  byte 0x14  0x00485f70  inherited WriteTo
//   slot 0x06  byte 0x18  0x00485f90  inherited ReadFrom
//   slot 0x07  byte 0x1c  0x0059fb50  override  Free
//   slot 0x08  byte 0x20  0x004798d0  inherited ShallowClone
//   slot 0x09  byte 0x24  0x00415ce0  inherited ShallowFree
//   slot 0x0a  byte 0x28  0x0059ff20  override  ComputeTacticalReachableTileCostsByUnitCategory
//   slot 0x0b  byte 0x2c  0x005a02e0  override  PropagateTileAccessibilityStrengthLevels
//   slot 0x0c  byte 0x30  0x0059f710  override  OrphanRetStub_0059f710
//   slot 0x0d  byte 0x34  0x005a1bd0  override  MoveTacticalUnitAndQueueEvent232AIfNoAdjacentReachableTarget
//   slot 0x0e  byte 0x38  0x005a1400  override  WrapperFor_thunk_ComputeHexNeighborTileIndices_At005a1400
//   slot 0x0f  byte 0x3c  0x005a1ca0  override  ExecuteTacticalActionAndQueueEventIfNoAdjacentValidTarget
//   slot 0x10  byte 0x40  0x005a1ee0  override  EvaluateAndResolveTacticalActionAgainstTileOccupant
//   slot 0x11  byte 0x44  0x005a2700  override  OrphanCallChain_C4_I30_005a2700
//   slot 0x12  byte 0x48  0x0059f730  override  CreateTTacticalBattleInstance
//   slot 0x13  byte 0x4c  0x005a3190  override  MarkTacticalTileStateQueuedAndMaybeDispatchPacket
//   slot 0x14  byte 0x50  0x005a3210  override  AdvanceOrResetTacticalTileStateRunAndMaybeDispatchPacket
//   slot 0x15  byte 0x54  0x005a3320  override  ClearTacticalTileStateRunByStride
//   slot 0x16  byte 0x58  0x005a3810  override  ComputeRallyStrengthAndQueueTacticalRallyCommand
//   slot 0x17  byte 0x5c  0x005a34d0  override  ExecuteTacticalMineActionAndQueuePacket
//   slot 0x18  byte 0x60  0x005a3640  override  ExecuteTacticalDigActionAndConsumeUnitActionPoints
// object size 0x78 (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TTacticalBattle) ===
