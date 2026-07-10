#pragma once

#include "game/TTacticalBattle.h"
#include "game/mfc.h"

// TODO(manifest): describe TNavyBattle and its role. Base edge (TTacticalBattle) recovered from RTTI CRuntimeClass chain: TNavyBattle -> TTacticalBattle -> TObject -> CObject.
class TTacticalUnit;

// VTABLE: IMPERIALISM 0x0066a140
class TNavyBattle : public TTacticalBattle {
public:
  // === BEGIN GENERATED DECLS (TNavyBattle) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TNavyBattle)
  virtual ~TNavyBattle() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  // slot 0x07 Free inherited unchanged (0x59fb50)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual void ComputeTacticalReachableTileCostsByUnitCategory(
      TTacticalUnit* unit) override; // slot 0x0a 0x5a59f0
  // slot 0x0b PropagateTileAccessibilityStrengthLevels inherited unchanged (0x5a02e0)
  virtual undefined OrphanRetStub_0059f710() override; // slot 0x0c 0x5a55c0
  virtual undefined MoveTacticalUnitAndQueueEvent232AIfNoAdjacentReachableTarget(
      int param_1, undefined4 param_2) override; // slot 0x0d 0x5a5c50
  // slot 0x0e WrapperFor_thunk_ComputeHexNeighborTileIndices_At005a1400 inherited unchanged (0x5a1400)
  virtual undefined ExecuteTacticalActionAndQueueEventIfNoAdjacentValidTarget(
      int param_1) override; // slot 0x0f 0x5a5bc0
  virtual undefined
  EvaluateAndResolveTacticalActionAgainstTileOccupant(int* param_1,
                                                      int param_2) override; // slot 0x10 0x5a5730
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
