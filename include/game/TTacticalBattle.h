#pragma once

#include "game/TObject.h"
#include "game/mfc.h"

class TList;

// TODO(manifest): describe TTacticalBattle and its role. Base edge (TObject) recovered from RTTI CRuntimeClass chain: TTacticalBattle -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x0066a088
class TTacticalBattle : public TObject {
public:
  // === BEGIN GENERATED DECLS (TTacticalBattle) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TTacticalBattle)
  virtual ~TTacticalBattle() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  virtual void Free() override; // slot 0x07 0x59fb50
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  virtual undefined
  ComputeTacticalReachableTileCostsByUnitCategory(int param_1);              // slot 0x0a 0x59ff20
  virtual undefined PropagateTileAccessibilityStrengthLevels(char* param_1); // slot 0x0b 0x5a02e0
  virtual undefined OrphanRetStub_0059f710();                                // slot 0x0c 0x59f710
  virtual undefined MoveTacticalUnitAndQueueEvent232AIfNoAdjacentReachableTarget(
      int param_1, undefined4 param_2); // slot 0x0d 0x5a1bd0
  virtual undefined
  WrapperFor_thunk_ComputeHexNeighborTileIndices_At005a1400(undefined4 param_1, int param_2,
                                                            char param_3); // slot 0x0e 0x5a1400
  virtual undefined
  ExecuteTacticalActionAndQueueEventIfNoAdjacentValidTarget(int param_1); // slot 0x0f 0x5a1ca0
  virtual undefined
  EvaluateAndResolveTacticalActionAgainstTileOccupant(int* param_1,
                                                      int param_2); // slot 0x10 0x5a1ee0
  virtual undefined OrphanCallChain_C4_I30_005a2700(int param_1);   // slot 0x11 0x5a2700
  virtual undefined CreateTTacticalBattleInstance();                // slot 0x12 0x59f730
  virtual undefined
  MarkTacticalTileStateQueuedAndMaybeDispatchPacket(int* param_1,
                                                    int param_2); // slot 0x13 0x5a3190
  virtual undefined
  AdvanceOrResetTacticalTileStateRunAndMaybeDispatchPacket(int param_1); // slot 0x14 0x5a3210
  virtual undefined ClearTacticalTileStateRunByStride(int param_1);      // slot 0x15 0x5a3320
  virtual undefined
  ComputeRallyStrengthAndQueueTacticalRallyCommand(int param_1); // slot 0x16 0x5a3810
  virtual undefined ExecuteTacticalMineActionAndQueuePacket(int param_1,
                                                            int param_2); // slot 0x17 0x5a34d0
  virtual undefined
  ExecuteTacticalDigActionAndConsumeUnitActionPoints(int* param_1,
                                                     undefined4 param_2); // slot 0x18 0x5a3640
  // === END GENERATED DECLS (TTacticalBattle) ===
  // TODO(manifest): add data members from the object slice (`just slice-discovery TTacticalBattle 0xCTOR`).

  // Zeroed by the real ctor (0x59f770); none of these 4 has further usage evidence yet.
  int field4;
  int field8;
  int field1c;
  // Falls within TTacticalBattle's own object-size slice (both this base and TArmyBattle
  // report 0x78, i.e. TArmyBattle adds no bytes of its own), zeroed here but only
  // observed being constructed (new TList()) from TArmyBattle::TArmyBattle's own body
  // (0x59f7f0, reached via a TArmyBattle-vtable-set-then-call chain, not from this base
  // ctor) -- declared here per the layout evidence, set by the derived ctor.
  TList* recordList20;
  int field24;
  int field34;
  int field74;

  TTacticalBattle();
};

