#pragma once

#include "game/TTacticalBattle.h"
#include "game/mfc.h"

// Forward declarations for types referenced by generated signatures.
class TStream;

// TODO(manifest): describe TArmyBattle and its role. Base edge (TTacticalBattle) recovered from RTTI CRuntimeClass chain: TArmyBattle -> TTacticalBattle -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x0064ca68
class TArmyBattle : public TTacticalBattle {
public:
  // === BEGIN GENERATED DECLS (TArmyBattle) — refreshed by recover-class; do not hand-edit ===
  DECLARE_DYNCREATE(TArmyBattle)
  virtual ~TArmyBattle(); // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  virtual void WriteTo(TStream* stream) override;  // slot 0x05 0x5a4da0
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x5a4990
  // slot 0x07 Free inherited unchanged (0x59fb50)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  // slot 0x0a ComputeTacticalReachableTileCostsByUnitCategory inherited unchanged (0x59ff20)
  // slot 0x0b PropagateTileAccessibilityStrengthLevels inherited unchanged (0x5a02e0)
  virtual undefined OrphanRetStub_0059f710() override; // slot 0x0c 0x5a51e0
  // slot 0x0d MoveTacticalUnitAndQueueEvent232AIfNoAdjacentReachableTarget inherited unchanged (0x5a1bd0)
  // slot 0x0e WrapperFor_thunk_ComputeHexNeighborTileIndices_At005a1400 inherited unchanged (0x5a1400)
  // slot 0x0f ExecuteTacticalActionAndQueueEventIfNoAdjacentValidTarget inherited unchanged (0x5a1ca0)
  // slot 0x10 EvaluateAndResolveTacticalActionAgainstTileOccupant inherited unchanged (0x5a1ee0)
  // slot 0x11 OrphanCallChain_C4_I30_005a2700 inherited unchanged (0x5a2700)
  virtual undefined CreateTTacticalBattleInstance() override; // slot 0x12 0x5a5320
  // slot 0x13 MarkTacticalTileStateQueuedAndMaybeDispatchPacket inherited unchanged (0x5a3190)
  // slot 0x14 AdvanceOrResetTacticalTileStateRunAndMaybeDispatchPacket inherited unchanged (0x5a3210)
  // slot 0x15 ClearTacticalTileStateRunByStride inherited unchanged (0x5a3320)
  // slot 0x16 ComputeRallyStrengthAndQueueTacticalRallyCommand inherited unchanged (0x5a3810)
  // slot 0x17 ExecuteTacticalMineActionAndQueuePacket inherited unchanged (0x5a34d0)
  // slot 0x18 ExecuteTacticalDigActionAndConsumeUnitActionPoints inherited unchanged (0x5a3640)
  // === END GENERATED DECLS (TArmyBattle) ===
  // TODO(manifest): add data members from the object slice (`just slice-discovery TArmyBattle 0xCTOR`).

  TArmyBattle();

  // Called by TArmyMgr::CreateTacticalBattleViewAndInitializeBattleSetup right after
  // construction, with the two combatant stacks and a composition class from
  // TMapMgr::ClassifyCityGateTerrainComposition. 0x005a4790, __thiscall, 387 bytes.
  // TODO: port body -- out of scope for that callsite, which only needs a real,
  // correctly-typed call.
  void InitializeBattleSetupAndMaybeDispatchTurnEventED8(class TArmyStack* ourStack,
                                                         class TArmyStack* enemyStack,
                                                         int compositionClass);
};

