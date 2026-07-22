#pragma once

#include "game/TTacticalBattle.h"
#include "game/mfc.h"

// Forward declarations for types referenced by generated signatures.
class TStream;
class TTacticalUnit;

// VTABLE: IMPERIALISM 0x0064ca68
class TArmyBattle : public TTacticalBattle {
public:
  DECLARE_DYNCREATE(TArmyBattle)
  virtual ~TArmyBattle() override; // slot 0x01 (scalar deleting destructor)
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
  virtual void DeployTacticalUnitToTile(TTacticalUnit* unit,
                                        TacticalTileIndex tileIndex) override; // slot 0x0c 0x5a51e0
  // slot 0x0d MoveTacticalUnitAndQueueEvent232AIfNoAdjacentReachableTarget inherited unchanged (0x5a1bd0)
  // slot 0x0e HasEnemyUnitOnTilesFlankingHexDirection inherited unchanged (0x5a1400)
  // slot 0x0f ExecuteTacticalActionAndQueueEventIfNoAdjacentValidTarget inherited unchanged (0x5a1ca0)
  // slot 0x10 EvaluateAndResolveTacticalActionAgainstTileOccupant inherited unchanged (0x5a1ee0)
  // slot 0x11 TransferTacticalUnitToOpposingSide inherited unchanged (0x5a2700)
  // Marks the battle decided (battleOutcomeCode44 = 1), asserts both sides, silences the
  // blink cue, resets the 'tool' toolbar's current-unit display, then delegates to
  // g_pMapContextActionManager->ApplyPostBattleStackOutcomeAndGrowUnitMeters with each
  // side's armyStack28 to relocate/reset the losing side and grow unit quality.
  virtual undefined FinalizeTacticalBattleOutcome(int sideWonFlag) override; // slot 0x12 0x5a5320
  // slot 0x13 MarkTacticalTileStateQueuedAndMaybeDispatchPacket inherited unchanged (0x5a3190)
  // slot 0x14 AdvanceOrResetTacticalTileStateRunAndMaybeDispatchPacket inherited unchanged (0x5a3210)
  // slot 0x15 ClearTacticalTileStateRunByStride inherited unchanged (0x5a3320)
  // slot 0x16 ComputeRallyStrengthAndQueueTacticalRallyCommand inherited unchanged (0x5a3810)
  // slot 0x17 ExecuteTacticalMineActionAndQueuePacket inherited unchanged (0x5a34d0)
  // slot 0x18 ExecuteTacticalDigActionAndConsumeUnitActionPoints inherited unchanged (0x5a3640)

  // Both original construction sites (TArmyMgr::CreateTacticalBattleViewAndInitialize-
  // BattleSetup 0x4a5b60 and the network receive path 0x54a1df) inline this ctor as just
  // the out-of-line base-ctor call plus the TArmyBattle vtable install -- no other body.
  // Defined in-class so the recompile inlines it the same way.
  TArmyBattle() : TTacticalBattle() {}

  // Allocates recordList20 (the deserialized/deployed unit list). Called out-of-line
  // right after construction at the TArmyMgr setup site; the network receive path
  // relies on ReadFrom populating the list instead. 0x0059f7f0.
  void AllocateRecordList();

  // Called by TArmyMgr::CreateTacticalBattleViewAndInitializeBattleSetup right after
  // construction (and by ReadFrom on the network receive path) with the two combatant
  // stacks, a composition class from TMapMgr::ClassifyCityGateTerrainComposition, the
  // battle-site fort level, and the cityScoreTable row of the site. 0x005a4790,
  // __thiscall, ret 0x14.
  void InitializeBattleSetupAndMaybeDispatchTurnEventED8(class TArmyStack* ourStack,
                                                         class TArmyStack* enemyStack,
                                                         int compositionClass, int fortLevel,
                                                         int battleSiteIndex);

  // Loads the battle-setup tab data (terrain/backdrop selection) for the composition
  // class + fort level. 0x005a4fc0, __thiscall, ret 8.
  void LoadBattleSetupTabDataByIndex(int compositionClass, int fortLevel);
};
