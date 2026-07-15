#pragma once

#include "game/TTacticalBattle.h"
#include "game/mfc.h"

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
  virtual void DeployTacticalUnitToTile(TTacticalUnit* unit,
                                        int tileIndex) override; // slot 0x0c 0x5a55c0
  virtual void MoveTacticalUnitAndQueueEvent232AIfNoAdjacentReachableTarget(
      TTacticalUnit* unit, int targetTileIndex) override; // slot 0x0d 0x5a5c50
  // slot 0x0e HasEnemyUnitOnTilesFlankingHexDirection inherited unchanged (0x5a1400)
  virtual void ExecuteTacticalActionAndQueueEventIfNoAdjacentValidTarget(
      TTacticalUnit* unit, int targetTileIndex) override; // slot 0x0f 0x5a5bc0
  virtual void EvaluateAndResolveTacticalActionAgainstTileOccupant(
      TTacticalUnit* attackerUnit, int targetTileIndex) override; // slot 0x10 0x5a5730
  // slot 0x11 TransferTacticalUnitToOpposingSide inherited unchanged (0x5a2700)
  virtual undefined CreateTTacticalBattleInstance() override; // slot 0x12 0x5a5b70
  // slot 0x13 MarkTacticalTileStateQueuedAndMaybeDispatchPacket inherited unchanged (0x5a3190)
  // slot 0x14 AdvanceOrResetTacticalTileStateRunAndMaybeDispatchPacket inherited unchanged (0x5a3210)
  // slot 0x15 ClearTacticalTileStateRunByStride inherited unchanged (0x5a3320)
  // slot 0x16 ComputeRallyStrengthAndQueueTacticalRallyCommand inherited unchanged (0x5a3810)
  // slot 0x17 ExecuteTacticalMineActionAndQueuePacket inherited unchanged (0x5a34d0)
  // slot 0x18 ExecuteTacticalDigActionAndConsumeUnitActionPoints inherited unchanged (0x5a3640)
  // === END GENERATED DECLS (TNavyBattle) ===

  TNavyBattle();
};

// 0x5a59a0: tileIndex -> (row = tileIndex/0x1d, doubled column = (row&1) + (tileIndex%0x1d)*2)
// for the 29-wide tactical hex grid. Genuine __stdcall free function (pure arithmetic).
void __stdcall ConvertHexTileIndexToRowAndDoubleColumn(int tileIndex, unsigned int* outRow,
                                                       int* outCol2X);
