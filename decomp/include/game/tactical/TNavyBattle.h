#pragma once

#include "compat.h"

#include "game/navy_tactical_types.h"
#include "game/tactical/TTacticalBattle.h"
#include "game/mfc.h"

class TTacticalUnit;

// VTABLE: IMPERIALISM 0x0066a140
class TNavyBattle : public TTacticalBattle {
public:
  DECLARE_DYNCREATE(TNavyBattle)
  // FUNCTION: IMPERIALISM 0x005a5500
  virtual ~TNavyBattle() override {} // slot 0x01 (scalar deleting destructor)
  virtual void CalculateMoveMap(
      TTacticalUnit* unit) override; // slot 0x0a 0x5a59f0
  virtual void DeployUnit(TTacticalUnit* unit,
                                        TacticalTileIndex tileIndex) override; // slot 0x0c 0x5a55c0
  virtual void MoveTacticalUnitAndQueueEvent232AIfNoAdjacentReachableTarget(
      TTacticalUnit* unit, TacticalTileIndex targetTileIndex) override; // slot 0x0d 0x5a5c50
  virtual void ExecuteTacticalActionAndQueueEventIfNoAdjacentValidTarget(
      TTacticalUnit* unit, TacticalTileIndex targetTileIndex) override; // slot 0x0f 0x5a5bc0
  virtual void EvaluateAndResolveTacticalActionAgainstTileOccupant(
      TTacticalUnit* attackerUnit,
      TacticalTileIndex targetTileIndex) override; // slot 0x10 0x5a5730
  // Simply re-resolves the navy order manager's map-order chains; sideWonFlag is unused.
  virtual void EndBattle(unsigned char sideWonFlag) override; // slot 0x12 0x5a5b70, Mac oracle

  // NOOP: verified empty in original 0x005a5485 (no standalone TNavyBattle::TNavyBattle body exists: construction is fully inlined into CreateObject 0x005a5480; that address is its operator-new call site)
  TNavyBattle() {}

  void InitTacticalBattle(TTacticalPlayer* ourPlayer,
                          TTacticalPlayer* enemyPlayer); // 0x5a5540, Mac oracle
  void SetTargeting(NavyTargeting targeting);            // 0x5a5b90

  int moveCostRotationStart;
  int neighborMoveCostByDirection[6];
};
ASSERT_SIZE(TNavyBattle, 0x94);

void __stdcall ConvertHexTileIndexToRowAndDoubleColumn(TacticalTileIndex tileIndex,
                                                       unsigned int* outRow, int* outCol2X);
