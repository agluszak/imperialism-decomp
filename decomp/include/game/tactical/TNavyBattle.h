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
  virtual ~TNavyBattle() override {}
  virtual void CalculateMoveMap(TTacticalUnit* unit) override;
  virtual void DeployUnit(TTacticalUnit* unit, TacticalTileIndex tileIndex) override;
  virtual void MoveAndCycle(TTacticalUnit* unit, TacticalTileIndex targetTileIndex) override;
  virtual void FireAndCycle(TTacticalUnit* unit, TacticalTileIndex targetTileIndex) override;
  virtual void FireOn(TTacticalUnit* attackerUnit, TacticalTileIndex targetTileIndex) override;
  // Simply re-resolves the navy order manager's map-order chains; sideWonFlag is unused.
  virtual void EndBattle(unsigned char sideWonFlag) override;

  // NOOP: verified empty in original 0x005a5485
  TNavyBattle() {}

  void InitTacticalBattle(TTacticalPlayer* ourPlayer, TTacticalPlayer* enemyPlayer);
  void SetTargeting(NavyTargeting targeting);

  int moveCostRotationStart;
  int neighborMoveCostByDirection[6];
};
ASSERT_SIZE(TNavyBattle, 0x94);

void __stdcall ConvertHexTileIndexToRowAndDoubleColumn(TacticalTileIndex tileIndex,
                                                       unsigned int* outRow, int* outCol2X);
