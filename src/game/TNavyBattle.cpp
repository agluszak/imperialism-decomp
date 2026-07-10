#include "game/TNavyBattle.h"

// SYNTHETIC: IMPERIALISM 0x005a54d0
// TNavyBattle::`scalar deleting destructor'
TNavyBattle::~TNavyBattle() {}
// SYNTHETIC: IMPERIALISM 0x005a5480
// TNavyBattle::CreateObject

// SYNTHETIC: IMPERIALISM 0x005a5520
// TNavyBattle::GetRuntimeClass

IMPLEMENT_DYNCREATE(TNavyBattle, TTacticalBattle)

TNavyBattle::TNavyBattle() {}

// FUNCTION: IMPERIALISM 0x005a55c0
void TNavyBattle::DeployTacticalUnitToTile(TTacticalUnit* unit, int tileIndex) {
  // TODO: port body @ 0x5a55c0.
  (void)unit;
  (void)tileIndex;
}

// FUNCTION: IMPERIALISM 0x005a5730
void TNavyBattle::EvaluateAndResolveTacticalActionAgainstTileOccupant(TTacticalUnit* attackerUnit,
                                                                      int targetTileIndex) {
  (void)attackerUnit;
  (void)targetTileIndex;
}

// FUNCTION: IMPERIALISM 0x005a59f0
void TNavyBattle::ComputeTacticalReachableTileCostsByUnitCategory(TTacticalUnit* unit) {
  (void)unit;
}

// FUNCTION: IMPERIALISM 0x005a5b70
undefined TNavyBattle::CreateTTacticalBattleInstance() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005a5bc0
void TNavyBattle::ExecuteTacticalActionAndQueueEventIfNoAdjacentValidTarget(TTacticalUnit* unit,
                                                                            int targetTileIndex) {
  (void)unit;
  (void)targetTileIndex;
}

// FUNCTION: IMPERIALISM 0x005a5c50
void TNavyBattle::MoveTacticalUnitAndQueueEvent232AIfNoAdjacentReachableTarget(
    TTacticalUnit* unit, int targetTileIndex) {
  (void)unit;
  (void)targetTileIndex;
}
