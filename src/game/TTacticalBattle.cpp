#include "game/TTacticalBattle.h"

#include "game/TList.h"

undefined TTacticalBattle::OrphanRetStub_0059f710() {
  return 0;
}

undefined TTacticalBattle::CreateTTacticalBattleInstance() {
  return 0;
}
// SYNTHETIC: IMPERIALISM 0x0059f6d0
// TTacticalBattle::CreateObject

// SYNTHETIC: IMPERIALISM 0x0059f750
// TTacticalBattle::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTacticalBattle, TObject)

// FUNCTION: IMPERIALISM 0x0059f770
TTacticalBattle::TTacticalBattle()
    : field4(0), field8(0), field1c(0), recordList20(nullptr), field24(0), field34(0), field74(0) {}

// SYNTHETIC: IMPERIALISM 0x0059f7a0
// TTacticalBattle::`scalar deleting destructor'
TTacticalBattle::~TTacticalBattle() {}

void TTacticalBattle::Free() {}

undefined TTacticalBattle::ComputeTacticalReachableTileCostsByUnitCategory(int param_1) {
  return 0;
}

undefined TTacticalBattle::PropagateTileAccessibilityStrengthLevels(char* param_1) {
  return 0;
}

undefined TTacticalBattle::WrapperFor_thunk_ComputeHexNeighborTileIndices_At005a1400(
    undefined4 param_1, int param_2, char param_3) {
  return 0;
}

undefined
TTacticalBattle::MoveTacticalUnitAndQueueEvent232AIfNoAdjacentReachableTarget(int param_1,
                                                                              undefined4 param_2) {
  return 0;
}

undefined TTacticalBattle::ExecuteTacticalActionAndQueueEventIfNoAdjacentValidTarget(int param_1) {
  return 0;
}

undefined TTacticalBattle::EvaluateAndResolveTacticalActionAgainstTileOccupant(int* param_1,
                                                                               int param_2) {
  return 0;
}

undefined TTacticalBattle::OrphanCallChain_C4_I30_005a2700(int param_1) {
  return 0;
}

undefined TTacticalBattle::MarkTacticalTileStateQueuedAndMaybeDispatchPacket(int* param_1,
                                                                             int param_2) {
  return 0;
}

undefined TTacticalBattle::AdvanceOrResetTacticalTileStateRunAndMaybeDispatchPacket(int param_1) {
  return 0;
}

undefined TTacticalBattle::ClearTacticalTileStateRunByStride(int param_1) {
  return 0;
}

undefined TTacticalBattle::ExecuteTacticalMineActionAndQueuePacket(int param_1, int param_2) {
  return 0;
}

undefined TTacticalBattle::ExecuteTacticalDigActionAndConsumeUnitActionPoints(int* param_1,
                                                                              undefined4 param_2) {
  return 0;
}

undefined TTacticalBattle::ComputeRallyStrengthAndQueueTacticalRallyCommand(int param_1) {
  return 0;
}
