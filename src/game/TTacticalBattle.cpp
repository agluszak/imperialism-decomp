#include "game/TTacticalBattle.h"

#include "game/TList.h"
#include "game/TTacticalPlayer.h"

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

// Body assignments (not a member-init list) reproduce the original store order
// +4, +8, +0x24, +0x1c, +0x34, +0x74, +0x20, which does not follow declaration order.
// FUNCTION: IMPERIALISM 0x0059f770
TTacticalBattle::TTacticalBattle() {
  field4 = 0;
  field8 = 0;
  field24 = 0;
  field1c = 0;
  field34 = 0;
  field74 = 0;
  recordList20 = 0;
}

// FUNCTION: IMPERIALISM 0x0059fc20
undefined TTacticalBattle::StartBattle() {
  return tacticalPlayer18->StartBattle();
}

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

// Turn-event 0x29/0x2a tactical receive family: promoted with verified signatures so
// the 0x545940 dispatcher gets correctly-typed calls; bodies not yet ported.

// FUNCTION: IMPERIALISM 0x005a1010
void TTacticalBattle::SetCurrentTacticalUnitSelection(void* unit, int flag) {
  // TODO: port body @ 0x5a1010.
  (void)unit;
  (void)flag;
}

// FUNCTION: IMPERIALISM 0x005a1910
void TTacticalBattle::MoveTacticalUnitBetweenTiles(void* unit, int arg20, int arg24, int flag) {
  // TODO: port body @ 0x5a1910.
  (void)unit;
  (void)arg20;
  (void)arg24;
  (void)flag;
}

// FUNCTION: IMPERIALISM 0x005a24a0
void TTacticalBattle::ApplyTacticalActionEffectsAndMaybeRemoveUnit(void* attackerUnit,
                                                                   void* targetUnit,
                                                                   int targetUnitField8, int arg24,
                                                                   int arg28, char arg2C,
                                                                   int flag) {
  // TODO: port body @ 0x5a24a0.
  (void)attackerUnit;
  (void)targetUnit;
  (void)targetUnitField8;
  (void)arg24;
  (void)arg28;
  (void)arg2C;
  (void)flag;
}

// FUNCTION: IMPERIALISM 0x005a35a0
void TTacticalBattle::HandleTacticalCommandTag_mine(int arg20, int arg24, int flag) {
  // TODO: port body @ 0x5a35a0.
  (void)arg20;
  (void)arg24;
  (void)flag;
}

// FUNCTION: IMPERIALISM 0x005a36d0
void TTacticalBattle::HandleTacticalCommandTag_digg(void* unit, int arg20, int flag) {
  // TODO: port body @ 0x5a36d0.
  (void)unit;
  (void)arg20;
  (void)flag;
}

// FUNCTION: IMPERIALISM 0x005a38e0
void TTacticalBattle::HandleTacticalCommandTag_raly(void* unit, int arg20, int arg24, int flag) {
  // TODO: port body @ 0x5a38e0.
  (void)unit;
  (void)arg20;
  (void)arg24;
  (void)flag;
}

// FUNCTION: IMPERIALISM 0x005a4370
void TTacticalBattle::HandleTacticalCommandTag_depl(void* unit, int arg20, int flag) {
  // TODO: port body @ 0x5a4370.
  (void)unit;
  (void)arg20;
  (void)flag;
}

// FUNCTION: IMPERIALISM 0x005a53e0
void* TTacticalBattle::SeekLinkedListCursorByNestedId(int nestedId) {
  // TODO: port body @ 0x5a53e0.
  (void)nestedId;
  return 0;
}
