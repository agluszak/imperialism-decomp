#include "game/TArmyBattle.h"

#include "game/TList.h"

// SYNTHETIC: IMPERIALISM 0x004a5c50
// TArmyBattle::`scalar deleting destructor'
TArmyBattle::~TArmyBattle() {}
// SYNTHETIC: IMPERIALISM 0x005a4710
// TArmyBattle::CreateObject

// SYNTHETIC: IMPERIALISM 0x005a4750
// TArmyBattle::GetRuntimeClass

IMPLEMENT_DYNCREATE(TArmyBattle, TTacticalBattle)

// FUNCTION: IMPERIALISM 0x0059f7f0
TArmyBattle::TArmyBattle() : TTacticalBattle() {
  recordList20 = new TList();
}

// FUNCTION: IMPERIALISM 0x005a4790
void TArmyBattle::InitializeBattleSetupAndMaybeDispatchTurnEventED8(TArmyStack* ourStack,
                                                                    TArmyStack* enemyStack,
                                                                    int compositionClass) {
  // TODO: port body @ 0x5a4790 (387 bytes; not yet ported). Declared for real so callers
  // (TArmyMgr::CreateTacticalBattleViewAndInitializeBattleSetup) get a correctly-typed
  // call site.
  (void)ourStack;
  (void)enemyStack;
  (void)compositionClass;
}

// FUNCTION: IMPERIALISM 0x005a4990
void TArmyBattle::ReadFrom(TStream* stream) {}

// FUNCTION: IMPERIALISM 0x005a4da0
void TArmyBattle::WriteTo(TStream* stream) {}

// FUNCTION: IMPERIALISM 0x005a51e0
undefined TArmyBattle::OrphanRetStub_0059f710() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005a5320
undefined TArmyBattle::CreateTTacticalBattleInstance() {
  return 0;
}
