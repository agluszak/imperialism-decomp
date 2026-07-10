#include "game/TArmyTacUnit.h"

#include "game/global_data_tables.h"

// SYNTHETIC: IMPERIALISM 0x0059b390
// TArmyTacUnit::`scalar deleting destructor'
TArmyTacUnit::~TArmyTacUnit() {}
// SYNTHETIC: IMPERIALISM 0x005a5ed0
// TArmyTacUnit::CreateObject

// SYNTHETIC: IMPERIALISM 0x005a5f00
// TArmyTacUnit::GetRuntimeClass

IMPLEMENT_DYNCREATE(TArmyTacUnit, TTacticalUnit)

// FUNCTION: IMPERIALISM 0x005a6120
int TArmyTacUnit::GetBaseActionPoints() {
  return g_awUnitTypeBaseActionPointTable[unitTypeC];
}

// FUNCTION: IMPERIALISM 0x005a6140
undefined TArmyTacUnit::OrphanTiny_ReturnZero_005a5d60() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005a6180
undefined TArmyTacUnit::OrphanLeaf_NoCall_Ins02_005a5d80() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005a61a0
undefined TArmyTacUnit::OrphanLeaf_NoCall_Ins02_005a5da0() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005a61c0
void TArmyTacUnit::ApplyTacticalDamage(int damageA, int damageB) {
  morale34 -= damageB;
  if (morale34 <= 0) {
    morale34 = 0;
    state1c = 1;
  }
  strength4 -= damageA;
  if (strength4 <= 0) {
    strength4 = 0;
    state1c = 3;
  }
}
