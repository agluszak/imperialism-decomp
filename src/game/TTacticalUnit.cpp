#include "game/TTacticalUnit.h"

// FUNCTION: IMPERIALISM 0x005a5d40
int TTacticalUnit::GetBaseActionPoints() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005a5d60
undefined TTacticalUnit::OrphanTiny_ReturnZero_005a5d60() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005a5d80
undefined TTacticalUnit::OrphanLeaf_NoCall_Ins02_005a5d80() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005a5da0
undefined TTacticalUnit::OrphanLeaf_NoCall_Ins02_005a5da0() {
  return 0;
}

// SYNTHETIC: IMPERIALISM 0x005a5dc0
// TTacticalUnit::`scalar deleting destructor'
TTacticalUnit::~TTacticalUnit() {}
// SYNTHETIC: IMPERIALISM 0x005a5d10
// TTacticalUnit::CreateObject

// SYNTHETIC: IMPERIALISM 0x005a5e10
// TTacticalUnit::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTacticalUnit, TObject)

// FUNCTION: IMPERIALISM 0x005a5e70
void TTacticalUnit::ApplyTacticalDamage(int damageA, int damageB) {
  (void)damageB;
  strength4 -= damageA;
  if (strength4 <= 0) {
    strength4 = 0;
    state1c = 3;
  }
}

// FUNCTION: IMPERIALISM 0x005a5eb0
undefined TTacticalUnit::CreateTArmyTacUnitInstance() {
  return 0;
}
