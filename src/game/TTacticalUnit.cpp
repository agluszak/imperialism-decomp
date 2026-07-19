#include "game/TTacticalUnit.h"

// FUNCTION: IMPERIALISM 0x005a5d40
int TTacticalUnit::GetBaseActionPoints() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005a5d60
int TTacticalUnit::GetUnitRange() {
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

// FUNCTION: IMPERIALISM 0x005a5e30
void TTacticalUnit::ConstructTTacticalUnitBaseState() {
  tileIndex8 = -2;
  selectedFlag18 = 0;
  state1c = 0;
  actionPoints28 = GetBaseActionPoints();
  aiStateCode2c = 0;
  attackTarget30 = NULL;
}

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
void TTacticalUnit::FlipUnitSideAffiliation() {
  side20 = (side20 == 0);
}
