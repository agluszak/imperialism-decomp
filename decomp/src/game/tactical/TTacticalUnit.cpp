#include "game/tactical/TTacticalUnit.h"

#include "game/globals/global_types.h"
#include "game/globals/tactical_globals.h"
#include "game/globals/shared_globals.h"

// FUNCTION: IMPERIALISM 0x005a5d40
int TTacticalUnit::GetBaseActionPoints() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005a5d60
int TTacticalUnit::GetUnitRange() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005a5d80
float TTacticalUnit::GetBaseAttackPower() {
  return g_fTacticalRetreatQualityWeightDefault;
}

// FUNCTION: IMPERIALISM 0x005a5da0
float TTacticalUnit::GetDamageScale() {
  return g_fTacticalRetreatQualityWeightDefault;
}

IMPLEMENT_DYNCREATE(TTacticalUnit, TObject)

// FUNCTION: IMPERIALISM 0x005a5e30
void TTacticalUnit::ITacticalUnit() {
  tileIndex = -2;
  selectedFlag = false;
  state1c = 0;
  actionPoints = GetBaseActionPoints();
  aiStateCode = 0;
  attackTarget = NULL;
}

// FUNCTION: IMPERIALISM 0x005a5e70
void TTacticalUnit::ApplyDamage(int damageA, int damageB) {
  (void)damageB;
  strength -= damageA;
  if (strength <= 0) {
    strength = 0;
    state1c = 3;
  }
}

// FUNCTION: IMPERIALISM 0x005a5eb0
void TTacticalUnit::FlipUnitSideAffiliation() {
  side = (side == 0);
}
