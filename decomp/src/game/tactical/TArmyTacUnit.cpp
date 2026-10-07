#include "game/tactical/TArmyTacUnit.h"

#include "game/military/TMilitaryUnit.h"
#include "game/globals/global_types.h"
#include "game/globals/tactical_globals.h"
#include "game/globals/shared_globals.h"

IMPLEMENT_DYNCREATE(TArmyTacUnit, TTacticalUnit)

// FUNCTION: IMPERIALISM 0x005a5f20
void TArmyTacUnit::IArmyTacUnit(TMilitaryUnit* source) {
  unitType = source->orderType;
  tileIndex = -2;
  selectedFlag = false;
  state1c = 0;
  actionPoints = GetBaseActionPoints();
  aiStateCode = 0;
  attackTarget = NULL;
  strength = source->strength;
  morale = source->strength;
  qualityLevel = static_cast<short>(source->experiencePercent / 100);
  ownerNationIndex = source->ownerNationSlot;
  sapTargetTileIndex = -1;
  sourceUnit = source;
  bool deployedCategory0Flag;
  if (source->unitOrder == 2 && g_anUnitTypeCombatCategoryByType[unitType] == 0) {
    deployedCategory0Flag = true;
  } else {
    deployedCategory0Flag = false;
  }
  flag3c = deployedCategory0Flag;
}

// FUNCTION: IMPERIALISM 0x005a5fe0
void TArmyTacUnit::ComputeTacticalProjectionScoreVector() {
  float qualityFactor = static_cast<float>(g_dTacticalQualityFactorBase -
                                           static_cast<short>(sourceUnit->experiencePercent / 100) *
                                               g_dTacticalQualityFactorStep);
  sourceUnit->GetAttribute(5);
  float strengthTerm = strength * g_fTacticalStrengthProjectionScale;
  float scale = strengthTerm * qualityFactor;
  projectionScores[0] = sourceUnit->GetAttribute(0) * scale * strengthTerm;
  projectionScores[1] = sourceUnit->GetAttribute(1) * scale;
  projectionScores[2] = sourceUnit->GetAttribute(2) * scale;
  projectionScores[3] = sourceUnit->GetAttribute(3) * scale;
  projectionScores[4] = sourceUnit->GetAttribute(4) * scale;
}

// FUNCTION: IMPERIALISM 0x005a6120
int TArmyTacUnit::GetBaseActionPoints() {
  return g_awUnitTypeBaseActionPointTable[unitType];
}

// FUNCTION: IMPERIALISM 0x005a6140
int TArmyTacUnit::GetUnitRange() {
  int range = g_anUnitTypeTacticalRangeByType[unitType];
  if (side == 1 && g_anUnitTypeCombatCategoryByType[unitType] == 2) {
    ++range;
  }
  return range;
}

// FUNCTION: IMPERIALISM 0x005a6180
float TArmyTacUnit::GetBaseAttackPower() {
  return g_afTacticalBaseAttackPowerByUnitType[unitType];
}

// FUNCTION: IMPERIALISM 0x005a61a0
float TArmyTacUnit::GetDamageScale() {
  return g_afTacticalDamageScaleByUnitType[unitType];
}

// FUNCTION: IMPERIALISM 0x005a61c0
void TArmyTacUnit::ApplyDamage(int damageA, int damageB) {
  morale -= damageB;
  if (morale <= 0) {
    morale = 0;
    state1c = 1;
  }
  strength -= damageA;
  if (strength <= 0) {
    strength = 0;
    state1c = 3;
  }
}

// FUNCTION: IMPERIALISM 0x005a6210
int TArmyTacUnit::GetUID() const {
  if (this != 0 && sourceUnit != 0) {
    return sourceUnit->persistentUnitId;
  }
  return 0;
}
