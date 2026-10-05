#include "game/tactical/TArmyTacUnit.h"

#include "game/military/TMilitaryUnit.h"
#include "game/globals/global_types.h"
#include "game/globals/tactical_globals.h"
#include "game/globals/shared_globals.h"

IMPLEMENT_DYNCREATE(TArmyTacUnit, TTacticalUnit)

// FUNCTION: IMPERIALISM 0x005a5f20
void TArmyTacUnit::IArmyTacUnit(TMilitaryUnit* source) {
  unitTypeC = source->orderType;
  tileIndex8 = -2;
  selectedFlag = 0;
  state1c = 0;
  actionPoints28 = GetBaseActionPoints();
  aiStateCode2c = 0;
  attackTarget = NULL;
  strength4 = source->strength34;
  morale34 = source->strength34;
  qualityLevel10 = static_cast<short>(source->experiencePercent / 100);
  ownerNationIndex14 = source->ownerNationSlot18;
  sapTargetTileIndex = -1;
  sourceUnit38 = source;
  bool deployedCategory0Flag;
  if (source->unitOrder == 2 && g_anUnitTypeCombatCategoryByType00669858[unitTypeC] == 0) {
    deployedCategory0Flag = true;
  } else {
    deployedCategory0Flag = false;
  }
  flag3c = deployedCategory0Flag;
}

// FUNCTION: IMPERIALISM 0x005a5fe0
void TArmyTacUnit::ComputeTacticalProjectionScoreVector() {
  // Quality is recomputed from the source unit's raw experience field (not the
  // cached qualityLevel10): (short)(experiencePercent / 100), same derivation as the ctor.
  float qualityFactor =
      static_cast<float>(g_dTacticalQualityFactorBase_00669ED0 -
                         static_cast<short>(sourceUnit38->experiencePercent / 100) *
                             g_dTacticalQualityFactorStep_00669EC8);
  // Retail still evaluates attribute 5, including its integer division, even
  // though tactical projection does not use the returned terrain adjustment.
  sourceUnit38->GetAttribute(5);
  float strengthTerm = strength4 * g_fTacticalStrengthProjectionScale_00669F0C;
  float scale = strengthTerm * qualityFactor;
  projectionScores[0] = sourceUnit38->GetAttribute(0) * scale * strengthTerm;
  projectionScores[1] = sourceUnit38->GetAttribute(1) * scale;
  projectionScores[2] = sourceUnit38->GetAttribute(2) * scale;
  projectionScores[3] = sourceUnit38->GetAttribute(3) * scale;
  projectionScores[4] = sourceUnit38->GetAttribute(4) * scale;
}

// FUNCTION: IMPERIALISM 0x005a6120
int TArmyTacUnit::GetBaseActionPoints() {
  return g_awUnitTypeBaseActionPointTable[unitTypeC];
}

// FUNCTION: IMPERIALISM 0x005a6140
int TArmyTacUnit::GetUnitRange() {
  int range = g_anUnitTypeTacticalRangeByType_006699E8[unitTypeC];
  if (side20 == 1 && g_anUnitTypeCombatCategoryByType00669858[unitTypeC] == 2) {
    ++range;
  }
  return range;
}

// FUNCTION: IMPERIALISM 0x005a6180
float TArmyTacUnit::GetBaseAttackPower() {
  return g_afTacticalBaseAttackPowerByUnitType[unitTypeC];
}

// FUNCTION: IMPERIALISM 0x005a61a0
float TArmyTacUnit::GetDamageScale() {
  return g_afTacticalDamageScaleByUnitType[unitTypeC];
}

// FUNCTION: IMPERIALISM 0x005a61c0
void TArmyTacUnit::ApplyDamage(int damageA, int damageB) {
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

// FUNCTION: IMPERIALISM 0x005a6210
int TArmyTacUnit::GetUID() const {
  if (this != 0 && sourceUnit38 != 0) {
    return sourceUnit38->persistentUnitId20;
  }
  return 0;
}
