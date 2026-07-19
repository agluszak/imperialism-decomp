#include "game/TArmyTacUnit.h"

#include "game/TMilitaryUnit.h"
#include "game/global_data_tables.h"

// SYNTHETIC: IMPERIALISM 0x0059b390
// TArmyTacUnit::`scalar deleting destructor'
TArmyTacUnit::~TArmyTacUnit() {}
// SYNTHETIC: IMPERIALISM 0x005a5ed0
// TArmyTacUnit::CreateObject

// SYNTHETIC: IMPERIALISM 0x005a5f00
// TArmyTacUnit::GetRuntimeClass

IMPLEMENT_DYNCREATE(TArmyTacUnit, TTacticalUnit)

// FUNCTION: IMPERIALISM 0x005a5f20
void TArmyTacUnit::ConstructTArmyTacUnitBaseState(TMilitaryUnit* source) {
  unitTypeC = source->orderType;
  tileIndex8 = -2;
  selectedFlag18 = 0;
  state1c = 0;
  actionPoints28 = GetBaseActionPoints();
  aiStateCode2c = 0;
  attackTarget30 = NULL;
  strength4 = source->field_34;
  morale34 = source->field_34;
  qualityLevel10 = static_cast<short>(source->field_38 / 100);
  ownerNationIndex14 = source->field_18;
  sapTargetTileIndex40 = -1;
  sourceUnit38 = source;
  unsigned char deployedCategory0Flag;
  if (source->field_8 == 2 && g_anUnitTypeCombatCategoryByType00669858[unitTypeC] == 0) {
    deployedCategory0Flag = 1;
  } else {
    deployedCategory0Flag = 0;
  }
  flag3c = deployedCategory0Flag;
}

// FUNCTION: IMPERIALISM 0x005a5fe0
void TArmyTacUnit::ComputeTacticalProjectionScoreVector() {
  // Quality is recomputed from the source unit's raw experience field (not the
  // cached qualityLevel10): (short)(field_38 / 100), same derivation as the ctor.
  float qualityFactor = static_cast<float>(g_dTacticalQualityFactorBase_00669ED0 -
                                           static_cast<short>(sourceUnit38->field_38 / 100) *
                                               g_dTacticalQualityFactorStep_00669EC8);
  sourceUnit38->GetUnitTypeStatPercent(5);
  float unitFactor = 1.0f;
  float strengthTerm = strength4 * g_fTacticalStrengthProjectionScale_00669F0C;
  float scale = strengthTerm * qualityFactor;
  field44 = sourceUnit38->GetUnitTypeStatPercent(0) * scale * strengthTerm * unitFactor;
  field48 = sourceUnit38->GetUnitTypeStatPercent(1) * scale * unitFactor;
  field4c = sourceUnit38->GetUnitTypeStatPercent(2) * scale;
  field50 = sourceUnit38->GetUnitTypeStatPercent(3) * scale;
  field54 = sourceUnit38->GetUnitTypeStatPercent(4) * scale * unitFactor;
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
