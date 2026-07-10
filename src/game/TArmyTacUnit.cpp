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
  field2c = 0;
  field30 = 0;
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

// FUNCTION: IMPERIALISM 0x005a6120
int TArmyTacUnit::GetBaseActionPoints() {
  return g_awUnitTypeBaseActionPointTable[unitTypeC];
}

// FUNCTION: IMPERIALISM 0x005a6140
int TArmyTacUnit::GetUnitRange() {
  // TODO: port body @ 0x5a6140 (0x6699e8 int table by unitTypeC, adjusted by side20).
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
