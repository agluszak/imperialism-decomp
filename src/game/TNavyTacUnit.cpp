#include "game/TNavyTacUnit.h"

#include "game/global_data_tables.h"
#include "game/TShip.h"

#include <stdlib.h>

// FUNCTION: IMPERIALISM 0x0059ed60
TShip* TNavyTacUnit::GetSourceTaskForce() {
  return sourceTaskForce34;
}

// SYNTHETIC: IMPERIALISM 0x0059ed80
// TNavyTacUnit::`scalar deleting destructor'
TNavyTacUnit::~TNavyTacUnit() {}
// SYNTHETIC: IMPERIALISM 0x005a6240
// TNavyTacUnit::CreateObject

// SYNTHETIC: IMPERIALISM 0x005a6270
// TNavyTacUnit::GetRuntimeClass

IMPLEMENT_DYNCREATE(TNavyTacUnit, TTacticalUnit)

TNavyTacUnit::TNavyTacUnit() {}

// FUNCTION: IMPERIALISM 0x005a6310
int TNavyTacUnit::GetBaseActionPoints() {
  return baseActionPoints3c;
}

// FUNCTION: IMPERIALISM 0x005a6330
int TNavyTacUnit::GetUnitRange() {
  return sourceTaskForce34->GetOrderNodeDescriptorWord0CByResourceType();
}

// FUNCTION: IMPERIALISM 0x005a6350
float TNavyTacUnit::GetBaseAttackPower() {
  return g_afTacticalNavyBaseAttackPowerByUnitType[unitTypeC];
}

// FUNCTION: IMPERIALISM 0x005a6370
float TNavyTacUnit::GetDamageScale() {
  return g_afTacticalNavyDamageScaleByUnitType[unitTypeC];
}

// FUNCTION: IMPERIALISM 0x005a63c0
void TNavyTacUnit::ApplyTacticalDamageAndDeathState(float damageAmount, int damageMode) {
  int hullDelta;
  int crewDelta;
  int actionPointDelta = 0;

  switch (damageMode) {
  case 0:
    hullDelta = static_cast<int>(damageAmount);
    crewDelta = static_cast<int>(damageAmount * g_dNavyDamageSplitRatioA_00669f10);
    break;
  case 1:
    hullDelta = static_cast<int>(damageAmount * g_dNavyDamageSplitRatioA_00669f10);
    crewDelta = static_cast<int>(damageAmount * g_dNavyDamageSplitRatioB_00669f18);
    break;
  case 2:
    hullDelta = static_cast<int>(damageAmount * g_dNavyDamageSplitRatioA_00669f10);
    crewDelta = 0;
    if (static_cast<float>(rand() % 10) < damageAmount) {
      actionPointDelta = 10;
    }
    break;
  default:
    // Unreached in practice (damageMode is always the 0-2 ship-panel toggle); the original
    // just reinterprets damageAmount's raw bits as both deltas rather than converting them.
    hullDelta = *reinterpret_cast<int*>(&damageAmount);
    crewDelta = *reinterpret_cast<int*>(&damageAmount);
    break;
  }

  strength4 -= hullDelta;
  crewStrength38 -= crewDelta;
  baseActionPoints3c -= actionPointDelta;
  if (strength4 <= 0 || crewStrength38 <= 0) {
    strength4 = 0;
    crewStrength38 = 0;
    state1c = 3;
  }
}
