#include "game/tactical/TNavyTacUnit.h"

#include <string.h>

#include "game/globals/global_types.h"
#include "game/globals/tactical_globals.h"
#include "game/globals/navy_globals.h"
#include "game/globals/shared_globals.h"
#include "game/navy/TShip.h"

#include <stdlib.h>

// FUNCTION: IMPERIALISM 0x0059ed60
TShip* TNavyTacUnit::GetSourceShip() {
  return sourceShip34;
}

// SYNTHETIC: IMPERIALISM 0x0059ed80
// TNavyTacUnit::`scalar deleting destructor'

// SYNTHETIC: IMPERIALISM 0x0059edb0
// TNavyTacUnit::~TNavyTacUnit
TNavyTacUnit::~TNavyTacUnit() {}
// SYNTHETIC: IMPERIALISM 0x005a6240
// TNavyTacUnit::CreateObject

// SYNTHETIC: IMPERIALISM 0x005a6270
// TNavyTacUnit::GetRuntimeClass

IMPLEMENT_DYNCREATE(TNavyTacUnit, TTacticalUnit)

// FUNCTION: IMPERIALISM 0x005a6290
void TNavyTacUnit::InitializeFromSourceShip(TShip* sourceShip) {
  tileIndex8 = -2;
  unitTypeC = g_anTacticalNavyUnitTypeByShipType_00669D80[sourceShip->type];
  selectedFlag18 = 0;
  state1c = 0;
  actionPoints28 = GetBaseActionPoints();
  aiStateCode2c = 0;
  attackTarget30 = 0;
  strength4 = sourceShip->strength;
  crewStrength38 = sourceShip->strength;
  int speed = sourceShip->GetSpeed();
  sourceShip34 = sourceShip;
  baseActionPoints3c = speed * 10;
}

// FUNCTION: IMPERIALISM 0x005a6310
int TNavyTacUnit::GetBaseActionPoints() {
  return baseActionPoints3c;
}

// FUNCTION: IMPERIALISM 0x005a6330
int TNavyTacUnit::GetUnitRange() {
  return sourceShip34->GetRange();
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
void TNavyTacUnit::ApplyNavalDamage(float damageAmount, NavyTargeting targeting) {
  int hullDelta;
  int crewDelta;
  int actionPointDelta = 0;

  switch (targeting) {
  case kNavyTargetingHull:
    hullDelta = static_cast<int>(damageAmount);
    crewDelta = static_cast<int>(damageAmount * g_dNavyDamageSplitRatioA_00669f10);
    break;
  case kNavyTargetingCrew:
    hullDelta = static_cast<int>(damageAmount * g_dNavyDamageSplitRatioA_00669f10);
    crewDelta = static_cast<int>(damageAmount * g_dNavyDamageSplitRatioB_00669f18);
    break;
  case kNavyTargetingSail:
    hullDelta = static_cast<int>(damageAmount * g_dNavyDamageSplitRatioA_00669f10);
    crewDelta = 0;
    if (static_cast<float>(rand() % 10) < damageAmount) {
      actionPointDelta = 10;
    }
    break;
  default:
    // Unreached in practice; preserve the original default branch's raw float bits.
    memcpy(&hullDelta, &damageAmount, sizeof(hullDelta));
    crewDelta = hullDelta;
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
