#include "game/tactical/TNavyTacUnit.h"

#include <string.h>

#include "game/globals/global_types.h"
#include "game/globals/tactical_globals.h"
#include "game/globals/navy_globals.h"
#include "game/globals/shared_globals.h"
#include "game/navy/TShip.h"

#include <stdlib.h>

// FUNCTION: IMPERIALISM 0x0059ed60
TShip* TNavyTacUnit::GetRealShip() {
  return sourceShip;
}

IMPLEMENT_DYNCREATE(TNavyTacUnit, TTacticalUnit)

// FUNCTION: IMPERIALISM 0x005a6290
void TNavyTacUnit::InitializeFromSourceShip(TShip* sourceShip) {
  tileIndex = -2;
  unitType = g_anTacticalNavyUnitTypeByShipType[sourceShip->type];
  selectedFlag = false;
  status = 0;
  actionPoints = GetBaseActionPoints();
  aiStateCode = 0;
  attackTarget = 0;
  strength = sourceShip->strength;
  secondaryCombatStrength = sourceShip->strength;
  int speed = sourceShip->GetSpeed();
  this->sourceShip = sourceShip;
  baseActionPoints = speed * 10;
}

// FUNCTION: IMPERIALISM 0x005a6310
int TNavyTacUnit::GetBaseActionPoints() {
  return baseActionPoints;
}

// FUNCTION: IMPERIALISM 0x005a6330
int TNavyTacUnit::GetUnitRange() {
  return sourceShip->GetRange();
}

// FUNCTION: IMPERIALISM 0x005a6350
float TNavyTacUnit::GetBaseAttackPower() {
  return g_afTacticalNavyBaseAttackPowerByUnitType[unitType];
}

// FUNCTION: IMPERIALISM 0x005a6370
float TNavyTacUnit::GetDamageScale() {
  return g_afTacticalNavyDamageScaleByUnitType[unitType];
}

// FUNCTION: IMPERIALISM 0x005a6390
short TNavyTacUnit::GetSourceShipTypeDescriptorWord() {
  return TShip::GetTypeHullPoints(sourceShip->type);
}

// FUNCTION: IMPERIALISM 0x005a63c0
void TNavyTacUnit::ApplyNavalDamage(float damageAmount, NavyTargeting targeting) {
  int strengthDelta;
  int secondaryCombatStrengthDelta;
  int actionPointDelta = 0;

  switch (targeting) {
  case kNavyTargetingHull:
    secondaryCombatStrengthDelta = static_cast<int>(damageAmount);
    strengthDelta = static_cast<int>(damageAmount * g_dNavyDamageSplitRatioA);
    break;
  case kNavyTargetingCrew:
    secondaryCombatStrengthDelta = static_cast<int>(damageAmount * g_dNavyDamageSplitRatioA);
    strengthDelta = static_cast<int>(damageAmount * g_dNavyDamageSplitRatioB);
    break;
  case kNavyTargetingSail:
    secondaryCombatStrengthDelta = static_cast<int>(damageAmount * g_dNavyDamageSplitRatioA);
    strengthDelta = 0;
    if (static_cast<float>(rand() % 10) < damageAmount) {
      actionPointDelta = 10;
    }
    break;
  default:
    // Unreached in practice; preserve the original default branch's raw float bits.
    memcpy(&secondaryCombatStrengthDelta, &damageAmount, sizeof(secondaryCombatStrengthDelta));
    strengthDelta = secondaryCombatStrengthDelta;
    break;
  }

  strength -= strengthDelta;
  secondaryCombatStrength -= secondaryCombatStrengthDelta;
  baseActionPoints -= actionPointDelta;
  if (strength <= 0 || secondaryCombatStrength <= 0) {
    strength = 0;
    secondaryCombatStrength = 0;
    status = 3;
  }
}
