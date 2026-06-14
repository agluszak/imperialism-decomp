#pragma once

#include "decomp_types.h"

#include "game/TCityOrderCapabilityState.h"

class TGreatPower;
class TLocalizationRuntime;
class TPtrList;

int SumMilitaryUnitPowerWeights(TPtrList* unitList);
float SumAlliedArmyScoreFactors(int targetNation);
float SumAlliedNavyScoreFactors(int targetNation);
short* GetRelationStandingRowForNation(short nationSlot);
int GetClampedQuarterYearTerm(void);
float TruncatedScoreFactorToFloat(float score);

static __inline TCityOrderCapabilityState* CityOrderCapabilityState(void) {
  return g_pCityOrderCapabilityState;
}
static __inline short CityOrderCapForNation(short nationSlot) {
  return g_pCityOrderCapabilityState->nationCapRows1e8[nationSlot].cap;
}
static __inline short CityOrderActiveZoneIndex(void) {
  return g_pCityOrderCapabilityState->activeZoneIndex1d4;
}
