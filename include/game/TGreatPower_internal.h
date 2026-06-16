#pragma once

#include "decomp_types.h"

#include "game/TCityOrderCapabilityState.h"
#include "game/TMinor.h"
#include "game/TShip.h"
#include "game/TZone.h"
#include "game/TPtrList.h"

class TGreatPower;
class TLocalizationRuntime;

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
static __inline int IsRecruitTier2EnabledForNation(short nationSlot) {
  return g_pCityOrderCapabilityState->orderCapRows277[nationSlot].recruitTierFlag27b == 2;
}

// Decode minor-capability row owner tag (0x004dab20 civ-work branch).
static __inline short ResolveMinorCapabilityOwnerNationSlot(const TMinor* minor) {
  short ownerTag = minor->encodedNationSlot;
  if (ownerTag > 99 && ownerTag < 200) {
    return static_cast<short>(ownerTag - 100);
  }
  return ownerTag;
}
