// TInvadeMission implementations.

#include <string.h>

#include "game/TInvadeMission.h"

#include "game/CIterator.h"
#include "game/TAutoGreatPower.h"
#include "game/TBeachheadMission.h"
#include "game/TCountry.h"
#include "game/TGlobalMapState.h"
#include "game/TMapMgr.h"
#include "game/TMilitaryUnit.h"
#include "game/TStream.h"
#include "game/global_data_tables.h"

IMPLEMENT_SERIAL(TInvadeMission, TAttackProvinceMission, 1)

// SYNTHETIC: IMPERIALISM 0x0053f080
// TInvadeMission::CreateObject

// FUNCTION: IMPERIALISM 0x0053f120
TMission* TInvadeMission::GetNavyMission() {
  return beachhead34;
}

// FUNCTION: IMPERIALISM 0x0053f140
char TInvadeMission::IsNavyMission() const {
  return 1;
}

// FUNCTION: IMPERIALISM 0x0053f160
void TInvadeMission::ForgetTaskForce(TTaskForce* taskForce) {
  if (beachhead34 != nullptr) {
    beachhead34->ForgetTaskForce(taskForce);
  }
}

// FUNCTION: IMPERIALISM 0x0053f190
void TInvadeMission::AcceptReenforcement(TShip* ship, unsigned char notify) {
  if (beachhead34 != nullptr) {
    beachhead34->AcceptReenforcement(ship, notify);
  }
}

// FUNCTION: IMPERIALISM 0x0053f1c0
void TInvadeMission::RejectConstituent(TShip* ship, unsigned char notify) {
  if (beachhead34 != nullptr) {
    beachhead34->RejectConstituent(ship, notify);
  }
}

// FUNCTION: IMPERIALISM 0x0053f1f0
float TInvadeMission::IndustrialCostOfNeeds() {
  return TArmyMission::IndustrialCostOfNeeds() + beachhead34->IndustrialCostOfNeeds();
}

// FUNCTION: IMPERIALISM 0x0053f240
char TInvadeMission::IsHospitalMission() const {
  return 0;
}

// SYNTHETIC: IMPERIALISM 0x0053f260
// TInvadeMission::GetRuntimeClass

// FUNCTION: IMPERIALISM 0x0053f2d0
TInvadeMission::TInvadeMission(short targetProvince, TZone* beachheadZone)
    : TAttackProvinceMission(targetProvince, -1), beachhead34(nullptr) {
  if (beachheadZone != nullptr) {
    beachhead34 = new TBeachheadMission(beachheadZone, this);
  }
}
// SYNTHETIC: IMPERIALISM 0x0053f3c0
// TInvadeMission::`scalar deleting destructor'

TInvadeMission::TInvadeMission() : TAttackProvinceMission(), beachhead34(nullptr) {}

// FUNCTION: IMPERIALISM 0x0053f410
void TInvadeMission::Free() {
  if (beachhead34 != nullptr) {
    beachhead34->Free();
    beachhead34 = nullptr;
  }
  TAttackProvinceMission::Free();
}

// Matches the original exactly: unconditionally dereferences beachhead34 (no null check),
// so this is only ever called on an instance with a live beachhead child.
// FUNCTION: IMPERIALISM 0x0053f4e0
char TInvadeMission::SmokeEmIfYouGotEm() {
  if (!beachhead34->SmokeEmIfYouGotEm()) {
    return 0;
  }
  CIterator iter(orderListAt18);
  for (void* item = iter.Reset(); iter.More(); item = iter.Advance()) {
    TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(item);
    if (unit->GetUnitMovementClassId() != 0) {
      RejectConstituent(unit, 1);
    }
  }
  return 1;
}

// FUNCTION: IMPERIALISM 0x0053f580
void TInvadeMission::Initialize() {
  beachhead34->InitializeMissionWithNationIdAndResetPathMarker(nationId04);
  marker11 = 1;
  if (targetProvince30 != -1) {
    pathMarker06 =
        static_cast<short>(g_pGlobalMapState->cityScoreTable[targetProvince30].ownerNationCode00);
  }
  marker11 = 3;
}

// FUNCTION: IMPERIALISM 0x0053f5f0
void TInvadeMission::SetStateByte8To2() {
  state08 = 2;
}

// FUNCTION: IMPERIALISM 0x0053f610
void TInvadeMission::CalculateNeeds() {
  TAttackProvinceMission::CalculateNeeds();
  if (beachhead34 != nullptr) {
    beachhead34->CalculateNeeds();
  }
}

// FUNCTION: IMPERIALISM 0x0053f640
void TInvadeMission::WriteTo(TStream* stream) {
  TAttackProvinceMission::WriteTo(stream);
  if (beachhead34 != nullptr) {
    beachhead34->WriteTo(stream);
  }
}

// FUNCTION: IMPERIALISM 0x0053f690
void TInvadeMission::ReadFrom(TStream* stream) {
  TArmyMission::ReadFrom(stream);
  stream->ReadBytes(&targetProvince30, 2);
  stream->ReadBytes(&amassingProvince32, 2);
  if (beachhead34 != nullptr) {
    beachhead34->Free();
  }
  beachhead34 = new TBeachheadMission();
  beachhead34->parentMission3c = this;
  beachhead34->ReadFrom(stream);
}

// FUNCTION: IMPERIALISM 0x0053f780
void TInvadeMission::GiveOrders() {
  if (beachhead34 != nullptr) {
    beachhead34->GiveOrders();
  }
  // Per-region, per-nation dispatch-dirty bitmask gate (byte at record+0xa1,
  // bit index nationId04) -- pending exact TGlobalMapCityScoreRecord field
  // recovery for that byte; approximated via raw offset access for now.
  const unsigned char* recordBytes =
      reinterpret_cast<const unsigned char*>(&g_pGlobalMapState->cityScoreTable[targetProvince30]);
  if (recordBytes[0xa1] & (1 << (nationId04 & 0x1f))) {
    TAttackProvinceMission::GiveOrders();
  }
}

// FUNCTION: IMPERIALISM 0x0053f7d0
void TInvadeMission::Reassess() {
  beachhead34->Reassess();
  SetStateByte8To2();
  CalculateImportance();
  CalculateNeeds();
}

// FUNCTION: IMPERIALISM 0x0053f800
float TInvadeMission::CalculatePriority() {
  float currentUnitCost = 0.0f;
  CIterator costIterator(orderListAt18);
  for (TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(costIterator.Reset()); costIterator.More();
       unit = static_cast<TMilitaryUnit*>(costIterator.Advance())) {
    currentUnitCost += static_cast<float>(unit->GetUnitTypeCostPoints());
  }

  int resourcePools[9] = {0, 0, 0, 0, 0, 0, 0, 0, 0};
  float committedResources[5] = {0.0f, 0.0f, 0.0f, 0.0f, 0.0f};
  int totalResourceDemand = 0;
  CIterator unitIterator(orderListAt18);
  for (TMilitaryUnit* selectedUnit = static_cast<TMilitaryUnit*>(unitIterator.Reset());
       unitIterator.More(); selectedUnit = static_cast<TMilitaryUnit*>(unitIterator.Advance())) {
    selectedUnit->AssertValid();
    short weightIndex = selectedUnit->IsNotStationedInProvince(GetPresentLocation());
    if (weightIndex > 5) {
      weightIndex = 5;
    }
    float distanceWeight = g_MissionOrderDistanceDecayWeightTable_006978c8[weightIndex];
    AccumulateUnitOrderPriorityVectorContribution(
        selectedUnit, committedResources, distanceWeight,
        static_cast<float>(g_pGlobalMapState->GetProvinceUnitOrderWeight(GetPresentLocation())));
  }

  for (int resourceIndex = 0; resourceIndex < 5; ++resourceIndex) {
    resourcePools[resourceIndex] =
        static_cast<int>(requiredEquipageByClass[resourceIndex] -
                         committedResources[resourceIndex] + resourcePools[resourceIndex]);
    totalResourceDemand += resourcePools[resourceIndex];
  }

  TMilitaryUnit* bestUnitByType[30];
  memset(bestUnitByType, 0, sizeof(bestUnitByType));
  char selectedIsIndustry;
  char selectedIsUpgrade;
  int selectedSlot;
  float cityActionCost = 0.0f;
  while (SelectBestCityDevelopmentFromResourcePools(nationId04, resourcePools, bestUnitByType,
                                                    &selectedIsIndustry, &selectedIsUpgrade,
                                                    &selectedSlot, 0, 0)) {
    cityActionCost += static_cast<float>(GetCityActionGateValueBySlot(selectedSlot));
  }

  if (cityActionCost > currentUnitCost) {
    return cityActionCost;
  }
  return currentUnitCost;
}

// FUNCTION: IMPERIALISM 0x0053faa0
char TInvadeMission::IsArmyMission() const {
  return 1;
}

// Same shape as TArmyMission::ValueOf, but the "not this mission's own unit"
// branch is scaled down by 0.1 unless IsArmyMission() says otherwise (TInvadeMission's
// own override always returns true, so the scale-down never actually triggers here -- kept
// as a real virtual dispatch to match the original rather than hardcoding).
// FUNCTION: IMPERIALISM 0x0053fac0
float TInvadeMission::ValueOf(TMilitaryUnit* candidateUnit) {
  float delta;
  if (flag10 != 0) {
    delta = 0.0f;
  } else if (candidateUnit->ownerMission40 == this) {
    delta = GetWeightedSatisfaction() -
            ComputeArmyMissionScoreDeltaWithScaledCandidateUnit(candidateUnit);
  } else {
    delta =
        ComputeArmyMissionScoreDeltaWithCandidateUnit(candidateUnit) - GetWeightedSatisfaction();
  }

  if (!IsArmyMission()) {
    delta *= 0.1f;
  }
  return delta;
}

// FUNCTION: IMPERIALISM 0x0053fb60
float TInvadeMission::ValueOf(TShip* candidate) {
  if (flag10 != 0) {
    return g_Recompute_Nation_Order_LookupTable_0065A9E8;
  }
  return beachhead34->ValueOf(candidate);
}

// FUNCTION: IMPERIALISM 0x0053fb90
void TInvadeMission::Hold(unsigned char value) {
  flag10 = value;
  if (beachhead34 != nullptr) {
    beachhead34->Hold(value);
  }
}

// FUNCTION: IMPERIALISM 0x0053fbc0
char TInvadeMission::Matches(int kind, int key, int mode) const {
  if (kind == 2 && key == targetProvince30 && beachhead34 != nullptr) {
    if (beachhead34->Matches(2, key, mode) != 0) {
      return 1;
    }
  }
  return 0;
}

// Builds the order-list contribution vector, then subtracts it from this mission's desired
// resource profile. When includePriorContributions is set, an existing output component is
// carried into the difference unless the desired component is already at or below the new
// contribution; that exhausted case uses the original's address-distinct zero carry scale.
// Each resulting float is converted through VC5's _ftol path before the beachhead child's
// own slot-0x2c contribution is added to the returned total.
// FUNCTION: IMPERIALISM 0x0053fc10
int TInvadeMission::AccumulateLack(int* accumulatedLack, unsigned char includeExistingLack) const {
  float vector[5] = {0};
  int total = 0;
  CIterator iter(orderListAt18);
  for (void* item = iter.Reset(); iter.More(); item = iter.Advance()) {
    TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(item);
    unit->AssertValid();
    short weightIndex = unit->IsNotStationedInProvince(GetPresentLocation());
    if (weightIndex > 5) {
      weightIndex = 5;
    }
    float distanceWeight = g_MissionOrderDistanceDecayWeightTable_006978c8[weightIndex];
    AccumulateUnitOrderPriorityVectorContribution(
        unit, vector, distanceWeight,
        static_cast<float>(g_pGlobalMapState->GetProvinceUnitOrderWeight(GetPresentLocation())));
  }

  for (int i = 0; i < 5; ++i) {
    float value;
    if (includeExistingLack != 0 && requiredEquipageByClass[i] <= vector[i]) {
      float difference = requiredEquipageByClass[i] - vector[i];
      value = difference + static_cast<float>(accumulatedLack[i]) *
                               g_InvadeMissionSuppressedPriorContributionScale_0065A95C;
    } else {
      value = requiredEquipageByClass[i] - vector[i] + static_cast<float>(accumulatedLack[i]);
    }
    int rounded = static_cast<int>(value);
    accumulatedLack[i] = rounded;
    total += rounded;
  }

  return total + beachhead34->AccumulateLack(accumulatedLack, includeExistingLack);
}

// FUNCTION: IMPERIALISM 0x0053fdc0
char TInvadeMission::TryResolveTargetTerrainClass() {
  presentLocation14 = static_cast<short>(0xffff);
  if (TAttackProvinceMission::TryResolveTargetTerrainClass() != 0) {
    presentLocation14 = static_cast<short>(0xffff);
    return 0;
  }
  presentLocation14 = static_cast<short>(
      g_apTerrainTypeDescriptorTable[nationId04]->GetHomeRegionCityRecordIndex());
  return 1;
}

// FUNCTION: IMPERIALISM 0x0053fe10
TMission* TInvadeMission::GetReplacementSlot48() {
  presentLocation14 = static_cast<short>(0xffff);
  return TAttackProvinceMission::GetReplacementSlot48();
}
