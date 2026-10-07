// TInvadeMission implementations.

#include <string.h>

#include "game/military/TInvadeMission.h"

#include "game/ui_core/CIterator.h"
#include "game/nation/TAutoGreatPower.h"
#include "game/map/TBeachheadMission.h"
#include "game/city_ui/TCountry.h"
#include "game/map/TMapMgr.h"
#include "game/military/TMilitaryUnit.h"
#include "game/core/TStream.h"
#include "game/globals/global_types.h"
#include "game/globals/military_globals.h"
#include "game/globals/shared_globals.h"

IMPLEMENT_SERIAL(TInvadeMission, TAttackProvinceMission, 1)

// FUNCTION: IMPERIALISM 0x0053f120
TMission* TInvadeMission::GetNavyMission() {
  return beachhead;
}

// FUNCTION: IMPERIALISM 0x0053f140
bool TInvadeMission::IsNavyMission() const {
  return true;
}

// FUNCTION: IMPERIALISM 0x0053f160
void TInvadeMission::ForgetTaskForce(TTaskForce* taskForce) {
  if (beachhead != nullptr) {
    beachhead->ForgetTaskForce(taskForce);
  }
}

// FUNCTION: IMPERIALISM 0x0053f190
void TInvadeMission::AcceptReenforcement(TShip* ship, bool notify) {
  if (beachhead != nullptr) {
    beachhead->AcceptReenforcement(ship, notify);
  }
}

// FUNCTION: IMPERIALISM 0x0053f1c0
void TInvadeMission::RejectConstituent(TShip* ship, bool notify) {
  if (beachhead != nullptr) {
    beachhead->RejectConstituent(ship, notify);
  }
}

// FUNCTION: IMPERIALISM 0x0053f1f0
float TInvadeMission::IndustrialCostOfNeeds() {
  float armyCost = 0.0f;
  for (int i = 0; i < 5; ++i) {
    armyCost += requiredEquipageByClass[i] * g_ArmyMissionDotProductWeights[i];
  }
  return armyCost + beachhead->IndustrialCostOfNeeds();
}

// FUNCTION: IMPERIALISM 0x0053f240
bool TInvadeMission::IsHospitalMission() const {
  return false;
}

// FUNCTION: IMPERIALISM 0x0053f2d0
TInvadeMission::TInvadeMission(TZone* beachheadZone, short targetProvince)
    : TAttackProvinceMission(targetProvince, -1), beachhead(nullptr) {
  if (beachheadZone != nullptr) {
    beachhead = new TBeachheadMission(beachheadZone, this);
  }
}

// FUNCTION: IMPERIALISM 0x0053f3f0
TInvadeMission::~TInvadeMission() {}

// FUNCTION: IMPERIALISM 0x0053f410
void TInvadeMission::Free() {
  beachhead->Free();

  TAutoGreatPower* nationState = static_cast<TAutoGreatPower*>(g_apNationStates[nationId]);
  nationState->AssertValid();
  nationState->SetProvinceStatus(targetProvince, kMissionDesirabilityUnmarked);

  CIterator iter(orderList);
  TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(iter.Reset());
  while (iter.More()) {
    unit->ownerMission = nullptr;
    unit = static_cast<TMilitaryUnit*>(iter.Advance());
  }

  orderList->RemoveAll();
  if (orderList != nullptr) {
    orderList->FreePayloadsAndDestroy();
  }
  orderList = nullptr;

  if (this != nullptr) {
    delete this;
  }
}

// FUNCTION: IMPERIALISM 0x0053f4e0
bool TInvadeMission::SmokeEmIfYouGotEm() {
  if (!beachhead->SmokeEmIfYouGotEm()) {
    return false;
  }
  CIterator iter(orderList);
  TArmyMission* armyMission = this;
  for (void* item = iter.Reset(); iter.More(); item = iter.Advance()) {
    TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(item);
    if (unit->GetCategory() != EncodeArmyUnitCategory(kArmyUnitCategoryMilitia)) {
      armyMission->RejectConstituent(unit, true);
    }
  }
  return true;
}

// FUNCTION: IMPERIALISM 0x0053f580
void TInvadeMission::Initialize() {
  beachhead->InitializeMissionWithNationIdAndResetPathMarker(nationId);
  marker11 = 1;
  if (targetProvince != -1) {
    pathMarker =
        static_cast<short>(g_pGlobalMapState->cityScoreTable[targetProvince].ownerNationCode);
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
  if (beachhead != nullptr) {
    beachhead->CalculateNeeds();
  }
}

// FUNCTION: IMPERIALISM 0x0053f640
void TInvadeMission::WriteTo(TStream* stream) {
  TArmyMission::WriteTo(stream);
  stream->WriteBytes(&targetProvince, 2);
  stream->WriteBytes(&amassingProvince, 2);
  beachhead->WriteTo(stream);
}

// FUNCTION: IMPERIALISM 0x0053f690
void TInvadeMission::ReadFrom(TStream* stream) {
  TArmyMission::ReadFrom(stream);
  stream->ReadBytes(&targetProvince, 2);
  stream->ReadBytes(&amassingProvince, 2);
  if (beachhead != nullptr) {
    beachhead->Free();
  }
  beachhead = new TBeachheadMission();
  beachhead->parentMission = this;
  beachhead->ReadFrom(stream);
}

// FUNCTION: IMPERIALISM 0x0053f780
void TInvadeMission::GiveOrders() {
  if (beachhead != nullptr) {
    beachhead->GiveOrders();
  }
  // Per-region, per-nation dispatch-dirty bitmask gate.
  if (g_pGlobalMapState->cityScoreTable[targetProvince].exploredByNationMask &
      (1 << (nationId & 0x1f))) {
    TAttackProvinceMission::GiveOrders();
  }
}

// FUNCTION: IMPERIALISM 0x0053f7d0
void TInvadeMission::Reassess() {
  beachhead->Reassess();
  SetStateByte8To2();
  CalculateImportance();
  CalculateNeeds();
}

// FUNCTION: IMPERIALISM 0x0053f800
float TInvadeMission::CalculatePriority() {
  float currentUnitCost = 0.0f;
  CIterator costIterator(orderList);
  for (TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(costIterator.Reset()); costIterator.More();
       unit = static_cast<TMilitaryUnit*>(costIterator.Advance())) {
    currentUnitCost += static_cast<float>(unit->GetArmsCarried());
  }

  int resourcePools[9] = {0, 0, 0, 0, 0, 0, 0, 0, 0};
  float committedResources[5] = {0.0f, 0.0f, 0.0f, 0.0f, 0.0f};
  int totalResourceDemand = 0;
  CIterator unitIterator(orderList);
  for (TMilitaryUnit* selectedUnit = static_cast<TMilitaryUnit*>(unitIterator.Reset());
       unitIterator.More(); selectedUnit = static_cast<TMilitaryUnit*>(unitIterator.Advance())) {
    selectedUnit->AssertValid();
    short weightIndex = selectedUnit->GetTurnDistanceTo(GetPresentLocation());
    if (weightIndex > 5) {
      weightIndex = 5;
    }
    float distanceWeight = g_MissionOrderDistanceDecayWeightTable[weightIndex];
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
  // Listing 0x0053f800 accumulates this retail local but never reads the final sum.
  (void)totalResourceDemand;

  TMilitaryUnit* bestUnitByType[30];
  memset(bestUnitByType, 0, sizeof(bestUnitByType));
  char selectedIsIndustry;
  char selectedIsUpgrade;
  int selectedSlot;
  float cityActionCost = 0.0f;
  while (SelectBestCityDevelopmentFromResourcePools(nationId, resourcePools, bestUnitByType,
                                                    &selectedIsIndustry, &selectedIsUpgrade,
                                                    &selectedSlot, 0, 0)) {
    cityActionCost += static_cast<float>(TMilitaryUnit::GetTypeArmsCarried(selectedSlot));
  }

  if (cityActionCost > currentUnitCost) {
    return cityActionCost;
  }
  return currentUnitCost;
}

// FUNCTION: IMPERIALISM 0x0053faa0
bool TInvadeMission::IsArmyMission() const {
  return true;
}

// FUNCTION: IMPERIALISM 0x0053fac0
float TInvadeMission::ValueOf(TMilitaryUnit* candidateUnit) {
  float delta;
  if (flag10 != 0) {
    delta = 0.0f;
  } else if (candidateUnit->ownerMission == this) {
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
    return 0.0f;
  }
  return beachhead->ValueOf(candidate);
}

// FUNCTION: IMPERIALISM 0x0053fb90
void TInvadeMission::Hold(bool value) {
  flag10 = value;
  if (beachhead != nullptr) {
    beachhead->Hold(value);
  }
}

// FUNCTION: IMPERIALISM 0x0053fbc0
bool TInvadeMission::Matches(eMissionType missionType, int key, TZone* zoneContext) const {
  return missionType == kMissionTypeInvadeProvince && key == targetProvince &&
         beachhead != nullptr && beachhead->Matches(kMissionTypeInvadeProvince, key, zoneContext);
}

// FUNCTION: IMPERIALISM 0x0053fc10
int TInvadeMission::AccumulateLack(int* accumulatedLack, bool includeExistingLack) const {
  float vector[5] = {0};
  int total = 0;
  AccumulateOrderPriorityVector(vector);

  for (int i = 0; i < 5; ++i) {
    float value;
    if (includeExistingLack && requiredEquipageByClass[i] <= vector[i]) {
      float difference = requiredEquipageByClass[i] - vector[i];
      value = difference * g_InvadeMissionSuppressedPriorContributionScale +
              static_cast<float>(accumulatedLack[i]);
    } else {
      value = requiredEquipageByClass[i] - vector[i] + static_cast<float>(accumulatedLack[i]);
    }
    int rounded = static_cast<int>(value);
    accumulatedLack[i] = rounded;
    total += rounded;
  }

  return total + beachhead->AccumulateLack(accumulatedLack, includeExistingLack);
}

// FUNCTION: IMPERIALISM 0x0053fdc0
bool TInvadeMission::TryResolveTargetTerrainClass() {
  presentLocation = -1;
  if (TAttackProvinceMission::TryResolveTargetTerrainClass()) {
    presentLocation = -1;
    return false;
  }
  presentLocation =
      static_cast<short>(g_apTerrainTypeDescriptorTable[nationId]->GetCapitolProvince());
  return true;
}

// FUNCTION: IMPERIALISM 0x0053fe10
TMission* TInvadeMission::GetReplacement() {
  presentLocation = -1;
  return TAttackProvinceMission::GetReplacement();
}
