// TArmyMission implementations.

#include <math.h>

#include "game/military/TArmyMission.h"
#include "game/core/stream_byteswap.h"
#include "game/TList.h"
#include "game/nation/TGreatPower.h"
#include "game/core/TStream.h"
#include "game/map/TMapMgr.h"
#include "game/military/TMilitaryUnit.h"
#include "game/globals/prelude.h"
#include "game/globals/military_globals.h"
#include "game/globals/shared_globals.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/ui_core/CIterator.h"

IMPLEMENT_SERIAL(TArmyMission, TMission, 1)

// FUNCTION: IMPERIALISM 0x005356f0
bool TArmyMission::IsArmyMission() const {
  return true;
}

// FUNCTION: IMPERIALISM 0x00535710
TMission* TArmyMission::GetArmyMission() {
  return this;
}

// FUNCTION: IMPERIALISM 0x00535730
TMission* TArmyMission::GetNavyMission() {
  return nullptr;
}

// FUNCTION: IMPERIALISM 0x00535750
short TArmyMission::GetPresentLocation() const {
  return presentLocation14;
}

// SYNTHETIC: IMPERIALISM 0x0053bfb0
// TArmyMission::CreateObject

// SYNTHETIC: IMPERIALISM 0x0053c030
// TArmyMission::GetRuntimeClass

// FUNCTION: IMPERIALISM 0x0053c0a0
TArmyMission::TArmyMission(int nodeKey) : TMission() {
  presentLocation14 = static_cast<short>(nodeKey);

  TList* list = new TList;
  orderListAt18 = list;
  if (list == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag("D:\\Ambit\\Cross\\UMissionSubs.cpp", 0x842);
  }

  for (int i = 0; i < 5; ++i) {
    requiredEquipageByClass[i] = 0.0f;
  }
}

// FUNCTION: IMPERIALISM 0x0053c1b0
bool TArmyMission::IsANoBrainer() const {
  return false;
}
// SYNTHETIC: IMPERIALISM 0x0053c1d0
// TArmyMission::`scalar deleting destructor'

// Shared accumulation loop over orderListAt18 (0x53c620 / 0x53ceb0 / 0x53d020 / 0x53d200 /
// 0x53fc10 all repeat this exact per-unit vector-contribution pattern -- kept `inline` and
// TU-local: giving it real external linkage (tried during bd 1uj.16.7) changed this TU's own
// inlining decisions at its two callers below and regressed 4 sibling functions by 8-25pp, so
// TInvadeMission::AccumulateLack duplicates the loop body instead of calling this, matching
// the original's own apparent per-callsite inlining).
inline void TArmyMission::AccumulateOrderPriorityVector(float* vector) const {
  CIterator iter(orderListAt18);
  for (void* item = iter.Reset(); iter.More(); item = iter.Advance()) {
    TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(item);
    unit->AssertValid();
    short weightIndex = unit->GetTurnDistanceTo(GetPresentLocation());
    if (weightIndex > 5) {
      weightIndex = 5;
    }
    AccumulateUnitOrderPriorityVectorContribution(
        unit, vector, g_MissionOrderDistanceDecayWeightTable_006978c8[weightIndex],
        static_cast<float>(g_pGlobalMapState->GetProvinceUnitOrderWeight(GetPresentLocation())));
  }
}

// FUNCTION: IMPERIALISM 0x0053c220
void TArmyMission::Free() {
  if (orderListAt18 != nullptr) {
    CIterator iter(orderListAt18);
    void* current = iter.Reset();
    while (iter.More()) {
      static_cast<TMilitaryUnit*>(current)->ownerMission40 = nullptr;
      current = iter.Advance();
    }

    orderListAt18->RemoveAll();
    orderListAt18->FreePayloadsAndDestroy();
    orderListAt18 = nullptr;
  }

  if (this != nullptr) {
    delete this;
  }
}

// FUNCTION: IMPERIALISM 0x0053c2b0
void TArmyMission::WriteTo(TStream* stream) {
  TMission::WriteTo(stream);
  stream->WriteBytes(&presentLocation14, 2);
  WriteFloatArrayElems(stream, requiredEquipageByClass, 5);

  stream->WriteInteger(orderListAt18->GetCount());

  // The nation lookup stays inside the loop, as at 0x53c350.
  CIterator iter(orderListAt18);
  void* currentUnit = iter.Reset();
  while (iter.More()) {
    stream->WriteInteger(
        g_apNationStates[nationId04]->militaryUnitList44->FindOneBasedOrdinalOf(currentUnit));
    currentUnit = iter.Advance();
  }
}

// FUNCTION: IMPERIALISM 0x0053c3d0
void TArmyMission::ReadFrom(TStream* stream) {
  TMission::ReadFrom(stream);
  stream->ReadBytes(&presentLocation14, 2);
  if (g_nSaveFormatVersion < 0xb) {
    stream->ReadBytes(&requiredEquipageByClass[0], 0x10);
    requiredEquipageByClass[4] = 0.0f;
  } else {
    stream->ReadBytes(&requiredEquipageByClass[0], 0x14);
    // In-place four-byte reverse over the whole array (0x53c420), not a per-element
    // load/swap/store through a temporary.
    ReverseDwordArrayBytes(requiredEquipageByClass, 5);
  }

  // The nation and its unit list are re-read on every iteration, and the ordinal is read
  // after them -- both follow from writing the lookup as one receiver expression, which
  // is the order 0x53c46a..0x53c48e evaluates.
  int count = stream->ReadInteger();
  while (count-- != 0) {
    TSortedList* unitList = g_apNationStates[nationId04]->militaryUnitList44;
    TMilitaryUnit* unit =
        static_cast<TMilitaryUnit*>(unitList->GetEntryByOrdinal(stream->ReadInteger()));
    AcceptReenforcement(unit, 0);
  }
}

// FUNCTION: IMPERIALISM 0x0053c4f0
char TArmyMission::SmokeEmIfYouGotEm() {
  if (orderListAt18 != nullptr) {
    CIterator iter(orderListAt18);
    void* item = iter.Reset();
    while (iter.More()) {
      TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(item);
      ArmyUnitCategoryStorage category = unit->GetCategory();
      if (category != EncodeArmyUnitCategory(kArmyUnitCategoryMilitia)) {
        RejectConstituent(unit, 1);
      }
      item = iter.Advance();
    }
  }
  return 1;
}

// FUNCTION: IMPERIALISM 0x0053c570
void TArmyMission::AcceptReenforcement(TMilitaryUnit* unit, unsigned char notify) {
  unit->TObject::AssertValid();
  TMission* owner = unit->ownerMission40;
  if (owner != nullptr) {
    owner->RejectConstituent(unit, notify);
  }
  unit->ownerMission40 = this;
  orderListAt18->AddHead(unit);
  if (static_cast<char>(notify) != 0) {
    Reassess();
  }
}

// FUNCTION: IMPERIALISM 0x0053c5e0
void TArmyMission::RejectConstituent(TMilitaryUnit* unit, unsigned char notify) {
  (void)notify;
  if (orderListAt18 != nullptr) {
    POSITION pos = orderListAt18->listState.Find(unit);
    if (pos != nullptr) {
      orderListAt18->listState.RemoveAt(pos);
    }
  }
  unit->ownerMission40 = nullptr;
}

// FUNCTION: IMPERIALISM 0x0053c620
int TArmyMission::AccumulateLack(int* accumulatedLack, unsigned char includeExistingLack) const {
  float vector[5] = {0.0f, 0.0f, 0.0f, 0.0f, 0.0f};
  CIterator iter(orderListAt18);
  for (void* item = iter.Reset(); iter.More(); item = iter.Advance()) {
    TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(item);
    unit->AssertValid();
    short weightIndex = unit->GetTurnDistanceTo(GetPresentLocation());
    if (weightIndex > 5) {
      weightIndex = 5;
    }
    float distanceWeight = g_MissionOrderDistanceDecayWeightTable_006978c8[weightIndex];
    AccumulateUnitOrderPriorityVectorContribution(
        unit, vector, distanceWeight,
        static_cast<float>(g_pGlobalMapState->GetProvinceUnitOrderWeight(GetPresentLocation())));
  }

  int total = 0;
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
  return total;
}

// FUNCTION: IMPERIALISM 0x0053c9d0
void TArmyMission::ProjectEquipage(float* vector, short targetTile, short bypassTileFilter) const {
  for (int i = 0; i < 5; ++i) {
    vector[i] = 0.0f;
  }
  CIterator iter(orderListAt18);
  for (void* item = iter.Reset(); iter.More(); item = iter.Advance()) {
    TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(item);
    unit->AssertValid();
    if (targetTile == -1 || unit->IsWithinXTurnsOf(bypassTileFilter, targetTile)) {
      AccumulateUnitOrderPriorityVectorContribution(
          unit, vector, 1.0f,
          static_cast<float>(g_pGlobalMapState->GetProvinceUnitOrderWeight(GetPresentLocation())));
    }
  }
}

// FUNCTION: IMPERIALISM 0x0053cac0
float TArmyMission::ProjectSatisfaction(short bypassTileFilter) const {
  float vector[5];
  ProjectEquipage(vector, GetPresentLocation(), bypassTileFilter);

  float numerator = 0.0f;
  float denominator = 0.0f;
  for (int i = 0; i < 5; ++i) {
    numerator += sqrtf(requiredEquipageByClass[i] * vector[i]);
    denominator += requiredEquipageByClass[i];
  }
  return numerator / denominator;
}

// FUNCTION: IMPERIALISM 0x0053cb50
void TArmyMission::AccumulateMissionUnitPriorityContributionWithScaleMode(TMilitaryUnit* unit,
                                                                          float* vector,
                                                                          bool scaleMode) {
  short weightIndex = unit->GetTurnDistanceTo(GetPresentLocation());
  if (weightIndex > 5) {
    weightIndex = 5;
  }
  float sign = scaleMode ? static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065AA08)
                         : static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065A9E0);
  float scale = g_MissionOrderDistanceDecayWeightTable_006978c8[weightIndex] * sign;
  float weight =
      static_cast<float>(g_pGlobalMapState->GetProvinceUnitOrderWeight(GetPresentLocation()));
  AccumulateUnitOrderPriorityVectorContribution(unit, vector, scale, weight);
}

// FUNCTION: IMPERIALISM 0x0053cc10
void AccumulateUnitOrderPriorityVectorContribution(TMilitaryUnit* unit, float* vector, float scale,
                                                   float weight) {
  short quality = unit->field_38;
  short stat5 = unit->GetAttribute(5);
  short strength = unit->field_34;
  float dampen = 1.0f - static_cast<float>(stat5) * weight * -0.0001f;
  scale = static_cast<float>(strength) * 0.002f *
          (1.0f - static_cast<float>(static_cast<short>(quality / 100)) * -0.1f) * scale;
  vector[0] = vector[0] - static_cast<float>(strength) * -0.002f *
                              static_cast<float>(unit->GetAttribute(0)) * scale * dampen;
  vector[1] = static_cast<float>(unit->GetAttribute(1)) * scale * dampen + vector[1];
  vector[2] = static_cast<float>(unit->GetAttribute(2)) * scale + vector[2];
  vector[3] = static_cast<float>(unit->GetAttribute(3)) * scale + vector[3];
  vector[4] = static_cast<float>(unit->GetAttribute(4)) * scale * dampen + vector[4];
}

// FUNCTION: IMPERIALISM 0x0053cda0
void TArmyMission::GetWeightedEquipage(float* vector) const {
  for (int i = 0; i < 5; ++i) {
    vector[i] = 0.0f;
  }

  CIterator iter(orderListAt18);
  for (TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(iter.Reset()); iter.More();
       unit = static_cast<TMilitaryUnit*>(iter.Advance())) {
    unit->AssertValid();
    short weightIndex = unit->GetTurnDistanceTo(GetPresentLocation());
    if (weightIndex > 5) {
      weightIndex = 5;
    }
    AccumulateUnitOrderPriorityVectorContribution(
        unit, vector, g_MissionOrderDistanceDecayWeightTable_006978c8[weightIndex],
        static_cast<float>(g_pGlobalMapState->GetProvinceUnitOrderWeight(GetPresentLocation())));
  }
}

// FUNCTION: IMPERIALISM 0x0053ceb0
float TArmyMission::GetWeightedSatisfaction() {
  float vector[5] = {0.0f, 0.0f, 0.0f, 0.0f, 0.0f};
  AccumulateOrderPriorityVector(vector);

  double numerator = 0.0;
  double denominator = 0.0;
  for (int i = 0; i < 5; ++i) {
    float target = requiredEquipageByClass[i];
    float v = vector[i];
    if (target < v) {
      v = (v - target) * 0.25f + target;
    }
    denominator += target;
    numerator += sqrt(static_cast<double>(v) * static_cast<double>(target));
  }
  return static_cast<float>(numerator / denominator);
}

// FUNCTION: IMPERIALISM 0x0053d020
float TArmyMission::ComputeArmyMissionScoreDeltaWithCandidateUnit(TMilitaryUnit* candidateUnit) {
  float vector[5] = {0.0f, 0.0f, 0.0f, 0.0f, 0.0f};
  AccumulateOrderPriorityVector(vector);

  short weightIndex = candidateUnit->GetTurnDistanceTo(GetPresentLocation());
  if (weightIndex > 5) {
    weightIndex = 5;
  }
  AccumulateUnitOrderPriorityVectorContribution(
      candidateUnit, vector, g_MissionOrderDistanceDecayWeightTable_006978c8[weightIndex],
      static_cast<float>(g_pGlobalMapState->GetProvinceUnitOrderWeight(GetPresentLocation())));

  double numerator = 0.0;
  double denominator = 0.0;
  for (int i = 0; i < 5; ++i) {
    float target = requiredEquipageByClass[i];
    float v = vector[i];
    if (target < v) {
      v = (v - target) * 0.25f + target;
    }
    denominator += target;
    numerator += sqrt(static_cast<double>(v) * static_cast<double>(target));
  }
  return static_cast<float>(numerator / denominator);
}

// FUNCTION: IMPERIALISM 0x0053d200
float TArmyMission::ComputeArmyMissionScoreDeltaWithScaledCandidateUnit(
    TMilitaryUnit* candidateUnit) {
  float vector[5] = {0.0f, 0.0f, 0.0f, 0.0f, 0.0f};
  AccumulateOrderPriorityVector(vector);

  short weightIndex = candidateUnit->GetTurnDistanceTo(GetPresentLocation());
  if (weightIndex > 5) {
    weightIndex = 5;
  }
  AccumulateUnitOrderPriorityVectorContribution(
      candidateUnit, vector, g_MissionOrderDistanceDecayWeightTable_006978c8[weightIndex] * -1.0f,
      static_cast<float>(g_pGlobalMapState->GetProvinceUnitOrderWeight(GetPresentLocation())));

  double numerator = 0.0;
  double denominator = 0.0;
  for (int i = 0; i < 5; ++i) {
    float target = requiredEquipageByClass[i];
    float v = vector[i];
    if (target < v) {
      v = (v - target) * 0.25f + target;
    }
    denominator += target;
    numerator += sqrt(static_cast<double>(v) * static_cast<double>(target));
  }
  return static_cast<float>(numerator / denominator);
}

// FUNCTION: IMPERIALISM 0x0053d3e0
float TArmyMission::IndustrialCostOfNeeds() {
  double total = 0.0;
  for (int i = 0; i < 5; ++i) {
    total += static_cast<double>(requiredEquipageByClass[i]) *
             static_cast<double>(g_ArmyMissionDotProductWeights_00697980[i]);
  }
  return static_cast<float>(total);
}

// FUNCTION: IMPERIALISM 0x0053d420
float TArmyMission::ValueOf(TMilitaryUnit* candidateUnit) {
  if (flag10 != 0) {
    return g_Recompute_Nation_Order_LookupTable_0065A9E8;
  }

  if (candidateUnit->ownerMission40 == this) {
    float ownScore = GetWeightedSatisfaction();
    return ownScore - ComputeArmyMissionScoreDeltaWithScaledCandidateUnit(candidateUnit);
  }
  float withCandidate = ComputeArmyMissionScoreDeltaWithCandidateUnit(candidateUnit);
  return withCandidate - GetWeightedSatisfaction();
}

// FUNCTION: IMPERIALISM 0x0053d4a0
float TArmyMission::FitnessOf(TMilitaryUnit* candidateUnit, float* referenceVector) {
  if (static_cast<double>(candidateUnit->field_34) * 0.002 < 139069760.0) {
    if (!IsANoBrainer()) {
      return -1000.0f;
    }
  }

  short weightIndex = candidateUnit->GetTurnDistanceTo(GetPresentLocation());
  if (weightIndex > 5) {
    weightIndex = 5;
  }
  float baseline = g_ArmyMissionCandidateScoreTable_006978f8[weightIndex + state08 * 6];

  float vector[5] = {0.0f, 0.0f, 0.0f, 0.0f, 0.0f};
  AccumulateUnitOrderPriorityVectorContribution(
      candidateUnit, vector, 1.0f,
      static_cast<float>(g_pGlobalMapState->GetProvinceUnitOrderWeight(GetPresentLocation())));

  float total = 0.0f;
  for (int i = 0; i < 5; ++i) {
    total += vector[i];
  }
  if (total == 0.0f) {
    return -1000.0f;
  }

  float sumSquaredDiff = 0.0f;
  for (int j = 0; j < 5; ++j) {
    float diff = vector[j] / total - referenceVector[j];
    sumSquaredDiff += diff * diff;
  }
  return -(sumSquaredDiff + baseline);
}

// FUNCTION: IMPERIALISM 0x0053d630
TMission* TArmyMission::GetReplacementSlot48() {
  short tileOwnerNationCode =
      g_pGlobalMapState->ResolveTileOwnerNationCodeNormalized(presentLocation14);
  return (tileOwnerNationCode == nationId04) ? this : nullptr;
}
