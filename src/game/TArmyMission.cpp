// TArmyMission implementations.

#include <math.h>

#include "game/TArmyMission.h"
#include "game/TList.h"
#include "game/TGreatPower.h"
#include "game/TStream.h"
#include "game/TMapMgr.h"
#include "game/TMilitaryUnit.h"
#include "game/global_data_tables.h"
#include "game/ui_invalidation_guard.h"
#include "game/CIterator.h"

IMPLEMENT_SERIAL(TArmyMission, TMission, 1)

// FUNCTION: IMPERIALISM 0x005356f0
char TArmyMission::IsArmyMission() const {
  return 1;
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

// Default constructor
TArmyMission::TArmyMission() : TMission() {
  presentLocation14 = 0;
  padding_16 = 0;
  orderListAt18 = nullptr;
  for (int i = 0; i < 5; ++i) {
    requiredEquipageByClass[i] = 0.0f;
  }
}

// SYNTHETIC: IMPERIALISM 0x0053bfb0
// TArmyMission::CreateObject

// SYNTHETIC: IMPERIALISM 0x0053c030
// TArmyMission::GetRuntimeClass

// FUNCTION: IMPERIALISM 0x0053c0a0
TArmyMission::TArmyMission(int nodeKey) : TMission() {
  nationId04 = 0xffff;
  pathMarker06 = 0xffff;
  presentLocation14 = static_cast<short>(nodeKey);
  padding_16 = static_cast<short>(0xffff);

  TList* list = static_cast<TList*>(TList::CreateObject());
  orderListAt18 = list;
  if (list == nullptr) {
    MessageBoxA(nullptr, "Nil Pointer", "Failure", 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag("D:\\Ambit\\Cross\\UMissionSubs.cpp", 0x842);
  }

  for (int i = 0; i < 5; ++i) {
    requiredEquipageByClass[i] = 0.0f;
  }
}

// FUNCTION: IMPERIALISM 0x0053c1b0
char TArmyMission::IsANoBrainer() const {
  return 0;
}
// SYNTHETIC: IMPERIALISM 0x0053c1d0
// TArmyMission::`scalar deleting destructor'

// Swaps float byte order (Big-Endian <-> Little-Endian)
static inline float SwapFloat(float val) {
  union {
    float f;
    unsigned char b[4];
  } src, dst;
  src.f = val;
  dst.b[0] = src.b[3];
  dst.b[1] = src.b[2];
  dst.b[2] = src.b[1];
  dst.b[3] = src.b[0];
  return dst.f;
}

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
    short weightIndex = unit->IsNotStationedInProvince(GetPresentLocation());
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
  stream->WriteBytesSlot78(&presentLocation14, 2);
  for (int i = 0; i < 5; ++i) {
    float swapped = SwapFloat(requiredEquipageByClass[i]);
    stream->WriteBytesSlot78(&swapped, 4);
  }

  int count = (orderListAt18 != nullptr) ? orderListAt18->GetCount() : 0;
  stream->WriteCountSlot88(count);

  TGreatPower* nation = g_apNationStates[nationId04];
  TSortedList* unitList = reinterpret_cast<TSortedList*>(nation->militaryUnitList44);

  if (orderListAt18 != nullptr) {
    CIterator iter(orderListAt18);
    void* currentUnit = iter.Reset();
    while (iter.More()) {
      int index = 1;
      POSITION pos = unitList->listState.GetHeadPosition();
      while (pos != nullptr) {
        if (unitList->listState.GetNext(pos) == currentUnit) {
          break;
        }
        index++;
      }
      stream->WriteCountSlot88(index);
      currentUnit = iter.Advance();
    }
  }
}

// FUNCTION: IMPERIALISM 0x0053c3d0
void TArmyMission::ReadFrom(TStream* stream) {
  int saveFormatVersion = g_nSaveFormatVersion;

  TMission::ReadFrom(stream);
  stream->ReadBytes(&presentLocation14, 2);
  if (saveFormatVersion < 0xb) {
    stream->ReadBytes(&requiredEquipageByClass[0], 0x10);
    requiredEquipageByClass[4] = 0.0f;
  } else {
    stream->ReadBytes(&requiredEquipageByClass[0], 0x14);
    for (int i = 0; i < 5; ++i) {
      requiredEquipageByClass[i] = SwapFloat(requiredEquipageByClass[i]);
    }
  }

  short count = stream->ReadShort();
  TGreatPower* nation = g_apNationStates[nationId04];
  TSortedList* unitList = reinterpret_cast<TSortedList*>(nation->militaryUnitList44);

  for (int i = 0; i < count; ++i) {
    short index = stream->ReadShort();
    void* unit = unitList->GetEntryByOrdinal(index);
    if (orderListAt18 != nullptr) {
      orderListAt18->AddTail(unit);
    }
  }
}

// FUNCTION: IMPERIALISM 0x0053c4f0
char TArmyMission::ReturnFalseSlot98() {
  if (orderListAt18 != nullptr) {
    CIterator iter(orderListAt18);
    void* item = iter.Reset();
    while (iter.More()) {
      TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(item);
      short movementClass = unit->GetUnitMovementClassId();
      if (movementClass != 0) {
        NoOpSlot88(unit, 1);
      }
      item = iter.Advance();
    }
  }
  return 1;
}

// FUNCTION: IMPERIALISM 0x0053c570
void TArmyMission::NoOpSlot80(TMilitaryUnit* unit, int notify) {
  unit->TObject::AssertValid();
  TMission* owner = unit->ownerMission40;
  if (owner != nullptr) {
    owner->NoOpSlot88(unit, notify);
  }
  unit->ownerMission40 = this;
  orderListAt18->AddHead(unit);
  if (static_cast<char>(notify) != 0) {
    Reassess();
  }
}

// FUNCTION: IMPERIALISM 0x0053c5e0
void TArmyMission::NoOpSlot88(TMilitaryUnit* unit, int unused) {
  (void)unused;
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
    short weightIndex = unit->IsNotStationedInProvince(GetPresentLocation());
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
    if (targetTile == -1 || unit->MatchesTargetTileOrBypass(bypassTileFilter, targetTile)) {
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
  short weightIndex = unit->IsNotStationedInProvince(GetPresentLocation());
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
  short stat5 = unit->GetUnitTypeStatPercent(5);
  short strength = unit->field_34;
  float dampen = 1.0f - static_cast<float>(stat5) * weight * -0.0001f;
  scale = static_cast<float>(strength) * 0.002f *
          (1.0f - static_cast<float>(static_cast<short>(quality / 100)) * -0.1f) * scale;
  vector[0] = vector[0] - static_cast<float>(strength) * -0.002f *
                              static_cast<float>(unit->GetUnitTypeStatPercent(0)) * scale * dampen;
  vector[1] = static_cast<float>(unit->GetUnitTypeStatPercent(1)) * scale * dampen + vector[1];
  vector[2] = static_cast<float>(unit->GetUnitTypeStatPercent(2)) * scale + vector[2];
  vector[3] = static_cast<float>(unit->GetUnitTypeStatPercent(3)) * scale + vector[3];
  vector[4] = static_cast<float>(unit->GetUnitTypeStatPercent(4)) * scale * dampen + vector[4];
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
    short weightIndex = unit->IsNotStationedInProvince(GetPresentLocation());
    if (weightIndex > 5) {
      weightIndex = 5;
    }
    AccumulateUnitOrderPriorityVectorContribution(
        unit, vector, g_MissionOrderDistanceDecayWeightTable_006978c8[weightIndex],
        static_cast<float>(g_pGlobalMapState->GetProvinceUnitOrderWeight(GetPresentLocation())));
  }
}

// FUNCTION: IMPERIALISM 0x0053ceb0
float TArmyMission::ReturnZeroFloatSlot68() {
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

  short weightIndex = candidateUnit->IsNotStationedInProvince(GetPresentLocation());
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

  short weightIndex = candidateUnit->IsNotStationedInProvince(GetPresentLocation());
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
float TArmyMission::ReturnZeroFloatSlot6C() {
  double total = 0.0;
  for (int i = 0; i < 5; ++i) {
    total += static_cast<double>(requiredEquipageByClass[i]) *
             static_cast<double>(g_ArmyMissionDotProductWeights_00697980[i]);
  }
  return static_cast<float>(total);
}

// FUNCTION: IMPERIALISM 0x0053d420
float TArmyMission::ReturnZeroFloatSlot70(TMilitaryUnit* candidateUnit) {
  if (flag10 != 0) {
    return g_Recompute_Nation_Order_LookupTable_0065A9E8;
  }

  if (candidateUnit->ownerMission40 == this) {
    float ownScore = ReturnZeroFloatSlot68();
    return ownScore - ComputeArmyMissionScoreDeltaWithScaledCandidateUnit(candidateUnit);
  }
  float withCandidate = ComputeArmyMissionScoreDeltaWithCandidateUnit(candidateUnit);
  return withCandidate - ReturnZeroFloatSlot68();
}

// FUNCTION: IMPERIALISM 0x0053d4a0
float TArmyMission::ReturnZeroFloatSlot78(TMilitaryUnit* candidateUnit, float* referenceVector) {
  if (static_cast<double>(candidateUnit->field_34) * 0.002 < 139069760.0) {
    if (!IsANoBrainer()) {
      return -1000.0f;
    }
  }

  short weightIndex = candidateUnit->IsNotStationedInProvince(GetPresentLocation());
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
