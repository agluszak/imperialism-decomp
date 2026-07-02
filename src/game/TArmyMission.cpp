// TArmyMission implementations.

#include <math.h>

#include "game/TArmyMission.h"
#include "game/TList.h"
#include "game/TGreatPower.h"
#include "game/TStream.h"
#include "game/TStationedUnitNode.h"
#include "game/global_data_tables.h"
#include "game/ui_invalidation_guard.h"
#include "game/CIterator.h"

IMPLEMENT_SERIAL(TArmyMission, TMission, 1)

// SYNTHETIC: IMPERIALISM 0x0053c030
// TArmyMission::GetRuntimeClass
// SYNTHETIC: IMPERIALISM 0x0053c1d0
// TArmyMission::`scalar deleting destructor'

// Not-yet-recovered free functions this file calls into (generic stub
// signature per the autogen stub definition; real signature applied via a
// typed cast at each call site so the linker resolves the correct symbol).
extern undefined4 GetTileNormalizedMovementClassId(void);
extern undefined4 AccumulateUnitOrderPriorityVectorContribution(void);
extern undefined4 ComputeArmyMissionScoreDeltaWithCandidateUnit(void);
extern undefined4 ComputeArmyMissionScoreDeltaWithScaledCandidateUnit(void);

// Nation-order priority weight/scoring tables (shared with the DefendProvince /
// Navy mission scoring family; not yet individually catalogued by field).
extern "C" {
extern const float g_ArmyMissionOrderWeightTable_006978c8[6];
extern const float g_ArmyMissionDotProductWeights_00697980[5];
extern const float g_ArmyMissionCandidateScoreTable_006978f8[];
}

namespace {

// Order-list items (orderListAt18) are a not-yet-recovered mission/order
// subtype whose instance size exceeds every currently-modelled mission class;
// only its owner back-pointer at +0x40 is known (cleared in Free()/NoOpSlot88,
// set in NoOpSlot80). Real type/name TBD via further class recovery.
struct TArmyMissionOrderItemLayout {
  char pad_00[0x40];
  TMission* owner; // +0x40
};

TMission*& OwnerOf(TMission* item) {
  return reinterpret_cast<TArmyMissionOrderItemLayout*>(item)->owner;
}

} // namespace

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

// Shared accumulation loop over orderListAt18 (0x53c620 / 0x53ceb0 both repeat
// this exact per-unit vector-contribution pattern).
void TArmyMission::AccumulateOrderPriorityVector(float* vector) {
  typedef void(__cdecl * AccumulateUnitOrderPriorityVectorContribution_t)(int, float*, float,
                                                                          float);
  AccumulateUnitOrderPriorityVectorContribution_t AccumulateUnitOrderPriorityVectorContribution_fn =
      reinterpret_cast<AccumulateUnitOrderPriorityVectorContribution_t>(
          (void*)&AccumulateUnitOrderPriorityVectorContribution);

  if (orderListAt18 == nullptr) {
    return;
  }
  CIterator iter(orderListAt18);
  for (void* unit = iter.Reset(); iter.More(); unit = iter.Advance()) {
    static_cast<TObject*>(unit)->AssertValid();
    short contextId = GetMissionTargetContextIdFromField14();
    short weightIndex = (pathMarker06 != contextId) ? 1 : 0;
    if (weightIndex > 5) {
      weightIndex = 5;
    }
    float scale = g_ArmyMissionOrderWeightTable_006978c8[weightIndex];
    AccumulateUnitOrderPriorityVectorContribution_fn(reinterpret_cast<int>(unit), vector, scale,
                                                     33.0f);
  }
}

// FUNCTION: IMPERIALISM 0x005356f0
char TArmyMission::ReturnFalseSlot50() {
  return 1;
}

// FUNCTION: IMPERIALISM 0x00535710
int TArmyMission::ReturnZeroSlot58() {
  return reinterpret_cast<int>(this);
}

// FUNCTION: IMPERIALISM 0x00535730
int TArmyMission::ReturnZeroSlot5C() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00535750
short TArmyMission::GetMissionTargetContextIdFromField14() {
  return field_14;
}

// Default constructor
TArmyMission::TArmyMission() : TMission() {
  field_14 = 0;
  padding_16 = 0;
  orderListAt18 = nullptr;
  for (int i = 0; i < 5; ++i) {
    resourceWeights[i] = 0.0f;
  }
}

// FUNCTION: IMPERIALISM 0x0053c0a0
TArmyMission::TArmyMission(int nodeKey) : TMission() {
  nationId04 = 0xffff;
  pathMarker06 = 0xffff;
  field_14 = static_cast<short>(nodeKey);
  padding_16 = static_cast<short>(0xffff);

  TList* list = TList::CreateTListInstance();
  orderListAt18 = list;
  if (list == nullptr) {
    MessageBoxA(nullptr, "Nil Pointer", "Failure", 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag("D:\\Ambit\\Cross\\UMissionSubs.cpp", 0x842);
  }

  for (int i = 0; i < 5; ++i) {
    resourceWeights[i] = 0.0f;
  }
}

// FUNCTION: IMPERIALISM 0x0053c1b0
char TArmyMission::ReturnFalseSlot28() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0053c220
void TArmyMission::Free() {
  if (orderListAt18 != nullptr) {
    CIterator iter(orderListAt18);
    void* current = iter.Reset();
    while (iter.More()) {
      OwnerOf(static_cast<TMission*>(current)) = nullptr;
      current = iter.Advance();
    }

    orderListAt18->RemoveAllSlot5C();
    orderListAt18->FreePayloadsAndDestroySlot58();
    orderListAt18 = nullptr;
  }

  if (this != nullptr) {
    delete this;
  }
}

// FUNCTION: IMPERIALISM 0x0053c2b0
void TArmyMission::WriteTo(TStream* stream) {
  TMission::WriteTo(stream);
  stream->WriteBytesSlot78(&field_14, 2);
  for (int i = 0; i < 5; ++i) {
    float swapped = SwapFloat(resourceWeights[i]);
    stream->WriteBytesSlot78(&swapped, 4);
  }

  int count = (orderListAt18 != nullptr) ? orderListAt18->GetCountSlot48() : 0;
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
  stream->ReadBytes(&field_14, 2);
  if (saveFormatVersion < 0xb) {
    stream->ReadBytes(&resourceWeights[0], 0x10);
    resourceWeights[4] = 0.0f;
  } else {
    stream->ReadBytes(&resourceWeights[0], 0x14);
    for (int i = 0; i < 5; ++i) {
      resourceWeights[i] = SwapFloat(resourceWeights[i]);
    }
  }

  short count = stream->ReadShort();
  TGreatPower* nation = g_apNationStates[nationId04];
  TSortedList* unitList = reinterpret_cast<TSortedList*>(nation->militaryUnitList44);

  for (int i = 0; i < count; ++i) {
    short index = stream->ReadShort();
    void* unit = unitList->GetEntryByOrdinalSlot4C(index);
    if (orderListAt18 != nullptr) {
      orderListAt18->AddTailSlot30(unit);
    }
  }
}

// FUNCTION: IMPERIALISM 0x0053c4f0
char TArmyMission::ReturnFalseSlot98() {
  if (orderListAt18 != nullptr) {
    CIterator iter(orderListAt18);
    void* unit = iter.Reset();
    while (iter.More()) {
      short movementClass = static_cast<TStationedUnitNode*>(unit)->GetUnitMovementClassId();
      if (movementClass != 0) {
        NoOpSlot88(static_cast<TMission*>(unit), 1);
      }
      unit = iter.Advance();
    }
  }
  return 1;
}

// FUNCTION: IMPERIALISM 0x0053c570
void TArmyMission::NoOpSlot80(TMission* item, int notify) {
  item->TObject::AssertValid();
  TMission*& owner = OwnerOf(item);
  if (owner != nullptr) {
    owner->NoOpSlot88(item, notify);
  }
  owner = this;
  orderListAt18->AddHeadSlot28(item);
  if (static_cast<char>(notify) != 0) {
    RefreshSlot40();
  }
}

// FUNCTION: IMPERIALISM 0x0053c5e0
void TArmyMission::NoOpSlot88(TMission* item, int unused) {
  (void)unused;
  if (orderListAt18 != nullptr) {
    POSITION pos = orderListAt18->listState.Find(item);
    if (pos != nullptr) {
      orderListAt18->listState.RemoveAt(pos);
    }
  }
  OwnerOf(item) = nullptr;
}

// FUNCTION: IMPERIALISM 0x0053c620
int TArmyMission::ReturnZeroSlot2C(int* outBuffer, int unused) {
  (void)unused;
  float vector[5] = {0.0f, 0.0f, 0.0f, 0.0f, 0.0f};
  AccumulateOrderPriorityVector(vector);

  int total = 0;
  for (int i = 0; i < 5; ++i) {
    int rounded = static_cast<int>(vector[i]);
    outBuffer[i] = rounded;
    total += rounded;
  }
  return total;
}

// FUNCTION: IMPERIALISM 0x0053ceb0
float TArmyMission::ReturnZeroFloatSlot68() {
  float vector[5] = {0.0f, 0.0f, 0.0f, 0.0f, 0.0f};
  AccumulateOrderPriorityVector(vector);

  double numerator = 0.0;
  double denominator = 0.0;
  for (int i = 0; i < 5; ++i) {
    float target = resourceWeights[i];
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
    total += static_cast<double>(resourceWeights[i]) *
             static_cast<double>(g_ArmyMissionDotProductWeights_00697980[i]);
  }
  return static_cast<float>(total);
}

// FUNCTION: IMPERIALISM 0x0053d420
float TArmyMission::ReturnZeroFloatSlot70(TMission* candidate) {
  if (flag10 != 0) {
    return 0.0f;
  }

  typedef float(__cdecl * ComputeArmyMissionScoreDeltaWithCandidateUnit_t)(TMission*);
  ComputeArmyMissionScoreDeltaWithCandidateUnit_t ComputeArmyMissionScoreDeltaWithCandidateUnit_fn =
      reinterpret_cast<ComputeArmyMissionScoreDeltaWithCandidateUnit_t>(
          (void*)&ComputeArmyMissionScoreDeltaWithCandidateUnit);
  typedef float(__cdecl * ComputeArmyMissionScoreDeltaWithScaledCandidateUnit_t)(TMission*);
  ComputeArmyMissionScoreDeltaWithScaledCandidateUnit_t
      ComputeArmyMissionScoreDeltaWithScaledCandidateUnit_fn =
          reinterpret_cast<ComputeArmyMissionScoreDeltaWithScaledCandidateUnit_t>(
              (void*)&ComputeArmyMissionScoreDeltaWithScaledCandidateUnit);

  if (OwnerOf(candidate) == this) {
    return ReturnZeroFloatSlot68() -
           ComputeArmyMissionScoreDeltaWithScaledCandidateUnit_fn(candidate);
  }
  return ComputeArmyMissionScoreDeltaWithCandidateUnit_fn(candidate) - ReturnZeroFloatSlot68();
}

// FUNCTION: IMPERIALISM 0x0053d4a0
float TArmyMission::ReturnZeroFloatSlot78(TMission* candidate, float* referenceVector) {
  short candidateField34 = *reinterpret_cast<short*>(reinterpret_cast<char*>(candidate) + 0x34);
  if (static_cast<double>(candidateField34) * 0.002 < 139069760.0) {
    if (!ReturnFalseSlot28()) {
      return -1000.0f;
    }
  }

  short contextId = GetMissionTargetContextIdFromField14();
  short weightIndex = (pathMarker06 != contextId) ? 1 : 0;
  if (weightIndex > 5) {
    weightIndex = 5;
  }
  float baseline = g_ArmyMissionCandidateScoreTable_006978f8[weightIndex + state08 * 6];

  float vector[5] = {0.0f, 0.0f, 0.0f, 0.0f, 0.0f};
  typedef void(__cdecl * AccumulateUnitOrderPriorityVectorContribution_t)(TMission*, float*, float,
                                                                          float);
  AccumulateUnitOrderPriorityVectorContribution_t AccumulateUnitOrderPriorityVectorContribution_fn =
      reinterpret_cast<AccumulateUnitOrderPriorityVectorContribution_t>(
          (void*)&AccumulateUnitOrderPriorityVectorContribution);
  AccumulateUnitOrderPriorityVectorContribution_fn(candidate, vector, 1.0f, 33.0f);

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
  typedef short(__cdecl * GetTileNormalizedMovementClassId_t)(int);
  GetTileNormalizedMovementClassId_t GetTileNormalizedMovementClassId_fn =
      reinterpret_cast<GetTileNormalizedMovementClassId_t>(
          (void*)&GetTileNormalizedMovementClassId);
  short movementClass = GetTileNormalizedMovementClassId_fn(field_14);
  return (movementClass == nationId04) ? this : nullptr;
}
