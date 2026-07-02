// TNavyMission implementations.

#include <math.h>

#include "game/TNavyMission.h"
#include "game/TStream.h"
#include "game/TList.h"
#include "game/TZone.h"
#include "game/TShip.h"
#include "game/TDiplomacyMgr.h"
#include "game/TMapOrderEntry.h"
#include "game/global_data_tables.h"

IMPLEMENT_SERIAL(TNavyMission, TMission, 1)

extern "C" {
extern const float g_Recompute_Nation_Order_LookupTable_0065A9E8;
extern const double g_Recompute_Nation_Order_LookupTable_0065A9F0;
extern double g_Recompute_Nation_Order_LookupTable_0065A9F8;
extern double g_Recompute_Nation_Order_LookupTable_0065AA00;
extern double g_Recompute_Nation_Order_LookupTable_0065AA08;
extern unsigned short g_Populate_Beachhead_Mission_LookupTable_00697958[];
extern const float g_ArmyMissionOrderWeightTable_006978c8[6];
extern const float g_ArmyMissionCandidateScoreTable_006978f8[];
}

// Not-yet-recovered free functions this file calls into (generic stub
// signature per the autogen stub definition; real signature applied via a
// typed cast at each call site so the linker resolves the correct symbol).
extern undefined4 FindMapActionContextByNodeId(void);
extern undefined4 GetNavyPrimaryOrderNodeByIndex(void);
extern undefined4 FindFirstTrackedHandlerMatchingModeAndShortKey(void);
extern undefined4 CompareMissionOrderEntriesByPriorityScore(void);
extern undefined4 ComputeOrderNodeDistanceQuotientByDescriptorWord24(void);
extern undefined4 GetOrCreateMissionOrderEntryForNode(void);
extern undefined4 SetMapOrderType9AndQueue(void);
extern undefined4 PromoteMapOrderChainAndQueue(void);
extern undefined4 SelectBestMapActionContextForNationDiplomacyMask(void);
extern undefined4 AccumulateNavyOrderCategoryVectorWithScale(void);
extern undefined4 BuildNavyOrderCategoryVectorForNationWithExclusion(void);
extern undefined4 IsZoneMaskOrArrayEntryPresentForKey(void);

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

// FUNCTION: IMPERIALISM 0x00535470
TNavyMission::TNavyMission(TZone* targetZone) : TMission() {
  nationId04 = 0xffff;
  pathMarker06 = 0xffff;
  targetZone14 = targetZone;
  targetZone18 = nullptr;
  navyField1c = 0;
  navyField20 = nullptr;
  orderList24 = nullptr;
  navyField28 = 0.0f;
  for (int i = 0; i < 4; ++i) {
    resourceWeights2c[i] = 0.0f;
  }
}

// FUNCTION: IMPERIALISM 0x005354c0
void TNavyMission::NoOpSlot9C() {}

// FUNCTION: IMPERIALISM 0x005354e0
char TNavyMission::ReturnFalseSlot54() {
  return 1;
}

// FUNCTION: IMPERIALISM 0x00535500
char TNavyMission::ReturnFalseSlot28() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00535520
int TNavyMission::ReturnZeroSlot58() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00535540
int TNavyMission::ReturnZeroSlot5C() {
  return reinterpret_cast<int>(this);
}

// FUNCTION: IMPERIALISM 0x00536390
TMission* CreateTNavyMission() {
  return new TNavyMission();
}

namespace {

float NormalizeFourComponentNavyVector(const float* vector, float sum) {
  if (sum == static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065A9F0)) {
    return g_Recompute_Nation_Order_LookupTable_0065A9E8;
  }
  const unsigned short* lookupTable = g_Populate_Beachhead_Mission_LookupTable_00697958;
  float accum = g_Recompute_Nation_Order_LookupTable_0065A9E8;
  for (int componentIndex = 0; componentIndex < 4; ++componentIndex) {
    float diff = vector[componentIndex] / sum -
                 static_cast<float>(static_cast<short>(lookupTable[componentIndex])) *
                     static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065A9F8);
    if (diff <= static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065A9F0)) {
      diff = -diff;
    }
    accum += diff;
  }
  return sum * (static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065AA08) -
                accum * static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065AA00));
}

void AccumulateNavyOrderVectorFromNode(TShip* orderNode, float* vector) {
  short normalizationBase = orderNode->GetNavyOrderNormalizationBaseByNationType();
  if (normalizationBase == 0) {
    return;
  }
  float scale = static_cast<float>(orderNode->stockLevel1c) / static_cast<float>(normalizationBase);
  int category = static_cast<int>(orderNode->stockLevel1c % normalizationBase);

  for (int componentIndex = 0; componentIndex < 4; ++componentIndex) {
    int contribution = orderNode->ComputeNavyOrderPriorityContributionPercentByCategory(category);
    if (componentIndex < 3) {
      vector[componentIndex] += static_cast<float>(contribution) * scale;
    } else {
      vector[componentIndex] += static_cast<float>(contribution);
    }
    category = contribution;
  }
}

} // namespace

// FUNCTION: IMPERIALISM 0x005364c0
void TNavyMission::Free() {
  if (navyField20 != nullptr) {
    navyField20->Free();
  }
  navyField20 = nullptr;

  while (orderList24 != nullptr) {
    orderList24->object_ptr = nullptr;
    orderList24 = TMapOrderEntry::DeleteMapOrderChildLinkAndReturnNext(orderList24);
  }

  if (this != nullptr) {
    delete this;
  }
}

// FUNCTION: IMPERIALISM 0x00536530
void TNavyMission::WriteTo(TStream* stream) {
  TMission::WriteTo(stream);

  int nodeIdx1 = -1;
  if (targetZone14 != nullptr) {
    nodeIdx1 = targetZone14->GetContextOrdinalOrInvalid();
  }
  stream->WriteCountSlot88(nodeIdx1);

  int nodeIdx2 = -1;
  if (targetZone18 != nullptr) {
    nodeIdx2 = targetZone18->GetContextOrdinalOrInvalid();
  }
  stream->WriteCountSlot88(nodeIdx2);

  for (int i = 0; i < 4; ++i) {
    float swapped = SwapFloat(resourceWeights2c[i]);
    stream->WriteBytesSlot78(&swapped, 4);
  }

  // orderList24 payloads are TShip nodes in this class (see TShip class recovery);
  // TMapOrderChildLinkNode::object_ptr is typed TMapOrderEntry* for the (more common)
  // army-mission usage of this shared node type.
  for (TMapOrderChildLinkNode* node = orderList24; node != nullptr; node = node->next) {
    int idx = reinterpret_cast<TShip*>(node->object_ptr)->GetIndexInPrimaryOrderList();
    stream->WriteCountSlot88(idx);
  }
  stream->WriteCountSlot88(-1);

  stream->WriteBytesSlot78(&navyField28, 4);
}

// FUNCTION: IMPERIALISM 0x00536650
void TNavyMission::ReadFrom(TStream* stream) {
  TMission::ReadFrom(stream);

  typedef int(__cdecl * FindMapActionContextByNodeId_t)(int id);
  FindMapActionContextByNodeId_t FindMapActionContextByNodeId_fn =
      reinterpret_cast<FindMapActionContextByNodeId_t>(
          (void*)&FindMapActionContextByNodeId); // at 0x55f100

  int id1 = stream->ReadInteger();
  targetZone14 = reinterpret_cast<TZone*>(FindMapActionContextByNodeId_fn(id1));

  int id2 = stream->ReadInteger();
  targetZone18 = reinterpret_cast<TZone*>(FindMapActionContextByNodeId_fn(id2));

  stream->ReadBytes(&resourceWeights2c[0], 0x10);
  for (int i = 0; i < 4; ++i) {
    resourceWeights2c[i] = SwapFloat(resourceWeights2c[i]);
  }

  typedef void*(__cdecl * GetNavyPrimaryOrderNodeByIndex_t)(int index, int unused);
  GetNavyPrimaryOrderNodeByIndex_t GetNavyPrimaryOrderNodeByIndex_fn =
      reinterpret_cast<GetNavyPrimaryOrderNodeByIndex_t>(
          (void*)&GetNavyPrimaryOrderNodeByIndex); // at 0x550640

  short nodeIdx = stream->ReadShort();
  if (nodeIdx > -1) {
    do {
      void* orderNode = GetNavyPrimaryOrderNodeByIndex_fn(nodeIdx, 0);
      NoOpSlot84(reinterpret_cast<int>(orderNode), 0);
      nodeIdx = stream->ReadShort();
    } while (nodeIdx >= 0);
  }

  stream->ReadBytes(&navyField28, 4);
  navyField1c = 0;
  if (navyField20 != nullptr) {
    navyField20->Free();
  }
  navyField20 = nullptr;
}

// FUNCTION: IMPERIALISM 0x00536740
char TNavyMission::ReturnFalseSlot98() {
  while (orderList24 != nullptr) {
    orderList24->object_ptr = nullptr;
    orderList24 = TMapOrderEntry::DeleteMapOrderChildLinkAndReturnNext(orderList24);
  }
  return 1;
}

// FUNCTION: IMPERIALISM 0x00536780
void TNavyMission::NoOpSlot84(int a, int b) {
  TMapOrderEntry* item = reinterpret_cast<TMapOrderEntry*>(a);
  TMission*& owner = *reinterpret_cast<TMission**>(reinterpret_cast<char*>(item) + 0x2c);
  if (owner != nullptr) {
    owner->NoOpSlot8C(a, b);
  }
  owner = this;
  TMapOrderChildLinkNode* node = TMapOrderEntry::CreateLinkedOrderNode(orderList24, item);
  orderList24 = node;
  if (static_cast<char>(b) != 0) {
    RefreshSlot40();
  }
}

// FUNCTION: IMPERIALISM 0x005367d0
void TNavyMission::NoOpSlot8C(int a, int b) {
  (void)b;
  TMapOrderEntry* item = reinterpret_cast<TMapOrderEntry*>(a);
  if (orderList24 != nullptr) {
    if (orderList24->object_ptr == item) {
      orderList24 = TMapOrderEntry::DeleteMapOrderChildLinkAndReturnNext(orderList24);
    } else {
      TMapOrderEntry::RemoveLinkedOrderNodeByValueRecursive(orderList24->next, item);
    }
  }
  *reinterpret_cast<int*>(reinterpret_cast<char*>(item) + 0x2c) = 0;
  if (navyField1c == a) {
    navyField1c = 0;
  }
}

// FUNCTION: IMPERIALISM 0x00536810
void TNavyMission::NoOpSlot90(int a) {
  if (reinterpret_cast<int>(navyField20) == a) {
    navyField20 = nullptr;
  }
}
// FUNCTION: IMPERIALISM 0x00536840
int TNavyMission::ReturnZeroSlot2C(int* outBuffer, int unused) {
  (void)unused;
  for (TMapOrderChildLinkNode* node = orderList24; node != nullptr; node = node->next) {
    TMapOrderEntry* entry = node->object_ptr;
    for (int category = 0; category < 4; ++category) {
      ComputeNavyOrderPriorityContributionPercentByCategory(
          entry->order_type, entry->required_count, entry->tiebreak_strength, category);
    }
    GetNavyOrderNormalizationBaseByResourceType(entry->order_type);
  }

  int total = 0;
  for (int i = 0; i < 4; ++i) {
    int rounded = static_cast<int>(resourceWeights2c[i]);
    outBuffer[i] = rounded;
    total += rounded;
  }
  return total;
}

// FUNCTION: IMPERIALISM 0x00536b30
void TNavyMission::RefreshSlot40() {
  // navyField28 is dual-purposed here as a raw selection-mode int (0/1/2);
  // GetMissionOrderBudgetByMode reads the same field as a float. Access via
  // a bit-reinterpreting pointer to avoid a numeric float<->int conversion.
  int* modeSlot = reinterpret_cast<int*>(&navyField28);

  SetStateByte8To2();
  ResetValue0CToZero();
  NoOpSlot3C();

  typedef void(__fastcall * IsZoneMaskOrArrayEntryPresentForKey_t)(short);
  IsZoneMaskOrArrayEntryPresentForKey_t IsZoneMaskOrArrayEntryPresentForKey_fn =
      reinterpret_cast<IsZoneMaskOrArrayEntryPresentForKey_t>(
          (void*)&IsZoneMaskOrArrayEntryPresentForKey);
  IsZoneMaskOrArrayEntryPresentForKey_fn(pathMarker06);

  if (orderList24 == nullptr) {
    *modeSlot = 0;
    return;
  }

  int mode = *modeSlot;
  if (mode == 0) {
    if (1.0f <= ComputeNavyOrderCategorySimilarityRatio(1)) {
      if (1.0f <= ComputeNavyOrderCategorySimilarityRatio(0)) {
        *modeSlot = 2;
        return;
      }
      *modeSlot = 1;
    }
  } else if (mode == 1) {
    *modeSlot = 2;
  } else if (mode == 2) {
    if (ComputeNavyOrderCategorySimilarityRatio(1) < 0.8f) {
      *modeSlot = 0;
      navyField20 = static_cast<TObject*>(GetReplacementSlot48());
    }
  }
}

// Shared helper for RefreshSlot40 (0x536b30's inlined similarity-ratio computation).
float TNavyMission::ComputeNavyOrderCategorySimilarityRatio(int excludeCurrent) {
  typedef void(__fastcall * BuildNavyOrderCategoryVectorForNationWithExclusion_t)(float*, TZone*,
                                                                                  int, TObject*);
  BuildNavyOrderCategoryVectorForNationWithExclusion_t
      BuildNavyOrderCategoryVectorForNationWithExclusion_fn =
          reinterpret_cast<BuildNavyOrderCategoryVectorForNationWithExclusion_t>(
              (void*)&BuildNavyOrderCategoryVectorForNationWithExclusion);

  float vector[4];
  BuildNavyOrderCategoryVectorForNationWithExclusion_fn(vector, targetZone14, excludeCurrent,
                                                        navyField20);
  float numerator = 0.0f;
  float denominator = 0.0f;
  for (int i = 0; i < 4; ++i) {
    numerator += sqrtf(resourceWeights2c[i] * vector[i]);
    denominator += resourceWeights2c[i];
  }
  return numerator / denominator;
}

// FUNCTION: IMPERIALISM 0x00536e40
void TNavyMission::MissionSlot44() {}

// FUNCTION: IMPERIALISM 0x00536fa0
void TNavyMission::RefreshMissionPortZoneContextForNation() {
  typedef void(__fastcall * SelectBestMapActionContextForNationDiplomacyMask_t)(int);
  SelectBestMapActionContextForNationDiplomacyMask_t
      SelectBestMapActionContextForNationDiplomacyMask_fn =
          reinterpret_cast<SelectBestMapActionContextForNationDiplomacyMask_t>(
              (void*)&SelectBestMapActionContextForNationDiplomacyMask);
  SelectBestMapActionContextForNationDiplomacyMask_fn(nationId04);
}

// FUNCTION: IMPERIALISM 0x00536fc0
TMission* TNavyMission::GetReplacementSlot48() {
  if (targetZone18 != nullptr) {
    if (targetZone18->QueryPortZoneCapability() != 0) {
      if (targetZone18->QueryZoneCapabilityFlagD(nationId04) == 0) {
        targetZone18 = reinterpret_cast<TZone*>(GetReplacementSlot48());
      }
    }
  }
  return (targetZone18 != nullptr) ? this : nullptr;
}

// FUNCTION: IMPERIALISM 0x00537060
int TNavyMission::GetMissionOrderBudgetByMode(int mode) {
  int modeVal = static_cast<int>(navyField28);
  if (modeVal == 0) {
    return reinterpret_cast<int>(targetZone18);
  }
  if (modeVal > 0 && modeVal < 3) {
    return reinterpret_cast<int>(targetZone14);
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x00537090
void TNavyMission::QueueMissionOrdersByPriorityForContext(int pContextAnchor,
                                                          int* ppSelectedChildNode) {
  typedef void*(__cdecl * FindFirstTrackedHandlerMatchingModeAndShortKey_t)(void*, int);
  FindFirstTrackedHandlerMatchingModeAndShortKey_t
      FindFirstTrackedHandlerMatchingModeAndShortKey_fn =
          reinterpret_cast<FindFirstTrackedHandlerMatchingModeAndShortKey_t>(
              (void*)&FindFirstTrackedHandlerMatchingModeAndShortKey);

  if ((*ppSelectedChildNode != 0) && (FindFirstTrackedHandlerMatchingModeAndShortKey_fn(
                                          orderList24, *ppSelectedChildNode) == nullptr)) {
    *ppSelectedChildNode = 0;
  }

  void* topOrder = nullptr;
  int maxScore = -1;

  typedef int(__cdecl * CompareMissionOrderEntriesByPriorityScore_t)(void*, int);
  CompareMissionOrderEntriesByPriorityScore_t CompareMissionOrderEntriesByPriorityScore_fn =
      reinterpret_cast<CompareMissionOrderEntriesByPriorityScore_t>(
          (void*)&CompareMissionOrderEntriesByPriorityScore);

  for (TMapOrderChildLinkNode* node = orderList24; node != nullptr; node = node->next) {
    int score = CompareMissionOrderEntriesByPriorityScore_fn(node->object_ptr, 3);
    if (maxScore < score) {
      topOrder = node->object_ptr;
      maxScore = score;
    }
  }

  void* selectedOrder = reinterpret_cast<void*>(*ppSelectedChildNode);

  if (topOrder != nullptr) {
    if (topOrder == selectedOrder) {
      topOrder = nullptr;
    } else {
      if (selectedOrder != nullptr) {
        typedef short(__fastcall * ComputeOrderNodeDistanceQuotientByDescriptorWord24_t)(void*);
        ComputeOrderNodeDistanceQuotientByDescriptorWord24_t
            ComputeOrderNodeDistanceQuotientByDescriptorWord24_fn =
                reinterpret_cast<ComputeOrderNodeDistanceQuotientByDescriptorWord24_t>(
                    (void*)&ComputeOrderNodeDistanceQuotientByDescriptorWord24);
        short target1 = ComputeOrderNodeDistanceQuotientByDescriptorWord24_fn(targetZone14);
        short target2 = ComputeOrderNodeDistanceQuotientByDescriptorWord24_fn(topOrder);
        if (target1 < target2) {
          goto LAB_0053711a;
        }
      }
      *ppSelectedChildNode = reinterpret_cast<int>(topOrder);
      topOrder = nullptr;
    }
  }

LAB_0053711a:
  void* startOrder = reinterpret_cast<void*>(*ppSelectedChildNode);
  void* orders[2] = {startOrder, topOrder};

  typedef void*(__fastcall * GetOrCreateMissionOrderEntryForNode_t)(void* self, int dummyEdx);
  GetOrCreateMissionOrderEntryForNode_t GetOrCreateMissionOrderEntryForNode_fn =
      reinterpret_cast<GetOrCreateMissionOrderEntryForNode_t>(
          (void*)&GetOrCreateMissionOrderEntryForNode);
  typedef void(__fastcall * SetMapOrderType9AndQueue_t)(void*);
  SetMapOrderType9AndQueue_t SetMapOrderType9AndQueue_fn =
      reinterpret_cast<SetMapOrderType9AndQueue_t>((void*)&SetMapOrderType9AndQueue);
  typedef void(__fastcall * PromoteMapOrderChainAndQueue_t)(void*, void*);
  PromoteMapOrderChainAndQueue_t PromoteMapOrderChainAndQueue_fn =
      reinterpret_cast<PromoteMapOrderChainAndQueue_t>((void*)&PromoteMapOrderChainAndQueue);

  for (int i = 0; i < 2; ++i) {
    void* orderObj = orders[i];
    if (orderObj == nullptr)
      continue;
    if (i == 1 && orderObj == startOrder)
      continue;

    void* nodePtr = FindFirstTrackedHandlerMatchingModeAndShortKey_fn(
        orderList24, reinterpret_cast<int>(orderObj));
    *reinterpret_cast<char*>(reinterpret_cast<char*>(nodePtr) + 0xc) = 1;
    void* entry = GetOrCreateMissionOrderEntryForNode_fn(orderObj, 0);

    if (*reinterpret_cast<int*>(reinterpret_cast<char*>(orderObj) + 8) == pContextAnchor) {
      SetMapOrderType9AndQueue_fn(entry);
    } else {
      PromoteMapOrderChainAndQueue_fn(entry, reinterpret_cast<void*>(pContextAnchor));
    }
  }
}

// FUNCTION: IMPERIALISM 0x005371d0
void TNavyMission::ConsolidateMissionOrderEntriesByTargetAndQueue(int* pContextAnchor) {
  typedef void*(__fastcall * GetOrCreateMissionOrderEntryForNode_t)(void* self, int dummyEdx);
  GetOrCreateMissionOrderEntryForNode_t GetOrCreateMissionOrderEntryForNode_fn =
      reinterpret_cast<GetOrCreateMissionOrderEntryForNode_t>(
          (void*)&GetOrCreateMissionOrderEntryForNode);
  typedef void(__fastcall * PromoteMapOrderChainAndQueue_t)(void*, void*);
  PromoteMapOrderChainAndQueue_t PromoteMapOrderChainAndQueue_fn =
      reinterpret_cast<PromoteMapOrderChainAndQueue_t>((void*)&PromoteMapOrderChainAndQueue);

  for (TMapOrderChildLinkNode* node = orderList24; node != nullptr; node = node->next) {
    if (node->active_flag == 0) {
      node->active_flag = 1;
      void* entry = GetOrCreateMissionOrderEntryForNode_fn(node->object_ptr, 0);
      for (TMapOrderChildLinkNode* other = orderList24; other != nullptr; other = other->next) {
        if (other->active_flag == 0 &&
            *reinterpret_cast<int*>(reinterpret_cast<char*>(other->object_ptr) + 8) ==
                *reinterpret_cast<int*>(reinterpret_cast<char*>(entry) + 0x18)) {
          static_cast<TMapOrderEntry*>(other->object_ptr)->RemoveNode(reinterpret_cast<int>(entry));
          other->active_flag = 1;
        }
      }
      PromoteMapOrderChainAndQueue_fn(entry, pContextAnchor);
    }
  }
}

// FUNCTION: IMPERIALISM 0x00537270
float TNavyMission::ReturnZeroFloatSlot74() {
  return 0.0f;
}

// FUNCTION: IMPERIALISM 0x00537610
float TNavyMission::ReturnZeroFloatSlot7C() {
  return 0.0f;
}

// FUNCTION: IMPERIALISM 0x005378c0
float TNavyMission::ReturnZeroFloatSlot6C() {
  double total = 0.0;
  for (int i = 0; i < 4; ++i) {
    total += static_cast<double>(resourceWeights2c[i]);
  }
  return static_cast<float>(total);
}

// FUNCTION: IMPERIALISM 0x00537f40
float TNavyMission::ReturnZeroFloatSlot68() {
  return 0.0f;
}

// FUNCTION: IMPERIALISM 0x005389f0
float TNavyMission::ComputeOrderDistributionSimilarityScoreWithDiplomacyFilter(int sourceNation,
                                                                               TZone* nodeContext) {
  float vector[4] = {0.0f, 0.0f, 0.0f, 0.0f};
  for (TShip* orderNode = GetNavyPrimaryOrderListHead(); orderNode != 0;
       orderNode = orderNode->nextOlder24) {
    if (orderNode->field08 == nodeContext &&
        g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(
            static_cast<short>(sourceNation), orderNode->ownerNationSlot14) != 0) {
      AccumulateNavyOrderVectorFromNode(orderNode, vector);
    }
  }
  float sum = g_Recompute_Nation_Order_LookupTable_0065A9E8;
  for (int componentIndex = 0; componentIndex < 4; ++componentIndex) {
    sum += vector[componentIndex];
  }
  return NormalizeFourComponentNavyVector(vector, sum);
}

// FUNCTION: IMPERIALISM 0x00538bf0
float TNavyMission::ComputeOrderDistributionSimilarityScoreForExactSourceNation(
    int sourceNation, TZone* nodeContext) {
  float vector[4] = {0.0f, 0.0f, 0.0f, 0.0f};
  for (TShip* orderNode = GetNavyPrimaryOrderListHead(); orderNode != 0;
       orderNode = orderNode->nextOlder24) {
    if (orderNode->field08 == nodeContext &&
        static_cast<short>(sourceNation) == orderNode->ownerNationSlot14) {
      AccumulateNavyOrderVectorFromNode(orderNode, vector);
    }
  }
  float sum = g_Recompute_Nation_Order_LookupTable_0065A9E8;
  for (int componentIndex = 0; componentIndex < 4; ++componentIndex) {
    sum += vector[componentIndex];
  }
  return NormalizeFourComponentNavyVector(vector, sum);
}

// Default constructor
TNavyMission::TNavyMission() : TMission() {
  targetZone14 = nullptr;
  targetZone18 = nullptr;
  navyField1c = 0;
  navyField20 = nullptr;
  orderList24 = nullptr;
  navyField28 = 0.0f;
  for (int i = 0; i < 4; ++i) {
    resourceWeights2c[i] = 0.0f;
  }
}
