// TNavyMission implementations.

#include <math.h>

#include "game/TNavyMission.h"
#include "game/TStream.h"
#include "game/TList.h"
#include "game/TZone.h"
#include "game/TShip.h"
#include "game/TDiplomacyMgr.h"
#include "game/TTaskForce.h"
#include "game/global_data_tables.h"

IMPLEMENT_SERIAL(TNavyMission, TMission, 1)

// Not-yet-recovered free functions this file calls into (generic stub
// signature per the autogen stub definition; real signature applied via a
// typed cast at each call site so the linker resolves the correct symbol).
extern undefined4 GetNavyPrimaryOrderNodeByIndex(void);
extern undefined4 FindFirstTrackedHandlerMatchingModeAndShortKey(void);
extern undefined4 CompareMissionOrderEntriesByPriorityScore(void);
extern undefined4 GetOrCreateMissionOrderEntryForNode(void);

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

// The binary body inlines TMission() (state08/value0c/marker11) and does NOT touch
// nationId04/pathMarker06; the vtable install lands mid-way through the zero stores.
// FUNCTION: IMPERIALISM 0x00535470
TNavyMission::TNavyMission(TZone* targetZone) : TMission() {
  targetZone14 = targetZone;
  targetZone18 = nullptr;
  navyField1c = 0;
  navyField20 = nullptr;
  orderList24 = nullptr;
  navyState28 = 0;
  for (int i = 0; i < 4; ++i) {
    resourceWeights2c[i] = 0.0f;
  }
}

// FUNCTION: IMPERIALISM 0x005354c0
void TNavyMission::NoOpSlot9C(void* pMapOrderEntry) {
  (void)pMapOrderEntry;
}

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

// SYNTHETIC: IMPERIALISM 0x00535560
// TNavyMission::`scalar deleting destructor'

// The trivial base-chain destructors collapse to a single reset of the vptr to CObject's
// runtime-object base vtable; MSVC emits exactly that write for this empty destructor.
// FUNCTION: IMPERIALISM 0x00535590
TNavyMission::~TNavyMission() {}

// SYNTHETIC: IMPERIALISM 0x00536390
// TNavyMission::CreateObject

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
    orderList24 = TTaskForce::DeleteMapOrderChildLinkAndReturnNext(orderList24);
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
  // TMapOrderChildLinkNode::object_ptr is typed TTaskForce* for the (more common)
  // army-mission usage of this shared node type.
  for (TMapOrderChildLinkNode* node = orderList24; node != nullptr; node = node->next) {
    int idx = reinterpret_cast<TShip*>(node->object_ptr)->GetIndexInPrimaryOrderList();
    stream->WriteCountSlot88(idx);
  }
  stream->WriteCountSlot88(-1);

  stream->WriteBytesSlot78(&navyState28, 4);
}

// FUNCTION: IMPERIALISM 0x00536650
void TNavyMission::ReadFrom(TStream* stream) {
  TMission::ReadFrom(stream);

  int id1 = stream->ReadInteger();
  targetZone14 = FindMapActionContextByNodeId(static_cast<short>(id1));

  int id2 = stream->ReadInteger();
  targetZone18 = FindMapActionContextByNodeId(static_cast<short>(id2));

  stream->ReadBytes(&resourceWeights2c[0], 0x10);
  for (int i = 0; i < 4; ++i) {
    resourceWeights2c[i] = SwapFloat(resourceWeights2c[i]);
  }

  short nodeIdx = stream->ReadShort();
  if (nodeIdx > -1) {
    do {
      TShip* orderNode = GetNavyPrimaryOrderNodeByIndex(nodeIdx);
      NoOpSlot84(reinterpret_cast<int>(orderNode), 0);
      nodeIdx = stream->ReadShort();
    } while (nodeIdx >= 0);
  }

  stream->ReadBytes(&navyState28, 4);
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
    orderList24 = TTaskForce::DeleteMapOrderChildLinkAndReturnNext(orderList24);
  }
  return 1;
}

// FUNCTION: IMPERIALISM 0x00536780
void TNavyMission::NoOpSlot84(int a, int b) {
  TTaskForce* item = reinterpret_cast<TTaskForce*>(a);
  TMission*& owner = *reinterpret_cast<TMission**>(reinterpret_cast<char*>(item) + 0x2c);
  if (owner != nullptr) {
    owner->NoOpSlot8C(a, b);
  }
  owner = this;
  TMapOrderChildLinkNode* node = orderList24->CreateLinkedOrderNode(item);
  orderList24 = node;
  if (static_cast<char>(b) != 0) {
    RefreshSlot40();
  }
}

// FUNCTION: IMPERIALISM 0x005367d0
void TNavyMission::NoOpSlot8C(int a, int b) {
  (void)b;
  TTaskForce* item = reinterpret_cast<TTaskForce*>(a);
  if (orderList24 != nullptr) {
    if (orderList24->object_ptr == item) {
      orderList24 = TTaskForce::DeleteMapOrderChildLinkAndReturnNext(orderList24);
    } else {
      orderList24->next->RemoveLinkedOrderNodeByValueRecursive(item);
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
    TTaskForce* entry = node->object_ptr;
    for (int category = 0; category < 4; ++category) {
      // Original dispatches the TShip method on the TTaskForce node (shared offsets).
      reinterpret_cast<TShip*>(entry)->ComputeNavyOrderPriorityContributionPercentByCategory(
          category);
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

  SetStateByte8To2();
  ResetValue0CToZero();
  NoOpSlot3C();

  targetZone14->IsZoneMaskOrArrayEntryPresentForKey(nationId04);

  if (orderList24 == nullptr) {
    navyState28 = 0;
    return;
  }

  int mode = navyState28;
  if (mode == 0) {
    if (1.0f <= ComputeNavyOrderCategorySimilarityRatio(1)) {
      if (1.0f <= ComputeNavyOrderCategorySimilarityRatio(0)) {
        navyState28 = 2;
        return;
      }
      navyState28 = 1;
    }
  } else if (mode == 1) {
    navyState28 = 2;
  } else if (mode == 2) {
    if (ComputeNavyOrderCategorySimilarityRatio(1) < 0.8f) {
      navyState28 = 0;
      navyField20 = static_cast<TObject*>(GetReplacementSlot48());
    }
  }
}

// FUNCTION: IMPERIALISM 0x00536e40
void TNavyMission::MissionSlot44() {}

// FUNCTION: IMPERIALISM 0x00536fa0
TZone* TNavyMission::RefreshMissionPortZoneContextForNation() {
  return targetZone14->SelectBestPrimaryNeighborForNationDiplomacyMask(nationId04);
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
TZone* TNavyMission::GetActiveTargetZoneByState28() {
  int state = navyState28;
  if (state != 0) {
    if (state > 0 && state <= 2) {
      return targetZone14;
    }
    return 0;
  }
  return targetZone18;
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
        // Ground truth (0x537090): the original compares the *existing selection's*
        // zone-distance against the *candidate's* zone-distance, both to targetZone14 --
        // the prior port dropped this argument and used targetZone14 itself as a fake
        // receiver for target1 instead of selectedOrder.
        short target1 = static_cast<TShip*>(selectedOrder)
                            ->ComputeOrderNodeDistanceQuotientByDescriptorWord24(targetZone14);
        short target2 =
            static_cast<TShip*>(topOrder)->ComputeOrderNodeDistanceQuotientByDescriptorWord24(
                targetZone14);
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

  for (int i = 0; i < 2; ++i) {
    void* orderObj = orders[i];
    if (orderObj == nullptr)
      continue;
    if (i == 1 && orderObj == startOrder)
      continue;

    void* nodePtr = FindFirstTrackedHandlerMatchingModeAndShortKey_fn(
        orderList24, reinterpret_cast<int>(orderObj));
    *reinterpret_cast<char*>(reinterpret_cast<char*>(nodePtr) + 0xc) = 1;
    // GetOrCreateMissionOrderEntryForNode (0x5503a0) creates/returns a TTaskForce
    // entry -- see the contextAnchor field comment in TTaskForce.h.
    TTaskForce* entry =
        static_cast<TTaskForce*>(GetOrCreateMissionOrderEntryForNode_fn(orderObj, 0));

    if (*reinterpret_cast<int*>(reinterpret_cast<char*>(orderObj) + 8) == pContextAnchor) {
      entry->SetMapOrderType9AndQueue();
    } else {
      entry->PromoteMapOrderChainAndQueue(reinterpret_cast<TZone*>(pContextAnchor));
    }
  }
}

// FUNCTION: IMPERIALISM 0x005371d0
void TNavyMission::ConsolidateMissionOrderEntriesByTargetAndQueue(int* pContextAnchor) {
  typedef void*(__fastcall * GetOrCreateMissionOrderEntryForNode_t)(void* self, int dummyEdx);
  GetOrCreateMissionOrderEntryForNode_t GetOrCreateMissionOrderEntryForNode_fn =
      reinterpret_cast<GetOrCreateMissionOrderEntryForNode_t>(
          (void*)&GetOrCreateMissionOrderEntryForNode);

  for (TMapOrderChildLinkNode* node = orderList24; node != nullptr; node = node->next) {
    if (node->active_flag == 0) {
      node->active_flag = 1;
      // GetOrCreateMissionOrderEntryForNode (0x5503a0) creates/returns a TTaskForce
      // entry -- see the contextAnchor field comment in TTaskForce.h.
      TTaskForce* entry =
          static_cast<TTaskForce*>(GetOrCreateMissionOrderEntryForNode_fn(node->object_ptr, 0));
      for (TMapOrderChildLinkNode* other = orderList24; other != nullptr; other = other->next) {
        if (other->active_flag == 0 && other->object_ptr->attachment == entry->contextAnchor) {
          other->object_ptr->RemoveNode(entry);
          other->active_flag = 1;
        }
      }
      entry->PromoteMapOrderChainAndQueue(reinterpret_cast<TZone*>(pContextAnchor));
    }
  }
}

// Adds one order node's 4-category priority contribution into `vector`, categories

// Scores how the mission's aggregate order profile matches its resource weights when
// the candidate order is added (foreign candidate) or removed (own candidate),
// relative to the current-profile score from slot 0x68.
// FUNCTION: IMPERIALISM 0x00537270
float TNavyMission::ReturnZeroFloatSlot74(void* candidate) {
  if (flag10 != 0) {
    return g_Recompute_Nation_Order_LookupTable_0065A9E8;
  }
  TShip* orderNode = static_cast<TShip*>(candidate);
  float profile[4];
  if (orderNode->field2c == this) {
    profile[0] = 0.0f;
    profile[1] = 0.0f;
    profile[2] = 0.0f;
    profile[3] = 0.0f;
    for (TMapOrderChildLinkNode* node = orderList24; node != 0; node = node->next) {
      TShip* entry = reinterpret_cast<TShip*>(node->object_ptr);
      short bucket;
      if (GetActiveTargetZoneByState28() != 0) {
        bucket = entry->ComputeOrderNodeDistanceQuotientByDescriptorWord24(
            GetActiveTargetZoneByState28());
      } else {
        bucket = 0;
      }
      if (bucket > 5) {
        bucket = 5;
      }
      AccumulateNavyOrderCategoryVectorWithScale(entry, profile,
                                                 g_ArmyMissionOrderWeightTable_006978c8[bucket]);
    }
    short bucket;
    if (GetActiveTargetZoneByState28() != 0) {
      bucket = orderNode->ComputeOrderNodeDistanceQuotientByDescriptorWord24(
          GetActiveTargetZoneByState28());
    } else {
      bucket = 0;
    }
    if (bucket > 5) {
      bucket = 5;
    }
    float weight = static_cast<float>(g_ArmyMissionOrderWeightTable_006978c8[bucket] *
                                      g_Recompute_Nation_Order_LookupTable_0065A9E0);
    float scaledRatio =
        weight * static_cast<float>(orderNode->stockLevel1c /
                                    orderNode->GetNavyOrderNormalizationBaseByNationType());
    profile[0] =
        static_cast<float>(orderNode->ComputeNavyOrderPriorityContributionPercentByCategory(0)) *
            scaledRatio +
        profile[0];
    profile[1] =
        static_cast<float>(orderNode->ComputeNavyOrderPriorityContributionPercentByCategory(1)) *
            scaledRatio +
        profile[1];
    profile[2] =
        static_cast<float>(orderNode->ComputeNavyOrderPriorityContributionPercentByCategory(2)) *
            scaledRatio +
        profile[2];
    profile[3] =
        static_cast<float>(orderNode->ComputeNavyOrderPriorityContributionPercentByCategory(3)) *
            weight +
        profile[3];
    float sqrtSum = g_Recompute_Nation_Order_LookupTable_0065A9E8;
    float weightSum = g_Recompute_Nation_Order_LookupTable_0065A9E8;
    for (int componentIndex = 0; componentIndex < 4; ++componentIndex) {
      sqrtSum +=
          static_cast<float>(sqrt(resourceWeights2c[componentIndex] * profile[componentIndex]));
      weightSum += resourceWeights2c[componentIndex];
    }
    return ReturnZeroFloatSlot68() - sqrtSum / weightSum;
  }
  profile[0] = 0.0f;
  profile[1] = 0.0f;
  profile[2] = 0.0f;
  profile[3] = 0.0f;
  for (TMapOrderChildLinkNode* node = orderList24; node != 0; node = node->next) {
    TShip* entry = reinterpret_cast<TShip*>(node->object_ptr);
    short bucket;
    if (GetActiveTargetZoneByState28() != 0) {
      bucket =
          entry->ComputeOrderNodeDistanceQuotientByDescriptorWord24(GetActiveTargetZoneByState28());
    } else {
      bucket = 0;
    }
    if (bucket > 5) {
      bucket = 5;
    }
    AccumulateNavyOrderCategoryVectorWithScale(entry, profile,
                                               g_ArmyMissionOrderWeightTable_006978c8[bucket]);
  }
  short bucket;
  if (GetActiveTargetZoneByState28() != 0) {
    bucket = orderNode->ComputeOrderNodeDistanceQuotientByDescriptorWord24(
        GetActiveTargetZoneByState28());
  } else {
    bucket = 0;
  }
  if (bucket > 5) {
    bucket = 5;
  }
  AccumulateNavyOrderCategoryVectorWithScale(orderNode, profile,
                                             g_ArmyMissionOrderWeightTable_006978c8[bucket]);
  float sqrtSum = g_Recompute_Nation_Order_LookupTable_0065A9E8;
  float weightSum = g_Recompute_Nation_Order_LookupTable_0065A9E8;
  for (int componentIndex = 0; componentIndex < 4; ++componentIndex) {
    sqrtSum +=
        static_cast<float>(sqrt(resourceWeights2c[componentIndex] * profile[componentIndex]));
    weightSum += resourceWeights2c[componentIndex];
  }
  return sqrtSum / weightSum - ReturnZeroFloatSlot68();
}

// Scores how badly a candidate navy order node fits this mission's target profile:
// squared distance between the node's normalized 4-category priority vector and the
// profile floats at targetProfile+0x10, plus a distance-bucket weight from the score
// table and an understock penalty.
// FUNCTION: IMPERIALISM 0x00537610
float TNavyMission::ReturnZeroFloatSlot7C(void* candidate, void* targetProfile) {
  TShip* orderNode = static_cast<TShip*>(candidate);
  int stockRatio = orderNode->stockLevel1c / orderNode->GetNavyOrderNormalizationBaseByNationType();
  if (static_cast<float>(stockRatio) < g_Recompute_Nation_Order_LookupTable_0065AA20 &&
      !ReturnFalseSlot28()) {
    return g_Recompute_Nation_Order_LookupTable_0065A9C4;
  }
  float profile[4] = {0.0f, 0.0f, 0.0f, 0.0f};
  short distanceBucket;
  if (GetActiveTargetZoneByState28() != 0) {
    distanceBucket = orderNode->ComputeOrderNodeDistanceQuotientByDescriptorWord24(
        GetActiveTargetZoneByState28());
  } else {
    distanceBucket = 0;
  }
  short clampedBucket = distanceBucket > 5 ? 5 : distanceBucket;
  float bucketWeight =
      g_ArmyMissionCandidateScoreTable_006978f8[static_cast<char>(state08) * 6 + clampedBucket];
  float scale = static_cast<float>(orderNode->stockLevel1c /
                                   orderNode->GetNavyOrderNormalizationBaseByNationType());
  profile[0] =
      static_cast<float>(orderNode->ComputeNavyOrderPriorityContributionPercentByCategory(0)) *
          scale +
      profile[0];
  profile[1] =
      static_cast<float>(orderNode->ComputeNavyOrderPriorityContributionPercentByCategory(1)) *
          scale +
      profile[1];
  profile[2] =
      static_cast<float>(orderNode->ComputeNavyOrderPriorityContributionPercentByCategory(2)) *
          scale +
      profile[2];
  profile[3] =
      static_cast<float>(orderNode->ComputeNavyOrderPriorityContributionPercentByCategory(3)) +
      profile[3];
  float sum = g_Recompute_Nation_Order_LookupTable_0065A9E8;
  float sumSquares = g_Recompute_Nation_Order_LookupTable_0065A9E8;
  int componentIndex;
  for (componentIndex = 0; componentIndex < 4; ++componentIndex) {
    sum += profile[componentIndex];
  }
  if (sum == g_Recompute_Nation_Order_LookupTable_0065A9F0) {
    return g_Recompute_Nation_Order_LookupTable_0065A9C4;
  }
  const float* targetVector = static_cast<float*>(targetProfile);
  for (componentIndex = 0; componentIndex < 4; ++componentIndex) {
    float delta = profile[componentIndex] / sum - targetVector[componentIndex + 4];
    sumSquares = delta * delta + sumSquares;
  }
  double understockPenalty;
  if (!ReturnFalseSlot28() &&
      orderNode->stockLevel1c < orderNode->GetNavyOrderNormalizationBaseByNationType()) {
    understockPenalty =
        (g_Recompute_Nation_Order_LookupTable_0065AA08 -
         static_cast<double>(orderNode->stockLevel1c /
                             orderNode->GetNavyOrderNormalizationBaseByNationType())) *
        g_Recompute_Nation_Order_LookupTable_0065A9BC;
  } else {
    understockPenalty = g_Recompute_Nation_Order_LookupTable_0065A9F0;
  }
  return static_cast<float>((sumSquares + bucketWeight) + understockPenalty);
}

// FUNCTION: IMPERIALISM 0x005378c0
float TNavyMission::ReturnZeroFloatSlot6C() {
  double total = 0.0;
  for (int i = 0; i < 4; ++i) {
    total += static_cast<double>(resourceWeights2c[i]);
  }
  return static_cast<float>(total);
}
// Builds a per-category priority vector over every orderList24 ship: a ship counts if
// it's within `distanceThreshold` hops of `nearZone` (or unconditionally when `nearZone`
// is null), OR -- when farther than that -- if it's within `distanceThreshold` hops of
// `farZone` instead (when farZone is both non-null and != nearZone). The per-ship
// contribution accumulation (ratio = stockLevel1c/normalizationBase, categories 0-2
// scaled by ratio, category 3 unscaled) is reproduced inline at both convergent call
// sites rather than via AccumulateNavyOrderCategoryVectorWithScale -- this specific
// function inlines its own copy in the original rather than calling out to 0x537c60.
// FUNCTION: IMPERIALISM 0x00537900
void TNavyMission::BuildNavyOrderCategoryVectorForNationWithExclusion(float* vector,
                                                                      TZone* nearZone,
                                                                      short distanceThreshold,
                                                                      TObject* farZone) {
  vector[0] = 0.0f;
  vector[1] = 0.0f;
  vector[2] = 0.0f;
  vector[3] = 0.0f;
  if (farZone == nearZone) {
    farZone = nullptr;
  }
  for (TMapOrderChildLinkNode* node = orderList24; node != nullptr; node = node->next) {
    TShip* ship = reinterpret_cast<TShip*>(node->object_ptr);
    bool inRange = true;
    if (nearZone != nullptr &&
        ship->ComputeOrderNodeDistanceQuotientByDescriptorWord24(nearZone) > distanceThreshold) {
      inRange = farZone != nullptr && ship->ComputeOrderNodeDistanceQuotientByDescriptorWord24(
                                          static_cast<TZone*>(farZone)) <= distanceThreshold;
    }
    if (inRange) {
      short normBase = ship->GetNavyOrderNormalizationBaseByNationType();
      float ratio = static_cast<float>(ship->stockLevel1c / normBase);
      vector[0] +=
          static_cast<float>(ship->ComputeNavyOrderPriorityContributionPercentByCategory(0)) *
          ratio;
      vector[1] +=
          static_cast<float>(ship->ComputeNavyOrderPriorityContributionPercentByCategory(1)) *
          ratio;
      vector[2] +=
          static_cast<float>(ship->ComputeNavyOrderPriorityContributionPercentByCategory(2)) *
          ratio;
      vector[3] +=
          static_cast<float>(ship->ComputeNavyOrderPriorityContributionPercentByCategory(3));
    }
  }
}

// Shared helper for RefreshSlot40 (0x536b30's inlined similarity-ratio computation).
float TNavyMission::ComputeNavyOrderCategorySimilarityRatio(int excludeCurrent) {
  float vector[4];
  BuildNavyOrderCategoryVectorForNationWithExclusion(
      vector, targetZone14, static_cast<short>(excludeCurrent), navyField20);
  float numerator = 0.0f;
  float denominator = 0.0f;
  for (int i = 0; i < 4; ++i) {
    numerator += sqrtf(resourceWeights2c[i] * vector[i]);
    denominator += resourceWeights2c[i];
  }
  return numerator / denominator;
}
// 0-2 scaled by (stock/normalization base)*scale and category 3 by scale alone.
// FUNCTION: IMPERIALISM 0x00537c60
void __cdecl AccumulateNavyOrderCategoryVectorWithScale(TShip* orderNode, float* vector,
                                                        float scale) {
  float ratio = static_cast<float>(orderNode->stockLevel1c /
                                   orderNode->GetNavyOrderNormalizationBaseByNationType()) *
                scale;
  vector[0] =
      static_cast<float>(orderNode->ComputeNavyOrderPriorityContributionPercentByCategory(0)) *
          ratio +
      vector[0];
  vector[1] =
      static_cast<float>(orderNode->ComputeNavyOrderPriorityContributionPercentByCategory(1)) *
          ratio +
      vector[1];
  vector[2] =
      static_cast<float>(orderNode->ComputeNavyOrderPriorityContributionPercentByCategory(2)) *
          ratio +
      vector[2];
  vector[3] =
      static_cast<float>(orderNode->ComputeNavyOrderPriorityContributionPercentByCategory(3)) *
          scale +
      vector[3];
}

// FUNCTION: IMPERIALISM 0x00537f40
float TNavyMission::ReturnZeroFloatSlot68() {
  return 0.0f;
}
// Weights all 4 categories uniformly by (stockLevel1c/normalizationBase) * a
// distance-decay factor (0.8^hopDistance, clamped to index 5) from a per-ship
// accumulator, over every existing orderList24 ship plus `candidateOrder`, then scores
// the resulting vector against resourceWeights2c via a Bhattacharyya-coefficient-style
// similarity. The per-ship accumulation is reproduced inline at both call sites (the
// loop body and the trailing candidate-ship call) rather than factored into a shared
// helper -- factoring it collapsed the codegen shape and tanked the score (9.48% vs the
// ~30%+ this idiom otherwise reaches), matching the original's per-callsite inlining.
// FUNCTION: IMPERIALISM 0x00538120
float TNavyMission::ComputeMissionOrderMatchScoreWithCandidateNavyOrder(TShip* candidateOrder) {
  float vector[4] = {
      g_Recompute_Nation_Order_LookupTable_0065A9E8, g_Recompute_Nation_Order_LookupTable_0065A9E8,
      g_Recompute_Nation_Order_LookupTable_0065A9E8, g_Recompute_Nation_Order_LookupTable_0065A9E8};
  for (TMapOrderChildLinkNode* node = orderList24; node != nullptr; node = node->next) {
    TShip* ship = reinterpret_cast<TShip*>(node->object_ptr);
    TZone* targetZone = GetActiveTargetZoneByState28();
    short distanceIndex = 0;
    if (targetZone != nullptr) {
      distanceIndex =
          ship->ComputeOrderNodeDistanceQuotientByDescriptorWord24(GetActiveTargetZoneByState28());
    }
    if (distanceIndex > 5) {
      distanceIndex = 5;
    }
    float scale =
        g_NavyOrderDistanceDecayWeightTable_006978c8[distanceIndex] *
        static_cast<float>(ship->stockLevel1c / ship->GetNavyOrderNormalizationBaseByNationType());
    for (int componentIndex = 0; componentIndex < 4; ++componentIndex) {
      vector[componentIndex] +=
          static_cast<float>(
              ship->ComputeNavyOrderPriorityContributionPercentByCategory(componentIndex)) *
          scale;
    }
  }

  TZone* targetZone = GetActiveTargetZoneByState28();
  short distanceIndex = 0;
  if (targetZone != nullptr) {
    distanceIndex = candidateOrder->ComputeOrderNodeDistanceQuotientByDescriptorWord24(
        GetActiveTargetZoneByState28());
  }
  if (distanceIndex > 5) {
    distanceIndex = 5;
  }
  float scale = g_NavyOrderDistanceDecayWeightTable_006978c8[distanceIndex] *
                static_cast<float>(candidateOrder->stockLevel1c /
                                   candidateOrder->GetNavyOrderNormalizationBaseByNationType());
  for (int componentIndex = 0; componentIndex < 4; ++componentIndex) {
    vector[componentIndex] +=
        static_cast<float>(
            candidateOrder->ComputeNavyOrderPriorityContributionPercentByCategory(componentIndex)) *
        scale;
  }

  float sumWeights = g_Recompute_Nation_Order_LookupTable_0065A9E8;
  float coefficient = g_Recompute_Nation_Order_LookupTable_0065A9E8;
  for (int i = 0; i < 4; ++i) {
    sumWeights += resourceWeights2c[i];
    coefficient += sqrtf(resourceWeights2c[i] * vector[i]);
  }
  return coefficient / sumWeights;
}

// Same shape as ComputeMissionOrderMatchScoreWithCandidateNavyOrder above, but negates
// the candidate ship's distance-weighted scale (* g_Recompute_Nation_Order_LookupTable_0065A9E0,
// which holds -1.0) before accumulating its contribution -- evaluating the profile with
// the candidate order removed rather than added. The existing orderList24 ships'
// contributions are unaffected (still added with a positive scale).
// FUNCTION: IMPERIALISM 0x005383f0
float TNavyMission::ComputeMissionOrderMatchScoreWithScaledCandidateNavyOrder(
    TShip* candidateOrder) {
  float vector[4] = {
      g_Recompute_Nation_Order_LookupTable_0065A9E8, g_Recompute_Nation_Order_LookupTable_0065A9E8,
      g_Recompute_Nation_Order_LookupTable_0065A9E8, g_Recompute_Nation_Order_LookupTable_0065A9E8};
  for (TMapOrderChildLinkNode* node = orderList24; node != nullptr; node = node->next) {
    TShip* ship = reinterpret_cast<TShip*>(node->object_ptr);
    TZone* targetZone = GetActiveTargetZoneByState28();
    short distanceIndex = 0;
    if (targetZone != nullptr) {
      distanceIndex =
          ship->ComputeOrderNodeDistanceQuotientByDescriptorWord24(GetActiveTargetZoneByState28());
    }
    if (distanceIndex > 5) {
      distanceIndex = 5;
    }
    float scale =
        g_NavyOrderDistanceDecayWeightTable_006978c8[distanceIndex] *
        static_cast<float>(ship->stockLevel1c / ship->GetNavyOrderNormalizationBaseByNationType());
    for (int componentIndex = 0; componentIndex < 4; ++componentIndex) {
      vector[componentIndex] +=
          static_cast<float>(
              ship->ComputeNavyOrderPriorityContributionPercentByCategory(componentIndex)) *
          scale;
    }
  }

  TZone* targetZone = GetActiveTargetZoneByState28();
  short distanceIndex = 0;
  if (targetZone != nullptr) {
    distanceIndex = candidateOrder->ComputeOrderNodeDistanceQuotientByDescriptorWord24(
        GetActiveTargetZoneByState28());
  }
  if (distanceIndex > 5) {
    distanceIndex = 5;
  }
  float scale = g_NavyOrderDistanceDecayWeightTable_006978c8[distanceIndex] *
                static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065A9E0) *
                static_cast<float>(candidateOrder->stockLevel1c /
                                   candidateOrder->GetNavyOrderNormalizationBaseByNationType());
  for (int componentIndex = 0; componentIndex < 4; ++componentIndex) {
    vector[componentIndex] +=
        static_cast<float>(
            candidateOrder->ComputeNavyOrderPriorityContributionPercentByCategory(componentIndex)) *
        scale;
  }

  float sumWeights = g_Recompute_Nation_Order_LookupTable_0065A9E8;
  float coefficient = g_Recompute_Nation_Order_LookupTable_0065A9E8;
  for (int i = 0; i < 4; ++i) {
    sumWeights += resourceWeights2c[i];
    coefficient += sqrtf(resourceWeights2c[i] * vector[i]);
  }
  return coefficient / sumWeights;
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

// Same shape as ComputeOrderDistributionSimilarityScoreForZone above, but scores against
// g_Populate_Beachhead_Mission_LookupTable_00697958[0..3] (the same table slice
// NormalizeFourComponentNavyVector's other callers use). The divergence-score tail is
// reproduced inline (not via NormalizeFourComponentNavyVector) to match the original's
// per-callsite inlining -- delegating to the shared helper collapsed the codegen shape
// and tanked the score (16.85% vs the ~29-37% this idiom otherwise reaches).
// FUNCTION: IMPERIALISM 0x00538dd0
float TNavyMission::ComputeOrderDistributionSimilarityScoreForZoneWithBaseProfile(
    TZone* nodeContext) {
  float vector[4] = {
      g_Recompute_Nation_Order_LookupTable_0065A9E8, g_Recompute_Nation_Order_LookupTable_0065A9E8,
      g_Recompute_Nation_Order_LookupTable_0065A9E8, g_Recompute_Nation_Order_LookupTable_0065A9E8};
  for (TShip* orderNode = GetNavyPrimaryOrderListHead(); orderNode != 0;
       orderNode = orderNode->nextOlder24) {
    if (orderNode->field08 == nodeContext &&
        g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(
            nationId04, orderNode->ownerNationSlot14) != 0) {
      AccumulateNavyOrderCategoryVectorWithScale(
          orderNode, vector, static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065AA08));
    }
  }
  float total = vector[0] + vector[1] + vector[2] + vector[3];
  if (total == static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065A9F0)) {
    return g_Recompute_Nation_Order_LookupTable_0065A9E8;
  }
  float diffSum = g_Recompute_Nation_Order_LookupTable_0065A9E8;
  for (int i = 0; i < 4; ++i) {
    float diff = vector[i] / total -
                 static_cast<float>(
                     static_cast<short>(g_Populate_Beachhead_Mission_LookupTable_00697958[i])) *
                     static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065A9F8);
    if (diff <= static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065A9F0)) {
      diff = -diff;
    }
    diffSum += diff;
  }
  return total * (static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065AA08) -
                  diffSum * static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065AA00));
}

// Default constructor
TNavyMission::TNavyMission() : TMission() {
  targetZone14 = nullptr;
  targetZone18 = nullptr;
  navyField1c = 0;
  navyField20 = nullptr;
  orderList24 = nullptr;
  navyState28 = 0;
  for (int i = 0; i < 4; ++i) {
    resourceWeights2c[i] = 0.0f;
  }
}

// Instance form of ComputeOrderDistributionSimilarityScoreWithDiplomacyFilter: sources
// the diplomacy filter's source nation from nationId04 (inherited from TMission) rather
// than an explicit argument, uses the fixed-category (0..3) accumulation shape (matching
// ComputeNavyOrderDistributionScoreForNation in TShip.cpp) instead of the rotating-category
// AccumulateNavyOrderVectorFromNode, and scores against
// g_Populate_Beachhead_Mission_LookupTable_00697958[4..7] instead of [0..3].
// FUNCTION: IMPERIALISM 0x00539a90
float TNavyMission::ComputeOrderDistributionSimilarityScoreForZone(TZone* nodeContext) {
  float vector[4] = {
      g_Recompute_Nation_Order_LookupTable_0065A9E8, g_Recompute_Nation_Order_LookupTable_0065A9E8,
      g_Recompute_Nation_Order_LookupTable_0065A9E8, g_Recompute_Nation_Order_LookupTable_0065A9E8};
  for (TShip* orderNode = GetNavyPrimaryOrderListHead(); orderNode != 0;
       orderNode = orderNode->nextOlder24) {
    if (orderNode->field08 == nodeContext &&
        g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(
            nationId04, orderNode->ownerNationSlot14) != 0) {
      AccumulateNavyOrderCategoryVectorWithScale(
          orderNode, vector, static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065AA08));
    }
  }
  float total = vector[0] + vector[1] + vector[2] + vector[3];
  if (total == static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065A9F0)) {
    return g_Recompute_Nation_Order_LookupTable_0065A9E8;
  }
  float diffSum = g_Recompute_Nation_Order_LookupTable_0065A9E8;
  for (int i = 0; i < 4; ++i) {
    float diff = vector[i] / total -
                 static_cast<float>(
                     static_cast<short>(g_Populate_Beachhead_Mission_LookupTable_00697958[4 + i])) *
                     static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065A9F8);
    if (diff <= static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065A9F0)) {
      diff = -diff;
    }
    diffSum += diff;
  }
  return total * (static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065AA08) -
                  diffSum * static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065AA00));
}
// If `portZone` has a definite single owner (owner code 0..6), scores directly for that
// owner (same divergence-score shape as TShip.cpp's ComputeNavyOrderDistributionScoreForNation,
// reproduced inline). Otherwise scans nations allied with this mission's own nationId04
// and keeps the best such score -- each iteration re-reads portZone's (still
// out-of-range) owner code as the ship filter rather than the candidate ally's index, so
// in practice this branch only ever contributes 0; modeled exactly as observed (Hard
// Rule 6) rather than "corrected" to use the loop index.
// FUNCTION: IMPERIALISM 0x0053b350
float TNavyMission::ComputeMissionNavyOrderDistributionScoreForPortOwnerOrAllies(TZone* portZone) {
  float best = g_Recompute_Nation_Order_LookupTable_0065A9E8;
  short ownerNation = portZone->GetPortZoneOwnerNationCodeFromMissionField48();
  if (ownerNation < 7) {
    float vector[4] = {g_Recompute_Nation_Order_LookupTable_0065A9E8,
                       g_Recompute_Nation_Order_LookupTable_0065A9E8,
                       g_Recompute_Nation_Order_LookupTable_0065A9E8,
                       g_Recompute_Nation_Order_LookupTable_0065A9E8};
    for (TShip* ship = GetNavyPrimaryOrderListHead(); ship != nullptr; ship = ship->nextOlder24) {
      if (ship->ownerNationSlot14 == ownerNation && ship->field08->QueryPortZoneCapability() &&
          ship->GetNavyOrderNormalizationBaseByNationType() <= ship->stockLevel1c) {
        AccumulateNavyOrderCategoryVectorWithScale(
            ship, vector, static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065AA08));
      }
    }
    float total = vector[0] + vector[1] + vector[2] + vector[3];
    if (total == static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065A9F0)) {
      return g_Recompute_Nation_Order_LookupTable_0065A9E8;
    }
    float diffSum = g_Recompute_Nation_Order_LookupTable_0065A9E8;
    for (int i = 0; i < 4; ++i) {
      float diff = vector[i] / total -
                   static_cast<float>(g_NavyOrderDistributionCategoryWeights_00697978[i]) *
                       static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065A9F8);
      if (diff <= static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065A9F0)) {
        diff = -diff;
      }
      diffSum += diff;
    }
    return total * (static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065AA08) -
                    diffSum * static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065AA00));
  }

  for (short allyIdx = 0; allyIdx < 7; ++allyIdx) {
    if (g_apNationStates[allyIdx] != nullptr &&
        g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(nationId04, allyIdx) != 0) {
      short scoreNation = portZone->GetPortZoneOwnerNationCodeFromMissionField48();
      float vector[4] = {g_Recompute_Nation_Order_LookupTable_0065A9E8,
                         g_Recompute_Nation_Order_LookupTable_0065A9E8,
                         g_Recompute_Nation_Order_LookupTable_0065A9E8,
                         g_Recompute_Nation_Order_LookupTable_0065A9E8};
      for (TShip* ship = GetNavyPrimaryOrderListHead(); ship != nullptr; ship = ship->nextOlder24) {
        if (ship->ownerNationSlot14 == scoreNation && ship->field08->QueryPortZoneCapability() &&
            ship->GetNavyOrderNormalizationBaseByNationType() <= ship->stockLevel1c) {
          AccumulateNavyOrderCategoryVectorWithScale(
              ship, vector, static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065AA08));
        }
      }
      float total = vector[0] + vector[1] + vector[2] + vector[3];
      float score = g_Recompute_Nation_Order_LookupTable_0065A9E8;
      if (total != static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065A9F0)) {
        float diffSum = g_Recompute_Nation_Order_LookupTable_0065A9E8;
        for (int i = 0; i < 4; ++i) {
          float diff = vector[i] / total -
                       static_cast<float>(g_NavyOrderDistributionCategoryWeights_00697978[i]) *
                           static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065A9F8);
          if (diff <= static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065A9F0)) {
            diff = -diff;
          }
          diffSum += diff;
        }
        score =
            total * (static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065AA08) -
                     diffSum * static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065AA00));
      }
      if (score > best) {
        best = score;
      }
    }
  }
  return best;
}
