// TNavyMission implementations.

#include "game/TNavyMission.h"
#include "game/TStream.h"
#include "game/TList.h"
#include "game/TZone.h"
#include "game/TShip.h"
#include "game/TDiplomacyMgr.h"
#include "game/global_data_tables.h"

IMPLEMENT_SERIAL(TNavyMission, TMission, 1)

extern "C" {
extern const float g_Recompute_Nation_Order_LookupTable_0065A9E8;
extern const double g_Recompute_Nation_Order_LookupTable_0065A9F0;
extern double g_Recompute_Nation_Order_LookupTable_0065A9F8;
extern double g_Recompute_Nation_Order_LookupTable_0065AA00;
extern double g_Recompute_Nation_Order_LookupTable_0065AA08;
extern unsigned short g_Populate_Beachhead_Mission_LookupTable_00697958[];

short GetMissionTargetContextIdFromField14(int arg);
void* FindFirstTrackedHandlerMatchingModeAndShortKey(void* list, int key);
int CompareMissionOrderEntriesByPriorityScore(void* item, int profile);
void __fastcall AttachMissionOrderAsQueuedChildAndNotify(void* order, void* notifyObj);
void __fastcall PromoteMapOrderChainAndQueue(void* order, void* contextAnchor);
int* __fastcall DeleteMapOrderChildLinkAndReturnNext(int* pChildLinkNode);
}

// Swaps float byte order (Big-Endian <-> Little-Endian)
static inline float SwapFloat(float val) {
  union { float f; unsigned char b[4]; } src, dst;
  src.f = val;
  dst.b[0] = src.b[3];
  dst.b[1] = src.b[2];
  dst.b[2] = src.b[1];
  dst.b[3] = src.b[0];
  return dst.f;
}

// Helper functions for static factory and metadata
// FUNCTION: IMPERIALISM 0x00536390
TMission* CreateTNavyMission() {
  return new TNavyMission();
}

// FUNCTION: IMPERIALISM 0x00536450
void* GetTNavyMissionClassNamePointer() {
  return &TNavyMission::classTNavyMission;
}

// Helper to serialize TNavyMission onto TStream
// FUNCTION: IMPERIALISM 0x00536530
void SerializeTNavyMissionCommon(TNavyMission* self, TStream* stream) {
  self->TMission::WriteTo(stream);
  
  typedef short (__fastcall *GetShortAtOffset14OrInvalid_t)(TZone* self, int dummyEdx);
  GetShortAtOffset14OrInvalid_t GetShortAtOffset14OrInvalid_fn =
      reinterpret_cast<GetShortAtOffset14OrInvalid_t>(0x55f0b0);

  int nodeIdx1 = -1;
  if (self->targetZone14 != nullptr) {
    nodeIdx1 = GetShortAtOffset14OrInvalid_fn(self->targetZone14, 0);
  }
  stream->WriteCountSlot88(nodeIdx1);

  int nodeIdx2 = -1;
  if (self->targetZone18 != nullptr) {
    nodeIdx2 = GetShortAtOffset14OrInvalid_fn(self->targetZone18, 0);
  }
  stream->WriteCountSlot88(nodeIdx2);

  for (int i = 0; i < 4; ++i) {
    float swapped = SwapFloat(self->resourceWeights2c[i]);
    stream->WriteBytesSlot78(&swapped, 4);
  }

  // Walk orderList24 and write indices
  // In Ghidra, the loop is:
  // for (iVar5 = *(int *)(unaff_EBX + 0x24); iVar5 != 0; iVar5 = *(int *)(iVar5 + 4)) {
  //   uVar6 = GetNavyPrimaryOrderListIndexOfNode();
  //   (*unaff_EBP)(uVar6);
  // }
  // (*unaff_EBP)(0xffffffff);
  // And (*unaff_EBP) is WriteCountSlot88!
  
  typedef int (__cdecl *GetNavyPrimaryOrderListIndexOfNode_t)(void* node);
  GetNavyPrimaryOrderListIndexOfNode_t GetNavyPrimaryOrderListIndexOfNode_fn =
      reinterpret_cast<GetNavyPrimaryOrderListIndexOfNode_t>(0x5503d0); // GetNavyPrimaryOrderListIndexOfNode is at 0x5503d0

  struct ListNode {
    void* item;
    ListNode* next;
  };

  ListNode* node = reinterpret_cast<ListNode*>(self->orderList24);
  while (node != nullptr) {
    int idx = GetNavyPrimaryOrderListIndexOfNode_fn(node->item);
    stream->WriteCountSlot88(idx);
    node = node->next;
  }
  stream->WriteCountSlot88(-1);

  stream->WriteBytesSlot78(&self->navyField28, 4);
}

// Helper to deserialize TNavyMission from TStream
// FUNCTION: IMPERIALISM 0x00536650
void DeserializeTNavyMissionCommon(TNavyMission* self, TStream* stream) {
  self->TMission::ReadFrom(stream);

  typedef int (__cdecl *FindMapActionContextByNodeId_t)(int id);
  FindMapActionContextByNodeId_t FindMapActionContextByNodeId_fn =
      reinterpret_cast<FindMapActionContextByNodeId_t>(0x55f1a0); // FindMapActionContextByNodeId is at 0x55f1a0

  int id1 = stream->ReadInteger();
  self->targetZone14 = reinterpret_cast<TZone*>(FindMapActionContextByNodeId_fn(id1));

  int id2 = stream->ReadInteger();
  self->targetZone18 = reinterpret_cast<TZone*>(FindMapActionContextByNodeId_fn(id2));

  stream->ReadBytes(&self->resourceWeights2c[0], 0x10);
  for (int i = 0; i < 4; ++i) {
    self->resourceWeights2c[i] = SwapFloat(self->resourceWeights2c[i]);
  }

  // Read order nodes
  typedef void* (__cdecl *GetNavyPrimaryOrderNodeByIndex_t)(int index, int unused);
  GetNavyPrimaryOrderNodeByIndex_t GetNavyPrimaryOrderNodeByIndex_fn =
      reinterpret_cast<GetNavyPrimaryOrderNodeByIndex_t>(0x550410); // GetNavyPrimaryOrderNodeByIndex is at 0x550410

  short nodeIdx = stream->ReadShort();
  if (nodeIdx > -1) {
    // (*pcVar3)(uVar4); where pcVar3 is slot 0x84 / 33 (byte 0x84 of TNavyMission)
    // Slot 33 (byte 0x84) is NoOpSlot84!
    do {
      void* orderNode = GetNavyPrimaryOrderNodeByIndex_fn(nodeIdx, 0);
      self->NoOpSlot84(reinterpret_cast<int>(orderNode), 0);
      nodeIdx = stream->ReadShort();
    } while (nodeIdx >= 0);
  }

  stream->ReadBytes(&self->navyField28, 4);
  self->navyField1c = 0;
  if (self->navyField20 != nullptr) {
    static_cast<TObject*>(self->navyField20)->Free();
  }
  self->navyField20 = nullptr;
}

namespace {

struct NavyPrimaryOrderNode {
  char pad00[8];
  TZone* nodeContext08;
  char pad0c[8];
  short sourceNation14;
  char pad16[6];
  short weight1c;
  char pad1e[6];
  void* next24;
};

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

void AccumulateNavyOrderVectorFromNode(NavyPrimaryOrderNode* orderNode, float* vector) {
  typedef short (__cdecl *GetNavyOrderNormalizationBaseByNationType_t)(void);
  GetNavyOrderNormalizationBaseByNationType_t GetNavyOrderNormalizationBaseByNationType_fn =
      reinterpret_cast<GetNavyOrderNormalizationBaseByNationType_t>(0x550d50); // at 0x550d50

  short normalizationBase = GetNavyOrderNormalizationBaseByNationType_fn();
  if (normalizationBase == 0) {
    return;
  }
  float scale = static_cast<float>(orderNode->weight1c) / static_cast<float>(normalizationBase);
  int category = static_cast<int>(orderNode->weight1c % normalizationBase);

  typedef short (__fastcall *ComputeNavyOrderPriorityContributionPercentByCategory_t)(void*, int);
  ComputeNavyOrderPriorityContributionPercentByCategory_t ComputeNavyOrderPriorityContributionPercentByCategory_fn =
      reinterpret_cast<ComputeNavyOrderPriorityContributionPercentByCategory_t>(0x550b60); // at 0x550b60

  for (int componentIndex = 0; componentIndex < 4; ++componentIndex) {
    short contribution = ComputeNavyOrderPriorityContributionPercentByCategory_fn(orderNode, category);
    if (componentIndex < 3) {
      vector[componentIndex] += static_cast<float>(contribution) * scale;
    } else {
      vector[componentIndex] += static_cast<float>(contribution);
    }
    category = static_cast<int>(contribution);
  }
}

} // namespace

// FUNCTION: IMPERIALISM 0x005389f0
float TNavyMission::ComputeOrderDistributionSimilarityScoreWithDiplomacyFilter(
    int sourceNation, TZone* nodeContext) {
  float vector[4] = {0.0f, 0.0f, 0.0f, 0.0f};
  for (NavyPrimaryOrderNode* orderNode =
           reinterpret_cast<NavyPrimaryOrderNode*>(GetNavyPrimaryOrderListHead());
       orderNode != 0; orderNode = reinterpret_cast<NavyPrimaryOrderNode*>(orderNode->next24)) {
    if (orderNode->nodeContext08 == nodeContext &&
        g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(static_cast<short>(sourceNation),
                                                                orderNode->sourceNation14) != 0) {
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
float TNavyMission::ComputeOrderDistributionSimilarityScoreForExactSourceNation(int sourceNation,
                                                                                TZone* nodeContext) {
  float vector[4] = {0.0f, 0.0f, 0.0f, 0.0f};
  for (NavyPrimaryOrderNode* orderNode =
           reinterpret_cast<NavyPrimaryOrderNode*>(GetNavyPrimaryOrderListHead());
       orderNode != 0; orderNode = reinterpret_cast<NavyPrimaryOrderNode*>(orderNode->next24)) {
    if (orderNode->nodeContext08 == nodeContext &&
        static_cast<short>(sourceNation) == orderNode->sourceNation14) {
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

// Destructor
// FUNCTION: IMPERIALISM 0x00535560
TNavyMission::~TNavyMission() {
  // ResetTNavyMissionToSentinelVtable is inline/automatic in MSVC
}

void TNavyMission::WriteTo(TStream* stream) {
  SerializeTNavyMissionCommon(this, stream);
}

void TNavyMission::ReadFrom(TStream* stream) {
  DeserializeTNavyMissionCommon(this, stream);
}

// FUNCTION: IMPERIALISM 0x005364c0
void TNavyMission::CleanupTMissionAndReleaseOwnedOrders() {
  if (navyField20 != nullptr) {
    static_cast<TObject*>(navyField20)->Free();
  }
  navyField20 = nullptr;

  while (orderList24 != nullptr) {
    *reinterpret_cast<int*>(reinterpret_cast<char*>(orderList24) + 0x2c) = 0;
    orderList24 = reinterpret_cast<TList*>(DeleteMapOrderChildLinkAndReturnNext(reinterpret_cast<int*>(orderList24)));
  }

  if (this != nullptr) {
    delete this;
  }
}

// FUNCTION: IMPERIALISM 0x00536fc0
uint TNavyMission::EnsureMissionCurrentTargetContextIsValid() {
  TZone* zone = reinterpret_cast<TZone*>(targetZone18);
  if (zone != nullptr) {
    if (zone->QueryPortZoneCapability() != 0) {
      if (zone->QueryZoneCapabilityFlagD(nationId04) == 0) {
        targetZone18 = reinterpret_cast<TZone*>(this->EnsureMissionCurrentTargetContextIsValid());
      }
    }
  }
  return (targetZone18 != nullptr) ? reinterpret_cast<uint>(this) : 0;
}

// FUNCTION: IMPERIALISM 0x00536740
void TNavyMission::ClearMissionQueuedOrderLinksAndOwnerPointers() {
  while (orderList24 != nullptr) {
    *reinterpret_cast<int*>(reinterpret_cast<char*>(orderList24) + 0x2c) = 0;
    orderList24 = reinterpret_cast<TList*>(DeleteMapOrderChildLinkAndReturnNext(reinterpret_cast<int*>(orderList24)));
  }
}

// FUNCTION: IMPERIALISM 0x00537090
void TNavyMission::QueueMissionOrdersByPriorityForContext(int pContextAnchor, int* ppSelectedChildNode) {
  struct ListNode {
    void* item;
    ListNode* next;
  };

  if ((*ppSelectedChildNode != 0) &&
      (FindFirstTrackedHandlerMatchingModeAndShortKey(orderList24, *ppSelectedChildNode) == nullptr)) {
    *ppSelectedChildNode = 0;
  }

  void* topOrder = nullptr;
  int maxScore = -1;

  ListNode* node = reinterpret_cast<ListNode*>(orderList24);
  while (node != nullptr) {
    int score = CompareMissionOrderEntriesByPriorityScore(node->item, 3);
    if (maxScore < score) {
      topOrder = node->item;
      maxScore = score;
    }
    node = node->next;
  }

  void* selectedOrder = reinterpret_cast<void*>(*ppSelectedChildNode);

  if (topOrder != nullptr) {
    if (topOrder == selectedOrder) {
      topOrder = nullptr;
    } else {
      if (selectedOrder != nullptr) {
        short target1 = GetMissionTargetContextIdFromField14(reinterpret_cast<int>(targetZone14));
        short target2 = GetMissionTargetContextIdFromField14(reinterpret_cast<int>(targetZone14));
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
  void* orders[2] = { startOrder, topOrder };

  typedef void* (__fastcall *GetOrCreateMissionOrderEntryForNode_t)(void* self, int dummyEdx);
  GetOrCreateMissionOrderEntryForNode_t GetOrCreateMissionOrderEntryForNode_fn =
      reinterpret_cast<GetOrCreateMissionOrderEntryForNode_t>(0x5503a0);

  for (int i = 0; i < 2; ++i) {
    void* orderObj = orders[i];
    if (orderObj == nullptr) continue;
    if (i == 1 && orderObj == startOrder) continue;

    void* nodePtr = FindFirstTrackedHandlerMatchingModeAndShortKey(orderList24, reinterpret_cast<int>(orderObj));
    *reinterpret_cast<char*>(reinterpret_cast<char*>(nodePtr) + 0xc) = 1;
    void* entry = GetOrCreateMissionOrderEntryForNode_fn(orderObj, 0);

    if (*reinterpret_cast<int*>(reinterpret_cast<char*>(orderObj) + 8) == pContextAnchor) {
      AttachMissionOrderAsQueuedChildAndNotify(entry, this);
    } else {
      PromoteMapOrderChainAndQueue(entry, reinterpret_cast<void*>(pContextAnchor));
    }
  }
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
