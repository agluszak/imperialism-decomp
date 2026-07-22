// TNavyMission implementations.

#include <math.h>

#include "game/TNavyMission.h"
#include "game/TStream.h"
#include "game/TList.h"
#include "game/TZone.h"
#include "game/TShip.h"
#include "game/navy_order.h"
#include "game/TDiplomacyMgr.h"
#include "game/TTaskForce.h"
#include "game/global_data_tables.h"

IMPLEMENT_SERIAL(TNavyMission, TMission, 1)

// The binary body inlines TMission() (state08/importanceScore0c/marker11) and does NOT touch
// nationId04/pathMarker06; the vtable install lands mid-way through the zero stores.
// FUNCTION: IMPERIALISM 0x00535470
TNavyMission::TNavyMission(TZone* targetZone) : TMission() {
  targetZone14 = targetZone;
  targetZone18 = nullptr;
  selectedOrder1c = nullptr;
  taskForce20 = nullptr;
  orderList24 = nullptr;
  navyState28 = 0;
  for (int i = 0; i < 4; ++i) {
    requiredShipEquipageByCategory[i] = 0.0f;
  }
}

// Swaps float byte order (Big-Endian <-> Little-Endian)
static inline float SwapFloat(float val) {
  union {
    float f;
    unsigned char b[4];
  } swapped;
  swapped.f = val;
  unsigned char byte0 = swapped.b[0];
  unsigned char byte1 = swapped.b[1];
  swapped.b[0] = swapped.b[3];
  swapped.b[1] = swapped.b[2];
  swapped.b[2] = byte1;
  swapped.b[3] = byte0;
  return swapped.f;
}

// FUNCTION: IMPERIALISM 0x005354c0
void TNavyMission::GiveActionOrders(TTaskForce* mapOrderEntry) {
  (void)mapOrderEntry;
}

// FUNCTION: IMPERIALISM 0x005354e0
bool TNavyMission::IsNavyMission() const {
  return true;
}

// FUNCTION: IMPERIALISM 0x00535500
bool TNavyMission::IsANoBrainer() const {
  return false;
}

// FUNCTION: IMPERIALISM 0x00535520
TMission* TNavyMission::GetArmyMission() {
  return nullptr;
}

// FUNCTION: IMPERIALISM 0x00535540
TMission* TNavyMission::GetNavyMission() {
  return this;
}

// SYNTHETIC: IMPERIALISM 0x00535560
// TNavyMission::`scalar deleting destructor'

// SYNTHETIC: IMPERIALISM 0x00536390
// TNavyMission::CreateObject

namespace {

float NormalizeFourComponentNavyVector(const float* vector, float sum) {
  if (sum == static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065A9F0)) {
    return g_Recompute_Nation_Order_LookupTable_0065A9E8;
  }
  const short* lookupTable = g_Populate_Beachhead_Mission_LookupTable_00697958;
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
  short normalizationBase = orderNode->GetMaxStrength();
  if (normalizationBase == 0) {
    return;
  }
  float scale = static_cast<float>(orderNode->strength) / static_cast<float>(normalizationBase);
  int category = static_cast<int>(orderNode->strength % normalizationBase);

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
  if (taskForce20 != nullptr) {
    taskForce20->Free();
  }
  taskForce20 = nullptr;

  while (orderList24 != nullptr) {
    orderList24->payload = nullptr;
    orderList24 = orderList24->DeleteMapOrderChildLinkAndReturnNext();
  }

  if (this != nullptr) {
    delete this;
  }
}

// FUNCTION: IMPERIALISM 0x00536530
void TNavyMission::WriteTo(TStream* stream) {
  TMission::WriteTo(stream);

  int nodeIdx1 = targetZone14 != nullptr ? targetZone14->GetContextOrdinalOrInvalid() : -1;
  stream->WriteCountSlot88(nodeIdx1);

  int nodeIdx2 = targetZone18 != nullptr ? targetZone18->GetContextOrdinalOrInvalid() : -1;
  stream->WriteCountSlot88(nodeIdx2);

  for (int i = 0; i < 4; ++i) {
    float swapped = SwapFloat(requiredShipEquipageByCategory[i]);
    stream->WriteBytesSlot78(&swapped, 4);
  }

  // orderList24 payloads are TShip primary-order nodes (serialized by roster index).
  for (TMapOrderChildLinkNode* node = orderList24; node != nullptr; node = node->next) {
    int idx = static_cast<TShip*>(node->payload)->GetIndex();
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

  stream->ReadBytes(&requiredShipEquipageByCategory[0], 0x10);
  for (int i = 0; i < 4; ++i) {
    requiredShipEquipageByCategory[i] = SwapFloat(requiredShipEquipageByCategory[i]);
  }

  short nodeIdx = stream->ReadShort();
  if (nodeIdx > -1) {
    do {
      TShip* orderNode = TShip::GetNth(nodeIdx);
      AcceptReenforcement(orderNode, 0);
      nodeIdx = stream->ReadShort();
    } while (nodeIdx >= 0);
  }

  stream->ReadBytes(&navyState28, 4);
  selectedOrder1c = nullptr;
  if (taskForce20 != nullptr) {
    taskForce20->Free();
  }
  taskForce20 = nullptr;
}

// FUNCTION: IMPERIALISM 0x00536740
char TNavyMission::SmokeEmIfYouGotEm() {
  while (orderList24 != nullptr) {
    orderList24->payload = nullptr;
    orderList24 = orderList24->DeleteMapOrderChildLinkAndReturnNext();
  }
  return 1;
}

// FUNCTION: IMPERIALISM 0x00536780
void TNavyMission::AcceptReenforcement(TShip* item, unsigned char notify) {
  if (item->mission != nullptr) {
    item->mission->RejectConstituent(item, notify);
  }
  item->mission = this;
  TMapOrderChildLinkNode* node = orderList24->CreateLinkedOrderNode(item);
  orderList24 = node;
  if (notify != 0) {
    Reassess();
  }
}

// FUNCTION: IMPERIALISM 0x005367d0
void TNavyMission::RejectConstituent(TShip* item, unsigned char notify) {
  (void)notify;
  if (orderList24 != nullptr) {
    if (orderList24->payload == item) {
      orderList24 = orderList24->DeleteMapOrderChildLinkAndReturnNext();
    } else {
      orderList24->next->RemoveLinkedOrderNodeByValueRecursive(item);
    }
  }
  item->mission = nullptr;
  if (selectedOrder1c == item) {
    selectedOrder1c = nullptr;
  }
}

// FUNCTION: IMPERIALISM 0x00536810
void TNavyMission::ForgetTaskForce(TTaskForce* taskForce) {
  if (taskForce20 == taskForce) {
    taskForce20 = nullptr;
  }
}
// FUNCTION: IMPERIALISM 0x00536840
int TNavyMission::AccumulateLack(int* accumulatedLack, unsigned char includeExistingLack) const {
  float vector[4] = {0.0f, 0.0f, 0.0f, 0.0f};
  for (TMapOrderChildLinkNode* node = orderList24; node != nullptr; node = node->next) {
    TShip* ship = static_cast<TShip*>(node->payload);
    short distance = 0;
    if (GetActiveTargetZoneByState28() != nullptr) {
      distance = ship->GetTurnDistanceTo(GetActiveTargetZoneByState28());
    }
    if (distance > 5) {
      distance = 5;
    }
    float scale = g_MissionOrderDistanceDecayWeightTable_006978c8[distance] *
                  static_cast<float>(ship->strength / ship->GetMaxStrength());
    vector[0] +=
        static_cast<float>(ship->ComputeNavyOrderPriorityContributionPercentByCategory(0)) * scale;
    vector[1] +=
        static_cast<float>(ship->ComputeNavyOrderPriorityContributionPercentByCategory(1)) * scale;
    vector[2] +=
        static_cast<float>(ship->ComputeNavyOrderPriorityContributionPercentByCategory(2)) * scale;
    vector[3] +=
        static_cast<float>(ship->ComputeNavyOrderPriorityContributionPercentByCategory(3)) * scale;
  }

  int total = 0;
  for (int i = 0; i < 4; ++i) {
    float delta = requiredShipEquipageByCategory[i] - vector[i];
    if (includeExistingLack != 0 && requiredShipEquipageByCategory[i] < vector[i]) {
      delta *= g_NavyMissionQueuedWeightDeficitScale_0065A958;
    }
    accumulatedLack[i + 5] = static_cast<int>(static_cast<float>(accumulatedLack[i + 5]) + delta);
    total += accumulatedLack[i + 5];
  }
  return total;
}

// FUNCTION: IMPERIALISM 0x00536b30
void TNavyMission::Reassess() {

  SetStateByte8To2();
  CalculateImportance();
  CalculateNeeds();

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
      targetZone18 = RefreshMissionPortZoneContextForNation();
    }
  }
}

// FUNCTION: IMPERIALISM 0x00536d60
void TNavyMission::CombineForce(TZone* location, TTaskForce*& taskForce) {
  if (taskForce != nullptr && taskForce->location != location) {
    taskForce->Free();
    taskForce = nullptr;
  }

  for (TMapOrderChildLinkNode* node = orderList24; node != nullptr; node = node->next) {
    TShip* ship = static_cast<TShip*>(node->payload);
    if (ship->location != location) {
      continue;
    }
    if (taskForce == nullptr) {
      taskForce = new TTaskForce(location, nationId04);
      taskForce->ITaskForce();
    }
    ship->ReassignToForce(taskForce);
  }
}

// FUNCTION: IMPERIALISM 0x00536e40
void TNavyMission::GiveOrders() {
  if (orderList24 != nullptr) {
    orderList24->active = 0;
    orderList24->next->SetChainActiveFlag(0);
  }

  if (navyState28 == 2) {
    ConsolidateMissionOrderEntriesByTargetAndQueue(targetZone14);
    CombineForce(targetZone14, taskForce20);
    if (taskForce20 != nullptr) {
      GiveActionOrders(taskForce20);
    }
    return;
  }

  if (navyState28 == 1) {
    ConsolidateMissionOrderEntriesByTargetAndQueue(targetZone14);
    CombineForce(targetZone14, taskForce20);
    if (taskForce20 != nullptr) {
      taskForce20->OrderEvade();
    }
    return;
  }

  if (navyState28 == 0) {
    if (targetZone18 == nullptr) {
      targetZone18 = RefreshMissionPortZoneContextForNation();
    }
    QueueMissionOrdersByPriorityForContext(targetZone14, &selectedOrder1c);
    ConsolidateMissionOrderEntriesByTargetAndQueue(targetZone18);
    CombineForce(targetZone18, taskForce20);
    if (taskForce20 != nullptr) {
      taskForce20->SetAggression(0);
      taskForce20->OrderPatrol(0);
    }
  }
}

// FUNCTION: IMPERIALISM 0x00536fa0
TZone* TNavyMission::RefreshMissionPortZoneContextForNation() {
  return targetZone14->SelectBestPrimaryNeighborForNationDiplomacyMask(nationId04);
}

// FUNCTION: IMPERIALISM 0x00536fc0
TMission* TNavyMission::GetReplacementSlot48() {
  if (targetZone18 != nullptr) {
    if (targetZone18->QueryPortZoneCapability() != 0) {
      if (targetZone18->QueryZoneCapabilityFlagD(nationId04) == 0) {
        targetZone18 = RefreshMissionPortZoneContextForNation();
      }
    }
  }
  return (targetZone18 != nullptr) ? this : nullptr;
}

// FUNCTION: IMPERIALISM 0x00537060
TZone* TNavyMission::GetActiveTargetZoneByState28() const {
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
void TNavyMission::QueueMissionOrdersByPriorityForContext(TZone* location, TShip** selectedOrder) {
  // Was bridged through a mis-targeted TMission::Find
  // cdecl stub cast (a name collision with the unrelated real function at 0x535940); the
  // actual callee here (verified via the 0x40635c ILT thunk row) is the already-ported
  // TMapOrderChildLinkNode::FindNodeMatching (0x552510).
  if (*selectedOrder != nullptr && orderList24->FindNodeMatching(*selectedOrder) == nullptr) {
    *selectedOrder = nullptr;
  }

  int maxScore = -1;
  TShip* topOrder = nullptr;

  // Was bridged through a mis-targeted "CompareMissionOrderEntriesByPriorityScore" cdecl
  // stub cast (a name collision with the unrelated real function at 0x536090); the actual
  // callee here (verified via the 0x403e77 ILT thunk row) is the already-ported
  // TTaskForce::ComputeValueForMission (0x5501b0).
  for (TMapOrderChildLinkNode* node = orderList24; node != nullptr; node = node->next) {
    int score = static_cast<TShip*>(node->payload)->ComputeValueForMission(3);
    if (maxScore < score) {
      topOrder = static_cast<TShip*>(node->payload);
      maxScore = score;
    }
  }

  if (topOrder != nullptr) {
    if (topOrder == *selectedOrder) {
      topOrder = nullptr;
    } else {
      if (*selectedOrder != nullptr) {
        // Ground truth (0x537090): the original compares the *existing selection's*
        // zone-distance against the *candidate's* zone-distance, both to targetZone14 --
        // the prior port dropped this argument and used targetZone14 itself as a fake
        // receiver for target1 instead of selectedOrder.
        short target1 = (*selectedOrder)->GetTurnDistanceTo(targetZone14);
        short target2 = topOrder->GetTurnDistanceTo(targetZone14);
        if (target1 < target2) {
          goto LAB_0053711a;
        }
      }
      *selectedOrder = topOrder;
      topOrder = nullptr;
    }
  }

LAB_0053711a:
  TShip* startOrder = *selectedOrder;
  for (TShip* order = startOrder; (order == startOrder || order == topOrder) && order != nullptr;
       order += topOrder - startOrder) {
    TMapOrderChildLinkNode* node = orderList24->FindNodeMatching(order);
    node->active = 1;
    TTaskForce* entry = order->DemandExclusiveTaskForce();

    if (order->location == location) {
      entry->OrderEvade();
    } else {
      entry->OrderSailTowards(location);
    }
  }
}

// FUNCTION: IMPERIALISM 0x005371d0
void TNavyMission::ConsolidateMissionOrderEntriesByTargetAndQueue(TZone* location) {
  for (TMapOrderChildLinkNode* node = orderList24; node != nullptr; node = node->next) {
    if (node->active == 0) {
      node->active = 1;
      TTaskForce* entry = static_cast<TShip*>(node->payload)->DemandExclusiveTaskForce();
      for (TMapOrderChildLinkNode* other = orderList24; other != nullptr; other = other->next) {
        if (other->active == 0 &&
            static_cast<TShip*>(other->payload)->location == entry->location) {
          static_cast<TShip*>(other->payload)->ReassignToForce(entry);
          other->active = 1;
        }
      }
      entry->OrderSailTowards(location);
    }
  }
}

// Adds one order node's 4-category priority contribution into `vector`, categories

// Scores how the mission's aggregate order profile matches its resource weights when
// the candidate order is added (foreign candidate) or removed (own candidate),
// relative to the current-profile score from slot 0x68.
// FUNCTION: IMPERIALISM 0x00537270
float TNavyMission::ValueOf(TShip* candidate) {
  if (flag10 != 0) {
    return g_Recompute_Nation_Order_LookupTable_0065A9E8;
  }
  TShip* orderNode = candidate;
  float profile[4];
  if (orderNode->mission == this) {
    profile[0] = 0.0f;
    profile[1] = 0.0f;
    profile[2] = 0.0f;
    profile[3] = 0.0f;
    for (TMapOrderChildLinkNode* node = orderList24; node != 0; node = node->next) {
      TShip* entry = static_cast<TShip*>(node->payload);
      short bucket;
      if (GetActiveTargetZoneByState28() != 0) {
        bucket = entry->GetTurnDistanceTo(GetActiveTargetZoneByState28());
      } else {
        bucket = 0;
      }
      if (bucket > 5) {
        bucket = 5;
      }
      AccumulateNavyOrderCategoryVectorWithScale(
          entry, profile, g_MissionOrderDistanceDecayWeightTable_006978c8[bucket]);
    }
    short bucket;
    if (GetActiveTargetZoneByState28() != 0) {
      bucket = orderNode->GetTurnDistanceTo(GetActiveTargetZoneByState28());
    } else {
      bucket = 0;
    }
    if (bucket > 5) {
      bucket = 5;
    }
    float weight = static_cast<float>(g_MissionOrderDistanceDecayWeightTable_006978c8[bucket] *
                                      g_Recompute_Nation_Order_LookupTable_0065A9E0);
    float scaledRatio =
        weight * static_cast<float>(orderNode->strength / orderNode->GetMaxStrength());
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
      sqrtSum += static_cast<float>(
          sqrt(requiredShipEquipageByCategory[componentIndex] * profile[componentIndex]));
      weightSum += requiredShipEquipageByCategory[componentIndex];
    }
    return GetWeightedSatisfaction() - sqrtSum / weightSum;
  }
  profile[0] = 0.0f;
  profile[1] = 0.0f;
  profile[2] = 0.0f;
  profile[3] = 0.0f;
  for (TMapOrderChildLinkNode* node = orderList24; node != 0; node = node->next) {
    TShip* entry = static_cast<TShip*>(node->payload);
    short bucket;
    if (GetActiveTargetZoneByState28() != 0) {
      bucket = entry->GetTurnDistanceTo(GetActiveTargetZoneByState28());
    } else {
      bucket = 0;
    }
    if (bucket > 5) {
      bucket = 5;
    }
    AccumulateNavyOrderCategoryVectorWithScale(
        entry, profile, g_MissionOrderDistanceDecayWeightTable_006978c8[bucket]);
  }
  short bucket;
  if (GetActiveTargetZoneByState28() != 0) {
    bucket = orderNode->GetTurnDistanceTo(GetActiveTargetZoneByState28());
  } else {
    bucket = 0;
  }
  if (bucket > 5) {
    bucket = 5;
  }
  AccumulateNavyOrderCategoryVectorWithScale(
      orderNode, profile, g_MissionOrderDistanceDecayWeightTable_006978c8[bucket]);
  float sqrtSum = g_Recompute_Nation_Order_LookupTable_0065A9E8;
  float weightSum = g_Recompute_Nation_Order_LookupTable_0065A9E8;
  for (int componentIndex = 0; componentIndex < 4; ++componentIndex) {
    sqrtSum += static_cast<float>(
        sqrt(requiredShipEquipageByCategory[componentIndex] * profile[componentIndex]));
    weightSum += requiredShipEquipageByCategory[componentIndex];
  }
  return sqrtSum / weightSum - GetWeightedSatisfaction();
}

// Scores how badly a candidate navy order node fits this mission's target profile:
// squared distance between the node's normalized 4-category priority vector and the
// profile floats at targetProfile+0x10, plus a distance-bucket weight from the score
// table and an understock penalty.
// FUNCTION: IMPERIALISM 0x00537610
float TNavyMission::FitnessOf(TShip* candidate, float* targetProfile) {
  TShip* orderNode = candidate;
  int stockRatio = orderNode->strength / orderNode->GetMaxStrength();
  if (static_cast<float>(stockRatio) < g_Recompute_Nation_Order_LookupTable_0065AA20 &&
      !IsANoBrainer()) {
    return g_Recompute_Nation_Order_LookupTable_0065A9C4;
  }
  float profile[4] = {0.0f, 0.0f, 0.0f, 0.0f};
  short distanceBucket;
  if (GetActiveTargetZoneByState28() != 0) {
    distanceBucket = orderNode->GetTurnDistanceTo(GetActiveTargetZoneByState28());
  } else {
    distanceBucket = 0;
  }
  short clampedBucket = distanceBucket > 5 ? 5 : distanceBucket;
  float bucketWeight =
      g_ArmyMissionCandidateScoreTable_006978f8[static_cast<char>(state08) * 6 + clampedBucket];
  float scale = static_cast<float>(orderNode->strength / orderNode->GetMaxStrength());
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
  const float* targetVector = targetProfile;
  for (componentIndex = 0; componentIndex < 4; ++componentIndex) {
    float delta = profile[componentIndex] / sum - targetVector[componentIndex + 4];
    sumSquares = delta * delta + sumSquares;
  }
  double understockPenalty;
  if (!IsANoBrainer() && orderNode->strength < orderNode->GetMaxStrength()) {
    understockPenalty = (g_Recompute_Nation_Order_LookupTable_0065AA08 -
                         static_cast<double>(orderNode->strength / orderNode->GetMaxStrength())) *
                        g_Recompute_Nation_Order_LookupTable_0065A9BC;
  } else {
    understockPenalty = g_Recompute_Nation_Order_LookupTable_0065A9F0;
  }
  return static_cast<float>((sumSquares + bucketWeight) + understockPenalty);
}

// FUNCTION: IMPERIALISM 0x005378c0
float TNavyMission::IndustrialCostOfNeeds() {
  double total = 0.0;
  for (int i = 0; i < 4; ++i) {
    total += static_cast<double>(requiredShipEquipageByCategory[i]);
  }
  return static_cast<float>(total);
}
// Builds a per-category priority vector over every orderList24 ship: a ship counts if
// it's within `distanceThreshold` hops of `nearZone` (or unconditionally when `nearZone`
// is null), OR -- when farther than that -- if it's within `distanceThreshold` hops of
// `farZone` instead (when farZone is both non-null and != nearZone). The per-ship
// contribution accumulation (ratio = strength/normalizationBase, categories 0-2
// scaled by ratio, category 3 unscaled) is reproduced inline at both convergent call
// sites rather than via AccumulateNavyOrderCategoryVectorWithScale -- this specific
// function inlines its own copy in the original rather than calling out to 0x537c60.
// FUNCTION: IMPERIALISM 0x00537900
void TNavyMission::BuildNavyOrderCategoryVectorForNationWithExclusion(float* vector,
                                                                      TZone* nearZone,
                                                                      short distanceThreshold,
                                                                      TZone* farZone) {
  vector[0] = 0.0f;
  vector[1] = 0.0f;
  vector[2] = 0.0f;
  vector[3] = 0.0f;
  if (farZone == nearZone) {
    farZone = nullptr;
  }
  for (TMapOrderChildLinkNode* node = orderList24; node != nullptr; node = node->next) {
    TShip* ship = static_cast<TShip*>(node->payload);
    bool inRange = true;
    if (nearZone != nullptr && ship->GetTurnDistanceTo(nearZone) > distanceThreshold) {
      inRange = farZone != nullptr && ship->GetTurnDistanceTo(farZone) <= distanceThreshold;
    }
    if (inRange) {
      short normBase = ship->GetMaxStrength();
      float ratio = static_cast<float>(ship->strength / normBase);
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

// Shared helper for Reassess (0x536b30's inlined similarity-ratio computation).
float TNavyMission::ComputeNavyOrderCategorySimilarityRatio(int excludeCurrent) {
  float vector[4];
  BuildNavyOrderCategoryVectorForNationWithExclusion(
      vector, targetZone14, static_cast<short>(excludeCurrent), targetZone18);
  float numerator = 0.0f;
  float denominator = 0.0f;
  for (int i = 0; i < 4; ++i) {
    numerator += sqrtf(requiredShipEquipageByCategory[i] * vector[i]);
    denominator += requiredShipEquipageByCategory[i];
  }
  return numerator / denominator;
}
// 0-2 scaled by (stock/normalization base)*scale and category 3 by scale alone.
// FUNCTION: IMPERIALISM 0x00537c60
void __cdecl AccumulateNavyOrderCategoryVectorWithScale(TShip* orderNode, float* vector,
                                                        float scale) {
  float ratio = static_cast<float>(orderNode->strength / orderNode->GetMaxStrength()) * scale;
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

// Same per-ship math as AccumulateNavyOrderCategoryVectorWithScale (ratio =
// (strength/normalizationBase)*weight, categories 0-2 scaled by ratio, category 3 by
// the raw distance weight alone), but the weight itself is derived per-ship from the
// active target zone's hop distance rather than passed in by the caller. Reproduced
// inline (not via a call to 0x537c60) to match the original, which inlines its own copy
// here rather than calling out.
// FUNCTION: IMPERIALISM 0x00537d40
void TNavyMission::BuildMissionQueuedOrderCategoryVector(float* vector) {
  vector[0] = 0.0f;
  vector[1] = 0.0f;
  vector[2] = 0.0f;
  vector[3] = 0.0f;
  for (TMapOrderChildLinkNode* node = orderList24; node != nullptr; node = node->next) {
    TShip* ship = static_cast<TShip*>(node->payload);
    TZone* targetZone = GetActiveTargetZoneByState28();
    short distanceIndex = 0;
    if (targetZone != nullptr) {
      distanceIndex = ship->GetTurnDistanceTo(GetActiveTargetZoneByState28());
    }
    if (distanceIndex > 5) {
      distanceIndex = 5;
    }
    float weight = g_MissionOrderDistanceDecayWeightTable_006978c8[distanceIndex];
    float ratio = static_cast<float>(ship->strength / ship->GetMaxStrength()) * weight;
    vector[0] +=
        static_cast<float>(ship->ComputeNavyOrderPriorityContributionPercentByCategory(0)) * ratio;
    vector[1] +=
        static_cast<float>(ship->ComputeNavyOrderPriorityContributionPercentByCategory(1)) * ratio;
    vector[2] +=
        static_cast<float>(ship->ComputeNavyOrderPriorityContributionPercentByCategory(2)) * ratio;
    vector[3] +=
        static_cast<float>(ship->ComputeNavyOrderPriorityContributionPercentByCategory(3)) * weight;
  }
}

// Same shape as ComputeNavyOrderCategorySimilarityRatio above, but always scores against
// targetZone14 (near) / targetZone18 (far), with an explicit
// caller-supplied distance threshold instead of a fixed 0/1.
// FUNCTION: IMPERIALISM 0x00537eb0
float TNavyMission::ComputeMissionQueuedOrderSimilarityForTargetNation(short distanceThreshold) {
  float vector[4];
  BuildNavyOrderCategoryVectorForNationWithExclusion(vector, targetZone14, distanceThreshold,
                                                     targetZone18);
  float numerator = 0.0f;
  float denominator = 0.0f;
  for (int i = 0; i < 4; ++i) {
    numerator += sqrtf(requiredShipEquipageByCategory[i] * vector[i]);
    denominator += requiredShipEquipageByCategory[i];
  }
  return numerator / denominator;
}

// FUNCTION: IMPERIALISM 0x00537f40
float TNavyMission::GetWeightedSatisfaction() {
  float vector[4] = {0.0f, 0.0f, 0.0f, 0.0f};
  for (TMapOrderChildLinkNode* node = orderList24; node != nullptr; node = node->next) {
    TShip* ship = static_cast<TShip*>(node->payload);
    short distance = 0;
    if (GetActiveTargetZoneByState28() != nullptr) {
      distance = ship->GetTurnDistanceTo(GetActiveTargetZoneByState28());
    }
    if (distance > 5) {
      distance = 5;
    }
    float scale = g_MissionOrderDistanceDecayWeightTable_006978c8[distance] *
                  static_cast<float>(ship->strength / ship->GetMaxStrength());
    for (int categoryIndex = 0; categoryIndex < 4; ++categoryIndex) {
      vector[categoryIndex] +=
          static_cast<float>(
              ship->ComputeNavyOrderPriorityContributionPercentByCategory(categoryIndex)) *
          scale;
    }
  }

  float numerator = 0.0f;
  float denominator = 0.0f;
  for (int scoreIndex = 0; scoreIndex < 4; ++scoreIndex) {
    if (requiredShipEquipageByCategory[scoreIndex] < vector[scoreIndex]) {
      vector[scoreIndex] = requiredShipEquipageByCategory[scoreIndex] +
                           (vector[scoreIndex] - requiredShipEquipageByCategory[scoreIndex]) *
                               g_NavyMissionSimilarityExcessBlend_0065A960;
    }
    numerator += sqrtf(requiredShipEquipageByCategory[scoreIndex] * vector[scoreIndex]);
    denominator += requiredShipEquipageByCategory[scoreIndex];
  }
  return numerator / denominator;
}
// Weights all 4 categories uniformly by (strength/normalizationBase) * a
// distance-decay factor (0.8^hopDistance, clamped to index 5) from a per-ship
// accumulator, over every existing orderList24 ship plus `candidateOrder`, then scores
// the resulting vector against requiredShipEquipageByCategory via a Bhattacharyya-coefficient-style
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
    TShip* ship = static_cast<TShip*>(node->payload);
    TZone* targetZone = GetActiveTargetZoneByState28();
    short distanceIndex = 0;
    if (targetZone != nullptr) {
      distanceIndex = ship->GetTurnDistanceTo(GetActiveTargetZoneByState28());
    }
    if (distanceIndex > 5) {
      distanceIndex = 5;
    }
    float scale = g_MissionOrderDistanceDecayWeightTable_006978c8[distanceIndex] *
                  static_cast<float>(ship->strength / ship->GetMaxStrength());
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
    distanceIndex = candidateOrder->GetTurnDistanceTo(GetActiveTargetZoneByState28());
  }
  if (distanceIndex > 5) {
    distanceIndex = 5;
  }
  float scale = g_MissionOrderDistanceDecayWeightTable_006978c8[distanceIndex] *
                static_cast<float>(candidateOrder->strength / candidateOrder->GetMaxStrength());
  for (int componentIndex = 0; componentIndex < 4; ++componentIndex) {
    vector[componentIndex] +=
        static_cast<float>(
            candidateOrder->ComputeNavyOrderPriorityContributionPercentByCategory(componentIndex)) *
        scale;
  }

  float sumWeights = g_Recompute_Nation_Order_LookupTable_0065A9E8;
  float coefficient = g_Recompute_Nation_Order_LookupTable_0065A9E8;
  for (int i = 0; i < 4; ++i) {
    sumWeights += requiredShipEquipageByCategory[i];
    coefficient += sqrtf(requiredShipEquipageByCategory[i] * vector[i]);
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
    TShip* ship = static_cast<TShip*>(node->payload);
    TZone* targetZone = GetActiveTargetZoneByState28();
    short distanceIndex = 0;
    if (targetZone != nullptr) {
      distanceIndex = ship->GetTurnDistanceTo(GetActiveTargetZoneByState28());
    }
    if (distanceIndex > 5) {
      distanceIndex = 5;
    }
    float scale = g_MissionOrderDistanceDecayWeightTable_006978c8[distanceIndex] *
                  static_cast<float>(ship->strength / ship->GetMaxStrength());
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
    distanceIndex = candidateOrder->GetTurnDistanceTo(GetActiveTargetZoneByState28());
  }
  if (distanceIndex > 5) {
    distanceIndex = 5;
  }
  float scale = g_MissionOrderDistanceDecayWeightTable_006978c8[distanceIndex] *
                static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065A9E0) *
                static_cast<float>(candidateOrder->strength / candidateOrder->GetMaxStrength());
  for (int componentIndex = 0; componentIndex < 4; ++componentIndex) {
    vector[componentIndex] +=
        static_cast<float>(
            candidateOrder->ComputeNavyOrderPriorityContributionPercentByCategory(componentIndex)) *
        scale;
  }

  float sumWeights = g_Recompute_Nation_Order_LookupTable_0065A9E8;
  float coefficient = g_Recompute_Nation_Order_LookupTable_0065A9E8;
  for (int i = 0; i < 4; ++i) {
    sumWeights += requiredShipEquipageByCategory[i];
    coefficient += sqrtf(requiredShipEquipageByCategory[i] * vector[i]);
  }
  return coefficient / sumWeights;
}

// FUNCTION: IMPERIALISM 0x005389f0
float TNavyMission::ComputeOrderDistributionSimilarityScoreWithDiplomacyFilter(int sourceNation,
                                                                               TZone* nodeContext) {
  float vector[4] = {0.0f, 0.0f, 0.0f, 0.0f};
  for (TShip* orderNode = TShip::GetFirst(); orderNode != 0; orderNode = orderNode->next) {
    if (orderNode->location == nodeContext &&
        g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(static_cast<short>(sourceNation),
                                                                orderNode->nation) != 0) {
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
  for (TShip* orderNode = TShip::GetFirst(); orderNode != 0; orderNode = orderNode->next) {
    if (orderNode->location == nodeContext &&
        static_cast<short>(sourceNation) == orderNode->nation) {
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
  for (TShip* orderNode = TShip::GetFirst(); orderNode != 0; orderNode = orderNode->next) {
    if (orderNode->location == nodeContext &&
        g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(nationId04, orderNode->nation) !=
            0) {
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
  selectedOrder1c = nullptr;
  taskForce20 = nullptr;
  orderList24 = nullptr;
  navyState28 = 0;
  for (int i = 0; i < 4; ++i) {
    requiredShipEquipageByCategory[i] = 0.0f;
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
  for (TShip* orderNode = TShip::GetFirst(); orderNode != 0; orderNode = orderNode->next) {
    if (orderNode->location == nodeContext &&
        g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(nationId04, orderNode->nation) !=
            0) {
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
    float vector[4] = {0.0f, 0.0f, 0.0f, 0.0f};
    for (TShip* ship = TShip::GetFirst(); ship != nullptr; ship = ship->next) {
      if (ship->nation == ownerNation && ship->IsInHomePort() &&
          ship->GetMaxStrength() <= ship->strength) {
        float stockRatio = static_cast<float>(ship->strength / ship->GetMaxStrength());
        vector[0] =
            static_cast<float>(ship->ComputeNavyOrderPriorityContributionPercentByCategory(0)) *
                stockRatio +
            vector[0];
        vector[1] =
            static_cast<float>(ship->ComputeNavyOrderPriorityContributionPercentByCategory(1)) *
                stockRatio +
            vector[1];
        vector[2] =
            static_cast<float>(ship->ComputeNavyOrderPriorityContributionPercentByCategory(2)) *
                stockRatio +
            vector[2];
        vector[3] =
            static_cast<float>(ship->ComputeNavyOrderPriorityContributionPercentByCategory(3)) +
            vector[3];
      }
    }
    float total = g_Recompute_Nation_Order_LookupTable_0065A9E8;
    float* component = vector;
    for (int remaining = 4; remaining != 0; --remaining) {
      total += *component++;
    }
    if (total == static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065A9F0)) {
      return g_Recompute_Nation_Order_LookupTable_0065A9E8;
    }
    float diffSum = g_Recompute_Nation_Order_LookupTable_0065A9E8;
    const short* targetWeight = g_NavyOrderDistributionCategoryWeights_00697978;
    component = vector;
    while (targetWeight < g_NavyOrderDistributionCategoryWeights_00697978 + 4) {
      float diff = *component / total -
                   static_cast<float>(*targetWeight) *
                       static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065A9F8);
      if (diff <= static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065A9F0)) {
        diff = -diff;
      }
      diffSum += diff;
      ++targetWeight;
      ++component;
    }
    return total * (static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065AA08) -
                    diffSum * static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065AA00));
  }

  for (short allyIdx = 0; allyIdx < 7; ++allyIdx) {
    if (g_apNationStates[allyIdx] != nullptr &&
        g_pDiplomacyTurnStateManager->HasPolicyWithNationSlot44(nationId04, allyIdx) != 0) {
      short scoreNation = portZone->GetPortZoneOwnerNationCodeFromMissionField48();
      float vector[4] = {0.0f, 0.0f, 0.0f, 0.0f};
      for (TShip* ship = TShip::GetFirst(); ship != nullptr; ship = ship->next) {
        if (ship->nation == scoreNation && ship->IsInHomePort() &&
            ship->GetMaxStrength() <= ship->strength) {
          float stockRatio = static_cast<float>(ship->strength / ship->GetMaxStrength());
          vector[0] =
              static_cast<float>(ship->ComputeNavyOrderPriorityContributionPercentByCategory(0)) *
                  stockRatio +
              vector[0];
          vector[1] =
              static_cast<float>(ship->ComputeNavyOrderPriorityContributionPercentByCategory(1)) *
                  stockRatio +
              vector[1];
          vector[2] =
              static_cast<float>(ship->ComputeNavyOrderPriorityContributionPercentByCategory(2)) *
                  stockRatio +
              vector[2];
          vector[3] =
              static_cast<float>(ship->ComputeNavyOrderPriorityContributionPercentByCategory(3)) +
              vector[3];
        }
      }
      float total = g_Recompute_Nation_Order_LookupTable_0065A9E8;
      float* component = vector;
      for (int remaining = 4; remaining != 0; --remaining) {
        total += *component++;
      }
      float score = g_Recompute_Nation_Order_LookupTable_0065A9E8;
      if (total != static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065A9F0)) {
        float diffSum = g_Recompute_Nation_Order_LookupTable_0065A9E8;
        const short* targetWeight = g_NavyOrderDistributionCategoryWeights_00697978;
        component = vector;
        while (targetWeight < g_NavyOrderDistributionCategoryWeights_00697978 + 4) {
          float diff = *component / total -
                       static_cast<float>(*targetWeight) *
                           static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065A9F8);
          if (diff <= static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065A9F0)) {
            diff = -diff;
          }
          diffSum += diff;
          ++targetWeight;
          ++component;
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

// SYNTHETIC: IMPERIALISM 0x00536450
// TNavyMission::GetRuntimeClass
