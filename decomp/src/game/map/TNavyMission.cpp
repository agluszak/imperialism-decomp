// TNavyMission implementations.

#include <math.h>

#include "game/map/TNavyMission.h"
#include "game/core/stream_byteswap.h"
#include "game/core/TStream.h"
#include "game/TList.h"
#include "game/map/TZone.h"
#include "game/navy/TShip.h"
#include "game/navy_order.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/navy/TTaskForce.h"
#include "game/globals/global_types.h"
#include "game/globals/military_globals.h"
#include "game/globals/navy_globals.h"
#include "game/globals/shared_globals.h"

// FUNCTION: IMPERIALISM 0x00535470
TNavyMission::TNavyMission(TZone* targetZone)
    : TMission(), missionTargetZone(targetZone), resolvedPortZone(nullptr), selectedOrder(nullptr),
      taskForce(nullptr), orderList(nullptr), navyState(0) {
  for (int i = 0; i < 4; ++i) {
    requiredShipEquipageByCategory[i] = 0.0f;
  }
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

IMPLEMENT_SERIAL(TNavyMission, TMission, 1)

// FUNCTION: IMPERIALISM 0x005364c0
void TNavyMission::Free() {
  if (taskForce != nullptr) {
    taskForce->Free();
  }
  taskForce = nullptr;

  while (orderList != nullptr) {
    orderList->payload->mission = nullptr;
    orderList = orderList->DeleteMapOrderChildLinkAndReturnNext();
  }

  if (this != nullptr) {
    delete this;
  }
}

// FUNCTION: IMPERIALISM 0x00536530
void TNavyMission::WriteTo(TStream* stream) {
  TMission::WriteTo(stream);

  int nodeIdx1 =
      missionTargetZone != nullptr ? missionTargetZone->GetContextOrdinalOrInvalid() : -1;
  stream->WriteInteger(nodeIdx1);

  int nodeIdx2 = resolvedPortZone != nullptr ? resolvedPortZone->GetContextOrdinalOrInvalid() : -1;
  stream->WriteInteger(nodeIdx2);

  WriteFloatArrayElems(stream, requiredShipEquipageByCategory, 4);

  // orderList payloads are TShip primary-order nodes (serialized by roster index).
  for (TMapOrderChildLinkNode* node = orderList; node != nullptr; node = node->next) {
    int idx = node->payload->GetIndex();
    stream->WriteInteger(idx);
  }
  stream->WriteInteger(-1);

  stream->WriteBytes(&navyState, 4);
}

// FUNCTION: IMPERIALISM 0x00536650
void TNavyMission::ReadFrom(TStream* stream) {
  TMission::ReadFrom(stream);

  short targetZoneId = stream->ReadInteger();
  missionTargetZone = FindMapActionContextByNodeId(targetZoneId);

  short secondaryZoneId = stream->ReadInteger();
  resolvedPortZone = FindMapActionContextByNodeId(secondaryZoneId);

  stream->ReadBytes(&requiredShipEquipageByCategory[0], 0x10);
  // In-place four-byte reverse over the array (0x53669e), not a per-element temporary.
  ReverseDwordArrayBytes(requiredShipEquipageByCategory, 4);

  short nodeIdx = stream->ReadInteger();
  if (nodeIdx > -1) {
    do {
      TShip* orderNode = TShip::GetNth(nodeIdx);
      AcceptReenforcement(orderNode, false);
      nodeIdx = stream->ReadInteger();
    } while (nodeIdx > -1);
  }

  stream->ReadBytes(&navyState, 4);
  selectedOrder = nullptr;
  if (taskForce != nullptr) {
    taskForce->Free();
  }
  taskForce = nullptr;
}

// FUNCTION: IMPERIALISM 0x00536740
bool TNavyMission::SmokeEmIfYouGotEm() {
  while (orderList != nullptr) {
    orderList->payload->mission = nullptr;
    orderList = orderList->DeleteMapOrderChildLinkAndReturnNext();
  }
  return true;
}

// FUNCTION: IMPERIALISM 0x00536780
void TNavyMission::AcceptReenforcement(TShip* item, bool notify) {
  if (item->mission != nullptr) {
    item->mission->RejectConstituent(item, notify);
  }
  item->mission = this;
  TMapOrderChildLinkNode* node = orderList->CreateLinkedOrderNode(item);
  orderList = node;
  if (notify) {
    Reassess();
  }
}

// FUNCTION: IMPERIALISM 0x005367d0
void TNavyMission::RejectConstituent(TShip* item, bool notify) {
  (void)notify;
  orderList = orderList->RemoveLinkedOrderNodeByValueRecursive(item);
  item->mission = nullptr;
  if (selectedOrder == item) {
    selectedOrder = nullptr;
  }
}

// FUNCTION: IMPERIALISM 0x00536810
void TNavyMission::ForgetTaskForce(TTaskForce* taskForce) {
  if (this->taskForce == taskForce) {
    this->taskForce = nullptr;
  }
}
// FUNCTION: IMPERIALISM 0x00536840
int TNavyMission::AccumulateLack(int* accumulatedLack, bool includeExistingLack) const {
  float vector[4] = {0.0f, 0.0f, 0.0f, 0.0f};
  for (TMapOrderChildLinkNode* node = orderList; node != nullptr; node = node->next) {
    TShip* ship = node->payload;
    short distance = 0;
    if (GetActiveTargetZoneByState28() != nullptr) {
      distance = ship->GetTurnDistanceTo(GetActiveTargetZoneByState28());
    }
    if (distance > 5) {
      distance = 5;
    }
    float scale = g_MissionOrderDistanceDecayWeightTable[distance] *
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
    if (includeExistingLack && requiredShipEquipageByCategory[i] < vector[i]) {
      delta *= g_NavyMissionQueuedWeightDeficitScale;
    }
    accumulatedLack[i + 5] = static_cast<int>(static_cast<float>(accumulatedLack[i + 5]) + delta);
    total += accumulatedLack[i + 5];
  }
  return total;
}

// Mac oracle: ComputeSeaZoneImportance.
// FUNCTION: IMPERIALISM 0x00536a40
float TNavyMission::ComputeSeaZoneImportance(TZone* zone) {
  float importance = static_cast<float>(zone->ComputeMapActionContextNodeValueAverage());

  for (TZone* port = TZone::GetFirstPortZone(); port != 0; port = port->GetNextPortZone()) {
    if (port->primaryNeighbors[0] == zone) {
      if (port->GetPortZoneOwnerNationCodeFromMissionField48() == nationId) {
        importance = importance * 1.5f;
      } else {
        importance = importance * 1.25f;
      }
    }
  }

  return importance / 5000.0f;
}

// FUNCTION: IMPERIALISM 0x00536b30
void TNavyMission::Reassess() {
  float vector[4];
  float numerator = 0.0f;
  float denominator = 0.0f;

  SetStateByte8To2();
  CalculateImportance();
  CalculateNeeds();

  missionTargetZone->IsZoneMaskOrArrayEntryPresentForKey(nationId);

  if (orderList == nullptr) {
    navyState = 0;
    return;
  }

  int mode = navyState;
  if (mode == 0) {
    ProjectEquipage(vector, missionTargetZone, 1, resolvedPortZone);
    for (int index = 0; index < 4; ++index) {
      numerator += sqrtf(requiredShipEquipageByCategory[index] * vector[index]);
      denominator += requiredShipEquipageByCategory[index];
    }
    if (1.0f <= numerator / denominator) {
      numerator = 0.0f;
      denominator = 0.0f;
      ProjectEquipage(vector, missionTargetZone, 0, resolvedPortZone);
      for (int index = 0; index < 4; ++index) {
        numerator += sqrtf(requiredShipEquipageByCategory[index] * vector[index]);
        denominator += requiredShipEquipageByCategory[index];
      }
      if (1.0f <= numerator / denominator) {
        navyState = 2;
        return;
      }
      navyState = 1;
    }
  } else if (mode == 1) {
    navyState = 2;
  } else if (mode == 2) {
    ProjectEquipage(vector, missionTargetZone, 1, resolvedPortZone);
    for (int index = 0; index < 4; ++index) {
      numerator += sqrtf(requiredShipEquipageByCategory[index] * vector[index]);
      denominator += requiredShipEquipageByCategory[index];
    }
    if (numerator / denominator < 0.8f) {
      navyState = 0;
      resolvedPortZone = RefreshMissionPortZoneContextForNation();
    }
  }
}

// FUNCTION: IMPERIALISM 0x00536d60
void TNavyMission::CombineForce(TZone* location, TTaskForce*& taskForce) {
  if (taskForce != nullptr && taskForce->location != location) {
    taskForce->Free();
    taskForce = nullptr;
  }

  for (TMapOrderChildLinkNode* node = orderList; node != nullptr; node = node->next) {
    TShip* ship = node->payload;
    if (ship->location != location) {
      continue;
    }
    if (taskForce == nullptr) {
      taskForce = new TTaskForce(location, nationId);
      taskForce->ITaskForce();
    }
    ship->ReassignToForce(taskForce);
  }
}

// FUNCTION: IMPERIALISM 0x00536e40
void TNavyMission::GiveOrders() {
  if (orderList != nullptr) {
    orderList->active = 0;
    orderList->next->SetChainActiveFlag(0);
  }

  if (navyState == 2) {
    ConsolidateMissionOrderEntriesByTargetAndQueue(missionTargetZone);
    CombineForce(missionTargetZone, taskForce);
    if (taskForce != nullptr) {
      GiveActionOrders(taskForce);
    }
    return;
  }

  if (navyState == 1) {
    ConsolidateMissionOrderEntriesByTargetAndQueue(missionTargetZone);
    CombineForce(missionTargetZone, taskForce);
    if (taskForce != nullptr) {
      taskForce->OrderEvade();
    }
    return;
  }

  if (navyState == 0) {
    if (resolvedPortZone == nullptr) {
      resolvedPortZone = RefreshMissionPortZoneContextForNation();
    }
    GiveReconOrders(missionTargetZone, &selectedOrder);
    ConsolidateMissionOrderEntriesByTargetAndQueue(resolvedPortZone);
    CombineForce(resolvedPortZone, taskForce);
    if (taskForce != nullptr) {
      taskForce->SetAggression(0);
      taskForce->OrderPatrol(false);
    }
  }
}

// FUNCTION: IMPERIALISM 0x00536fa0
TZone* TNavyMission::RefreshMissionPortZoneContextForNation() {
  return missionTargetZone->GetSafestNearbyZoneFor(nationId);
}

// FUNCTION: IMPERIALISM 0x00536fc0
TMission* TNavyMission::GetReplacement() {
  if (resolvedPortZone != nullptr) {
    if (resolvedPortZone->QueryPortZoneCapability()) {
      if (!resolvedPortZone->QueryZoneCapabilityFlagD(nationId)) {
        resolvedPortZone = RefreshMissionPortZoneContextForNation();
      }
    }
  }
  return (resolvedPortZone != nullptr) ? this : nullptr;
}

// FUNCTION: IMPERIALISM 0x00537010
TShip* TNavyMission::PickBestShipForMissionType(int missionType) const {
  TShip* best = nullptr;
  int bestValue = -1;
  for (TMapOrderChildLinkNode* node = orderList; node != nullptr; node = node->next) {
    // The payload is reloaded rather than cached, as the original does.
    int value = node->payload->ComputeValueForMission(missionType);
    if (value > bestValue) {
      best = node->payload;
      bestValue = value;
    }
  }
  return best;
}

// FUNCTION: IMPERIALISM 0x00537060
TZone* TNavyMission::GetActiveTargetZoneByState28() const {
  int state = navyState;
  if (state != 0) {
    if (state > 0 && state <= 2) {
      return missionTargetZone;
    }
    return 0;
  }
  return resolvedPortZone;
}

// FUNCTION: IMPERIALISM 0x00537090
void TNavyMission::GiveReconOrders(TZone* location, TShip** selectedOrder) {
  if (*selectedOrder != nullptr && orderList->FindNodeMatching(*selectedOrder) == nullptr) {
    *selectedOrder = nullptr;
  }

  int maxScore = -1;
  TShip* topOrder = nullptr;

  for (TMapOrderChildLinkNode* node = orderList; node != nullptr; node = node->next) {
    int score = node->payload->ComputeValueForMission(3);
    if (maxScore < score) {
      topOrder = node->payload;
      maxScore = score;
    }
  }

  if (topOrder != nullptr) {
    if (topOrder == *selectedOrder) {
      topOrder = nullptr;
    } else {
      if (*selectedOrder != nullptr) {
        short target1 = (*selectedOrder)->GetTurnDistanceTo(missionTargetZone);
        short target2 = topOrder->GetTurnDistanceTo(missionTargetZone);
        if (target1 < target2) {
          goto activateSelectedOrders;
        }
      }
      *selectedOrder = topOrder;
      topOrder = nullptr;
    }
  }

activateSelectedOrders:
  TShip* startOrder = *selectedOrder;
  for (TShip* order = startOrder; (order == startOrder || order == topOrder) && order != nullptr;
       order += topOrder - startOrder) {
    TMapOrderChildLinkNode* node = orderList->FindNodeMatching(order);
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
  for (TMapOrderChildLinkNode* node = orderList; node != nullptr; node = node->next) {
    if (node->active == 0) {
      node->active = 1;
      TTaskForce* entry = node->payload->DemandExclusiveTaskForce();
      for (TMapOrderChildLinkNode* other = orderList; other != nullptr; other = other->next) {
        if (other->active == 0 && other->payload->location == entry->location) {
          other->payload->ReassignToForce(entry);
          other->active = 1;
        }
      }
      entry->OrderSailTowards(location);
    }
  }
}

// Adds one order node's 4-category priority contribution into `vector`, categories

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
    for (TMapOrderChildLinkNode* node = orderList; node != 0; node = node->next) {
      TShip* entry = node->payload;
      short bucket;
      if (GetActiveTargetZoneByState28() != 0) {
        bucket = entry->GetTurnDistanceTo(GetActiveTargetZoneByState28());
      } else {
        bucket = 0;
      }
      if (bucket > 5) {
        bucket = 5;
      }
      AccumulateNavyOrderCategoryVectorWithScale(entry, profile,
                                                 g_MissionOrderDistanceDecayWeightTable[bucket]);
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
    float weight = static_cast<float>(g_MissionOrderDistanceDecayWeightTable[bucket] *
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
  for (TMapOrderChildLinkNode* node = orderList; node != 0; node = node->next) {
    TShip* entry = node->payload;
    short bucket;
    if (GetActiveTargetZoneByState28() != 0) {
      bucket = entry->GetTurnDistanceTo(GetActiveTargetZoneByState28());
    } else {
      bucket = 0;
    }
    if (bucket > 5) {
      bucket = 5;
    }
    AccumulateNavyOrderCategoryVectorWithScale(entry, profile,
                                               g_MissionOrderDistanceDecayWeightTable[bucket]);
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
  AccumulateNavyOrderCategoryVectorWithScale(orderNode, profile,
                                             g_MissionOrderDistanceDecayWeightTable[bucket]);
  float sqrtSum = g_Recompute_Nation_Order_LookupTable_0065A9E8;
  float weightSum = g_Recompute_Nation_Order_LookupTable_0065A9E8;
  for (int componentIndex = 0; componentIndex < 4; ++componentIndex) {
    sqrtSum += static_cast<float>(
        sqrt(requiredShipEquipageByCategory[componentIndex] * profile[componentIndex]));
    weightSum += requiredShipEquipageByCategory[componentIndex];
  }
  return sqrtSum / weightSum - GetWeightedSatisfaction();
}

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
      g_ArmyMissionCandidateScoreTable[static_cast<char>(state08) * 6 + clampedBucket];
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
    float delta = profile[componentIndex] / sum - targetVector[componentIndex + 5];
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
  return -static_cast<float>((sumSquares + bucketWeight) + understockPenalty);
}

// FUNCTION: IMPERIALISM 0x005378c0
float TNavyMission::IndustrialCostOfNeeds() {
  float total = g_Recompute_Nation_Order_LookupTable_0065A9E8;
  for (int i = 0; i < 4; ++i) {
    total += requiredShipEquipageByCategory[i] * g_NavyMissionIndustrialCostWeights[i];
  }
  return total;
}
// FUNCTION: IMPERIALISM 0x00537900
void TNavyMission::ProjectEquipage(float* vector, TZone* nearZone, short distanceThreshold,
                                   TZone* farZone) {
  vector[0] = 0.0f;
  vector[1] = 0.0f;
  vector[2] = 0.0f;
  vector[3] = 0.0f;
  if (farZone == nearZone) {
    farZone = nullptr;
  }
  for (TMapOrderChildLinkNode* node = orderList; node != nullptr; node = node->next) {
    TShip* ship = node->payload;
    if (nearZone == nullptr || ship->GetTurnDistanceTo(nearZone) <= distanceThreshold) {
      AccumulateNavyOrderCategoryVectorWithScale(ship, vector, 1.0f);
    } else if (farZone != nullptr && ship->GetTurnDistanceTo(farZone) <= distanceThreshold) {
      AccumulateNavyOrderCategoryVectorWithScale(ship, vector, 1.0f);
    }
  }
}

// FUNCTION: IMPERIALISM 0x00537b20
void TNavyMission::AccumulateWeightedShipEquipage(TShip* ship, float* vector, char positive) {
  short distanceIndex = 0;
  if (GetActiveTargetZoneByState28() != 0) {
    distanceIndex = ship->GetTurnDistanceTo(GetActiveTargetZoneByState28());
  }
  if (distanceIndex > 5) {
    distanceIndex = 5;
  }
  float weight =
      static_cast<float>((positive != 0 ? g_Recompute_Nation_Order_LookupTable_0065AA08
                                        : g_Recompute_Nation_Order_LookupTable_0065A9E0) *
                         g_MissionOrderDistanceDecayWeightTable[distanceIndex]);
  float ratio = static_cast<float>(ship->strength / ship->GetMaxStrength()) * weight;
  vector[0] =
      static_cast<float>(ship->ComputeNavyOrderPriorityContributionPercentByCategory(0)) * ratio +
      vector[0];
  vector[1] =
      static_cast<float>(ship->ComputeNavyOrderPriorityContributionPercentByCategory(1)) * ratio +
      vector[1];
  vector[2] =
      static_cast<float>(ship->ComputeNavyOrderPriorityContributionPercentByCategory(2)) * ratio +
      vector[2];
  vector[3] =
      static_cast<float>(ship->ComputeNavyOrderPriorityContributionPercentByCategory(3)) * weight +
      vector[3];
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

// FUNCTION: IMPERIALISM 0x00537d40
void TNavyMission::BuildMissionQueuedOrderCategoryVector(float* vector) {
  vector[0] = 0.0f;
  vector[1] = 0.0f;
  vector[2] = 0.0f;
  vector[3] = 0.0f;
  for (TMapOrderChildLinkNode* node = orderList; node != nullptr; node = node->next) {
    TShip* ship = node->payload;
    TZone* targetZone = GetActiveTargetZoneByState28();
    short distanceIndex = 0;
    if (targetZone != nullptr) {
      distanceIndex = ship->GetTurnDistanceTo(GetActiveTargetZoneByState28());
    }
    if (distanceIndex > 5) {
      distanceIndex = 5;
    }
    float weight = g_MissionOrderDistanceDecayWeightTable[distanceIndex];
    AccumulateNavyOrderCategoryVectorWithScale(ship, vector, weight);
  }
}

// FUNCTION: IMPERIALISM 0x00537eb0
float TNavyMission::ProjectSatisfaction(short distanceThreshold) {
  float vector[4];
  ProjectEquipage(vector, missionTargetZone, distanceThreshold, resolvedPortZone);
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
  for (TMapOrderChildLinkNode* node = orderList; node != nullptr; node = node->next) {
    TShip* ship = node->payload;
    short distance = 0;
    if (GetActiveTargetZoneByState28() != nullptr) {
      distance = ship->GetTurnDistanceTo(GetActiveTargetZoneByState28());
    }
    if (distance > 5) {
      distance = 5;
    }
    float scale = g_MissionOrderDistanceDecayWeightTable[distance] *
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

  float numerator = 0.0f;
  float denominator = 0.0f;
  for (int scoreIndex = 0; scoreIndex < 4; ++scoreIndex) {
    if (requiredShipEquipageByCategory[scoreIndex] < vector[scoreIndex]) {
      vector[scoreIndex] = requiredShipEquipageByCategory[scoreIndex] +
                           (vector[scoreIndex] - requiredShipEquipageByCategory[scoreIndex]) *
                               g_NavyMissionSimilarityExcessBlend;
    }
    numerator += sqrtf(requiredShipEquipageByCategory[scoreIndex] * vector[scoreIndex]);
    denominator += requiredShipEquipageByCategory[scoreIndex];
  }
  return numerator / denominator;
}
// FUNCTION: IMPERIALISM 0x00538120
float TNavyMission::ComputeMissionOrderMatchScoreWithCandidateNavyOrder(TShip* candidateOrder) {
  float vector[4] = {
      g_Recompute_Nation_Order_LookupTable_0065A9E8, g_Recompute_Nation_Order_LookupTable_0065A9E8,
      g_Recompute_Nation_Order_LookupTable_0065A9E8, g_Recompute_Nation_Order_LookupTable_0065A9E8};
  for (TMapOrderChildLinkNode* node = orderList; node != nullptr; node = node->next) {
    TShip* ship = node->payload;
    TZone* targetZone = GetActiveTargetZoneByState28();
    short distanceIndex = 0;
    if (targetZone != nullptr) {
      distanceIndex = ship->GetTurnDistanceTo(GetActiveTargetZoneByState28());
    }
    if (distanceIndex > 5) {
      distanceIndex = 5;
    }
    float scale = g_MissionOrderDistanceDecayWeightTable[distanceIndex] *
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

  TZone* targetZone = GetActiveTargetZoneByState28();
  short distanceIndex = 0;
  if (targetZone != nullptr) {
    distanceIndex = candidateOrder->GetTurnDistanceTo(GetActiveTargetZoneByState28());
  }
  if (distanceIndex > 5) {
    distanceIndex = 5;
  }
  float scale = g_MissionOrderDistanceDecayWeightTable[distanceIndex] *
                static_cast<float>(candidateOrder->strength / candidateOrder->GetMaxStrength());
  vector[0] +=
      static_cast<float>(candidateOrder->ComputeNavyOrderPriorityContributionPercentByCategory(0)) *
      scale;
  vector[1] +=
      static_cast<float>(candidateOrder->ComputeNavyOrderPriorityContributionPercentByCategory(1)) *
      scale;
  vector[2] +=
      static_cast<float>(candidateOrder->ComputeNavyOrderPriorityContributionPercentByCategory(2)) *
      scale;
  vector[3] +=
      static_cast<float>(candidateOrder->ComputeNavyOrderPriorityContributionPercentByCategory(3)) *
      scale;

  float sumWeights = g_Recompute_Nation_Order_LookupTable_0065A9E8;
  float coefficient = g_Recompute_Nation_Order_LookupTable_0065A9E8;
  for (int i = 0; i < 4; ++i) {
    sumWeights += requiredShipEquipageByCategory[i];
    coefficient += sqrtf(requiredShipEquipageByCategory[i] * vector[i]);
  }
  return coefficient / sumWeights;
}

// FUNCTION: IMPERIALISM 0x005383f0
float TNavyMission::ComputeMissionOrderMatchScoreWithScaledCandidateNavyOrder(
    TShip* candidateOrder) {
  float vector[4] = {
      g_Recompute_Nation_Order_LookupTable_0065A9E8, g_Recompute_Nation_Order_LookupTable_0065A9E8,
      g_Recompute_Nation_Order_LookupTable_0065A9E8, g_Recompute_Nation_Order_LookupTable_0065A9E8};
  for (TMapOrderChildLinkNode* node = orderList; node != nullptr; node = node->next) {
    TShip* ship = node->payload;
    TZone* targetZone = GetActiveTargetZoneByState28();
    short distanceIndex = 0;
    if (targetZone != nullptr) {
      distanceIndex = ship->GetTurnDistanceTo(GetActiveTargetZoneByState28());
    }
    if (distanceIndex > 5) {
      distanceIndex = 5;
    }
    float scale = g_MissionOrderDistanceDecayWeightTable[distanceIndex] *
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

  TZone* targetZone = GetActiveTargetZoneByState28();
  short distanceIndex = 0;
  if (targetZone != nullptr) {
    distanceIndex = candidateOrder->GetTurnDistanceTo(GetActiveTargetZoneByState28());
  }
  if (distanceIndex > 5) {
    distanceIndex = 5;
  }
  float scale = g_MissionOrderDistanceDecayWeightTable[distanceIndex] *
                static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065A9E0) *
                static_cast<float>(candidateOrder->strength / candidateOrder->GetMaxStrength());
  vector[0] +=
      static_cast<float>(candidateOrder->ComputeNavyOrderPriorityContributionPercentByCategory(0)) *
      scale;
  vector[1] +=
      static_cast<float>(candidateOrder->ComputeNavyOrderPriorityContributionPercentByCategory(1)) *
      scale;
  vector[2] +=
      static_cast<float>(candidateOrder->ComputeNavyOrderPriorityContributionPercentByCategory(2)) *
      scale;
  vector[3] +=
      static_cast<float>(candidateOrder->ComputeNavyOrderPriorityContributionPercentByCategory(3)) *
      scale;

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
        g_pDiplomacyTurnStateManager->IsNationPairAtWar(static_cast<short>(sourceNation),
                                                        orderNode->nation)) {
      short normalizationBase = orderNode->GetMaxStrength();
      if (normalizationBase != 0) {
        float scale =
            static_cast<float>(orderNode->strength) / static_cast<float>(normalizationBase);
        int category = static_cast<int>(orderNode->strength % normalizationBase);
        int contribution =
            orderNode->ComputeNavyOrderPriorityContributionPercentByCategory(category);
        vector[0] += static_cast<float>(contribution) * scale;
        category = contribution;
        contribution = orderNode->ComputeNavyOrderPriorityContributionPercentByCategory(category);
        vector[1] += static_cast<float>(contribution) * scale;
        category = contribution;
        contribution = orderNode->ComputeNavyOrderPriorityContributionPercentByCategory(category);
        vector[2] += static_cast<float>(contribution) * scale;
        category = contribution;
        contribution = orderNode->ComputeNavyOrderPriorityContributionPercentByCategory(category);
        vector[3] += static_cast<float>(contribution);
      }
    }
  }
  float sum = g_Recompute_Nation_Order_LookupTable_0065A9E8;
  for (int componentIndex = 0; componentIndex < 4; ++componentIndex) {
    sum += vector[componentIndex];
  }
  if (sum == static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065A9F0)) {
    return g_Recompute_Nation_Order_LookupTable_0065A9E8;
  }
  float accum = g_Recompute_Nation_Order_LookupTable_0065A9E8;
  for (int diffIndex = 0; diffIndex < 4; ++diffIndex) {
    float diff = vector[diffIndex] / sum -
                 static_cast<float>(
                     static_cast<short>(g_Populate_Beachhead_Mission_LookupTable[diffIndex])) *
                     static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065A9F8);
    if (diff <= static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065A9F0)) {
      diff = -diff;
    }
    accum += diff;
  }
  return sum * (static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065AA08) -
                accum * static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065AA00));
}

// FUNCTION: IMPERIALISM 0x00538bf0
float TNavyMission::ComputeOrderDistributionSimilarityScoreForExactSourceNation(
    int sourceNation, TZone* nodeContext) {
  float vector[4] = {0.0f, 0.0f, 0.0f, 0.0f};
  for (TShip* orderNode = TShip::GetFirst(); orderNode != 0; orderNode = orderNode->next) {
    if (orderNode->location == nodeContext &&
        static_cast<short>(sourceNation) == orderNode->nation) {
      short normalizationBase = orderNode->GetMaxStrength();
      if (normalizationBase != 0) {
        float scale =
            static_cast<float>(orderNode->strength) / static_cast<float>(normalizationBase);
        int category = static_cast<int>(orderNode->strength % normalizationBase);
        int contribution =
            orderNode->ComputeNavyOrderPriorityContributionPercentByCategory(category);
        vector[0] += static_cast<float>(contribution) * scale;
        category = contribution;
        contribution = orderNode->ComputeNavyOrderPriorityContributionPercentByCategory(category);
        vector[1] += static_cast<float>(contribution) * scale;
        category = contribution;
        contribution = orderNode->ComputeNavyOrderPriorityContributionPercentByCategory(category);
        vector[2] += static_cast<float>(contribution) * scale;
        category = contribution;
        contribution = orderNode->ComputeNavyOrderPriorityContributionPercentByCategory(category);
        vector[3] += static_cast<float>(contribution);
      }
    }
  }
  float sum = g_Recompute_Nation_Order_LookupTable_0065A9E8;
  for (int componentIndex = 0; componentIndex < 4; ++componentIndex) {
    sum += vector[componentIndex];
  }
  if (sum == static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065A9F0)) {
    return g_Recompute_Nation_Order_LookupTable_0065A9E8;
  }
  float accum = g_Recompute_Nation_Order_LookupTable_0065A9E8;
  for (int diffIndex = 0; diffIndex < 4; ++diffIndex) {
    float diff = vector[diffIndex] / sum -
                 static_cast<float>(
                     static_cast<short>(g_Populate_Beachhead_Mission_LookupTable[diffIndex])) *
                     static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065A9F8);
    if (diff <= static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065A9F0)) {
      diff = -diff;
    }
    accum += diff;
  }
  return sum * (static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065AA08) -
                accum * static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065AA00));
}

// Scores the accumulated order distribution against target profile [0..3].
// FUNCTION: IMPERIALISM 0x00538dd0
float TNavyMission::ComputeOrderDistributionSimilarityScoreForZoneWithBaseProfile(
    TZone* nodeContext) {
  float vector[4] = {
      g_Recompute_Nation_Order_LookupTable_0065A9E8, g_Recompute_Nation_Order_LookupTable_0065A9E8,
      g_Recompute_Nation_Order_LookupTable_0065A9E8, g_Recompute_Nation_Order_LookupTable_0065A9E8};
  for (TShip* orderNode = TShip::GetFirst(); orderNode != 0; orderNode = orderNode->next) {
    if (orderNode->location == nodeContext &&
        g_pDiplomacyTurnStateManager->IsNationPairAtWar(nationId, orderNode->nation)) {
      float scale = static_cast<float>(orderNode->strength / orderNode->GetMaxStrength()) *
                    static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065AA08);
      vector[0] +=
          static_cast<float>(orderNode->ComputeNavyOrderPriorityContributionPercentByCategory(0)) *
          scale;
      vector[1] +=
          static_cast<float>(orderNode->ComputeNavyOrderPriorityContributionPercentByCategory(1)) *
          scale;
      vector[2] +=
          static_cast<float>(orderNode->ComputeNavyOrderPriorityContributionPercentByCategory(2)) *
          scale;
      vector[3] +=
          static_cast<float>(orderNode->ComputeNavyOrderPriorityContributionPercentByCategory(3));
    }
  }
  float total = vector[0] + vector[1] + vector[2] + vector[3];
  if (total == static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065A9F0)) {
    return g_Recompute_Nation_Order_LookupTable_0065A9E8;
  }
  float diffSum = g_Recompute_Nation_Order_LookupTable_0065A9E8;
  for (int i = 0; i < 4; ++i) {
    float diff =
        vector[i] / total -
        static_cast<float>(static_cast<short>(g_Populate_Beachhead_Mission_LookupTable[i])) *
            static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065A9F8);
    if (diff <= static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065A9F0)) {
      diff = -diff;
    }
    diffSum += diff;
  }
  return total * (static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065AA08) -
                  diffSum * static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065AA00));
}
// FUNCTION: IMPERIALISM 0x00539a90
float TNavyMission::ComputeOrderDistributionSimilarityScoreForZone(TZone* nodeContext) {
  float vector[4] = {
      g_Recompute_Nation_Order_LookupTable_0065A9E8, g_Recompute_Nation_Order_LookupTable_0065A9E8,
      g_Recompute_Nation_Order_LookupTable_0065A9E8, g_Recompute_Nation_Order_LookupTable_0065A9E8};
  for (TShip* orderNode = TShip::GetFirst(); orderNode != 0; orderNode = orderNode->next) {
    if (orderNode->location == nodeContext &&
        g_pDiplomacyTurnStateManager->IsNationPairAtWar(nationId, orderNode->nation)) {
      float scale = static_cast<float>(orderNode->strength / orderNode->GetMaxStrength()) *
                    static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065AA08);
      vector[0] +=
          static_cast<float>(orderNode->ComputeNavyOrderPriorityContributionPercentByCategory(0)) *
          scale;
      vector[1] +=
          static_cast<float>(orderNode->ComputeNavyOrderPriorityContributionPercentByCategory(1)) *
          scale;
      vector[2] +=
          static_cast<float>(orderNode->ComputeNavyOrderPriorityContributionPercentByCategory(2)) *
          scale;
      vector[3] +=
          static_cast<float>(orderNode->ComputeNavyOrderPriorityContributionPercentByCategory(3));
    }
  }
  float total = vector[0] + vector[1] + vector[2] + vector[3];
  if (total == static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065A9F0)) {
    return g_Recompute_Nation_Order_LookupTable_0065A9E8;
  }
  float diffSum = g_Recompute_Nation_Order_LookupTable_0065A9E8;
  for (int i = 0; i < 4; ++i) {
    float diff =
        vector[i] / total -
        static_cast<float>(static_cast<short>(g_Populate_Beachhead_Mission_LookupTable[4 + i])) *
            static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065A9F8);
    if (diff <= static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065A9F0)) {
      diff = -diff;
    }
    diffSum += diff;
  }
  return total * (static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065AA08) -
                  diffSum * static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065AA00));
}
// FUNCTION: IMPERIALISM 0x0053b350
float TNavyMission::ComputeMissionNavyOrderDistributionScoreForPortOwnerOrAllies(TZone* portZone) {
  float best = g_Recompute_Nation_Order_LookupTable_0065A9E8;
  short ownerNation = portZone->GetPortZoneOwnerNationCodeFromMissionField48();
  if (ownerNation < 7) {
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
    if (total == static_cast<float>(g_Recompute_Nation_Order_LookupTable_0065A9F0)) {
      return g_Recompute_Nation_Order_LookupTable_0065A9E8;
    }
    float diffSum = g_Recompute_Nation_Order_LookupTable_0065A9E8;
    const short* targetWeight = g_NavyOrderDistributionCategoryWeights;
    component = vector;
    while (targetWeight < g_NavyOrderDistributionCategoryWeights + 4) {
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
        g_pDiplomacyTurnStateManager->IsNationPairAtWar(nationId, allyIdx)) {
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
        const short* targetWeight = g_NavyOrderDistributionCategoryWeights;
        component = vector;
        while (targetWeight < g_NavyOrderDistributionCategoryWeights + 4) {
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
