// TScatteredShipsMission implementations.

#include "game/map/TScatteredShipsMission.h"
#include "game/nation/TAutoGreatPower.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/core/TStream.h"
#include "game/navy/TShip.h"
#include "game/navy/TTaskForce.h"
#include "game/map/TZone.h"
#include "game/globals/global_types.h"
#include "game/globals/navy_globals.h"
#include "game/globals/shared_globals.h"
#include "game/navy_order.h"

// The archive extraction operator below is emitted by IMPLEMENT_SERIAL:
//   CArchive& AFXAPI operator>>(CArchive&, TScatteredShipsMission*&)
// SYNTHETIC: IMPERIALISM 0x0053bb60
// operator>>
IMPLEMENT_SERIAL(TScatteredShipsMission, TNavyMission, 1)

// SYNTHETIC: IMPERIALISM 0x0053ba60
// TScatteredShipsMission::CreateObject

// SYNTHETIC: IMPERIALISM 0x0053bb20
// TScatteredShipsMission::GetRuntimeClass
// SYNTHETIC: IMPERIALISM 0x005356a0
// TScatteredShipsMission::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x00535640
bool TScatteredShipsMission::IsHospitalMission() const {
  return true;
}

// FUNCTION: IMPERIALISM 0x00535660
bool TScatteredShipsMission::IsDefensiveSeaZoneMission() const {
  return true;
}

// FUNCTION: IMPERIALISM 0x00535680
bool TScatteredShipsMission::IsANoBrainer() const {
  return true;
}

// FUNCTION: IMPERIALISM 0x005356d0
TScatteredShipsMission::~TScatteredShipsMission() {}

// FUNCTION: IMPERIALISM 0x0053bb90
void TScatteredShipsMission::Initialize() {
  marker11 = 0;
  importanceScore0c = g_fScatteredShipsMissionDefaultScore;
}

// FUNCTION: IMPERIALISM 0x0053bbb0
void TScatteredShipsMission::Reassess() {
  SetStateByte8To2();
  CalculateImportance();
  CalculateNeeds();
}

// FUNCTION: IMPERIALISM 0x0053bbe0
TMission* TScatteredShipsMission::GetReplacementSlot48() {
  return this;
}

// FUNCTION: IMPERIALISM 0x0053bc00
void TScatteredShipsMission::SetStateByte8To2() {
  state08 = 3;
}

// FUNCTION: IMPERIALISM 0x0053bc20
void TScatteredShipsMission::CalculateImportance() {
  importanceScore0c = g_fScatteredShipsMissionDefaultScore;
}

// Spreads the fixed g_Populate_Beachhead_Mission_LookupTable_00697958 percentages across
// requiredShipEquipageByCategory[4], scaled by (1 + this mission's nation's active-mission pressure).
// AssertValid()s the nation first (same CObject virtual slot 0xc dispatch used elsewhere in
// this file family).
// FUNCTION: IMPERIALISM 0x0053bc40
void TScatteredShipsMission::CalculateNeeds() {
  TAutoGreatPower* nation = static_cast<TAutoGreatPower*>(g_apNationStates[nationId04]);
  nation->AssertValid();
  float navyPressure = nation->activeMissionPressureAverageB6c;
  float pressureScale = navyPressure + g_MissionPositiveFallback_0065A9B8;

  const short* lookupTable = g_Populate_Beachhead_Mission_LookupTable_00697958;
  for (int i = 0; i < 4; ++i) {
    requiredShipEquipageByCategory[i] = static_cast<float>(static_cast<short>(lookupTable[i])) *
                                        pressureScale *
                                        g_Recompute_Nation_Order_LookupTable_0065A9F8;
  }
}

// FUNCTION: IMPERIALISM 0x0053bcc0
bool TScatteredShipsMission::Matches(eMissionType missionType, int key, TZone* zoneContext) const {
  return missionType == kMissionTypeScatteredShips && zoneContext == nullptr && key == -1;
}

// Selects the nearest inactive ship-list entry to *targetZone, marks the selected link
// active, and returns its ship. The pointer-to-pointer contract makes each distance probe
// observe the caller's current zone variable.
// FUNCTION: IMPERIALISM 0x0053bd30
TShip* SelectNearestInactiveShipToZone(TZone** targetZone, TMapOrderChildLinkNode* head) {
  TMapOrderChildLinkNode* best = head;
  while (best != nullptr && best->active != 0) {
    best = best->next;
  }
  if (best == nullptr) {
    return nullptr;
  }

  for (TMapOrderChildLinkNode* candidate = best->next; candidate != nullptr;
       candidate = candidate->next) {
    if (candidate->active == 0) {
      TShip* bestShip = static_cast<TShip*>(best->payload);
      TShip* candidateShip = static_cast<TShip*>(candidate->payload);
      short bestDistance =
          bestShip->location->GetCachedMapActionContextDistanceOrRecompute(*targetZone);
      short candidateDistance =
          candidateShip->location->GetCachedMapActionContextDistanceOrRecompute(*targetZone);
      if (candidateDistance < bestDistance) {
        best = candidate;
      }
    }
  }

  best->active = 1;
  return static_cast<TShip*>(best->payload);
}

// Deactivates the whole existing shipList chain, then hunts for a port-zone context
// eligible for this mission's nation (!QueryPortZoneCapability() &&
// HasSecondaryNeighborWithNationTag(nationId04), same eligibility pair the whole
// TControlSeaZoneMission family's CalculateNeeds/GiveActionOrders use elsewhere) -- first to confirm
// at least one exists at all (walking g_pMapActionContextListHead via prev18), then re-walks
// from the head, stepped forward g_pSimMgr->GetEconomicTurn() % 50 times (wrapping to the
// head on a null prev18), as the starting point for an unbounded sweep: for every eligible
// zone visited (wrapping forever via prev18), picks the first still-inactive orderList24
// node, then scans the remaining inactive nodes for the one whose (TZone*) reading of
// TTaskForce::shipOrders is nearest that zone (TZone::GetCachedMapActionContextDistanceOrRecompute),
// marks it active, and -- unless it's already anchored on that same zone -- promotes/queues
// it there. Returns as soon as no inactive node remains (shipList is finite, so the
// sweep is bounded even though the zone ring never explicitly stops).
// FUNCTION: IMPERIALISM 0x0053bdd0
void TScatteredShipsMission::GiveOrders() {
  if (orderList24 != nullptr) {
    orderList24->active = 0;
    orderList24->next->SetChainActiveFlag(0);
  }

  int stepCount = static_cast<int>(g_pSimMgr->GetEconomicTurn()) % 50;

  TZone* zone = g_pMapActionContextListHead;
  while (zone != nullptr) {
    if (!zone->QueryPortZoneCapability() && zone->HasSecondaryNeighborWithNationTag(nationId04)) {
      break;
    }
    zone = zone->prev18;
  }
  if (zone == nullptr) {
    return;
  }

  TZone* current = g_pMapActionContextListHead;
  while (stepCount-- != 0) {
    TZone* nextZone = current->prev18;
    current = (nextZone != nullptr) ? nextZone : g_pMapActionContextListHead;
  }

  while (true) {
    if (!current->QueryPortZoneCapability() &&
        current->HasSecondaryNeighborWithNationTag(nationId04)) {
      TMapOrderChildLinkNode* best = orderList24;
      while (best != nullptr && best->active != 0) {
        best = best->next;
      }
      if (best == nullptr) {
        return;
      }

      for (TMapOrderChildLinkNode* candidate = best->next; candidate != nullptr;
           candidate = candidate->next) {
        if (candidate->active == 0) {
          TZone* candidateZone = static_cast<TShip*>(candidate->payload)->location;
          TZone* bestZone = static_cast<TShip*>(best->payload)->location;
          short candidateDistance =
              candidateZone->GetCachedMapActionContextDistanceOrRecompute(current);
          short bestDistance = bestZone->GetCachedMapActionContextDistanceOrRecompute(current);
          if (candidateDistance < bestDistance) {
            best = candidate;
          }
        }
      }

      best->active = 1;
      TShip* target = static_cast<TShip*>(best->payload);
      if (target == nullptr) {
        return;
      }
      if (target->location != current) {
        target->DemandExclusiveTaskForce()->OrderSailTowards(current);
      }
    }

    TZone* nextZone = current->prev18;
    current = (nextZone != nullptr) ? nextZone : g_pMapActionContextListHead;
  }
}

// FUNCTION: IMPERIALISM 0x0053bf90
TZone* TScatteredShipsMission::RefreshMissionPortZoneContextForNation() {
  return nullptr;
}
