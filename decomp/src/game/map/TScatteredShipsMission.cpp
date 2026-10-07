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

IMPLEMENT_SERIAL(TScatteredShipsMission, TNavyMission, 1)

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
  requiredForces = 0;
  importanceScore = g_fScatteredShipsMissionDefaultScore;
}

// FUNCTION: IMPERIALISM 0x0053bbb0
void TScatteredShipsMission::Reassess() {
  ResetPriority();
  CalculateImportance();
  CalculateNeeds();
}

// FUNCTION: IMPERIALISM 0x0053bbe0
TMission* TScatteredShipsMission::GetReplacement() {
  return this;
}

// FUNCTION: IMPERIALISM 0x0053bc00
void TScatteredShipsMission::ResetPriority() {
  priority = 3;
}

// FUNCTION: IMPERIALISM 0x0053bc20
void TScatteredShipsMission::CalculateImportance() {
  importanceScore = g_fScatteredShipsMissionDefaultScore;
}

// FUNCTION: IMPERIALISM 0x0053bc40
void TScatteredShipsMission::CalculateNeeds() {
  TAutoGreatPower* nation = static_cast<TAutoGreatPower*>(g_apNationStates[nationId]);
  nation->AssertValid();
  float navyPressure = nation->activeMissionPressureAverage;
  float pressureScale = navyPressure + g_MissionPositiveFallback;

  const short* lookupTable = g_Populate_Beachhead_Mission_LookupTable;
  for (int i = 0; i < 4; ++i) {
    requiredShipEquipageByCategory[i] =
        static_cast<float>(static_cast<short>(lookupTable[i])) * pressureScale * 0.01;
  }
}

// FUNCTION: IMPERIALISM 0x0053bcc0
bool TScatteredShipsMission::Matches(eMissionType missionType, int key, TZone* zoneContext) const {
  return missionType == kMissionTypeScatteredShips && zoneContext == NULL && key == -1;
}

// FUNCTION: IMPERIALISM 0x0053bd00
TZone* AdvanceZoneCursorToPrevOrWrapToHead(TZone** cursor) {
  TZone* next = (*cursor)->prev18;
  *cursor = next;
  if (next == NULL) {
    *cursor = g_pMapActionContextListHead;
  }
  return next;
}

// FUNCTION: IMPERIALISM 0x0053bd30
TShip* SelectNearestInactiveShipToZone(TZone** targetZone, TMapOrderChildLinkNode* head) {
  TMapOrderChildLinkNode* best = head;
  while (best != NULL && best->active != 0) {
    best = best->next;
  }
  if (best == NULL) {
    return NULL;
  }

  for (TMapOrderChildLinkNode* candidate = best->next; candidate != NULL;
       candidate = candidate->next) {
    if (candidate->active == 0) {
      TShip* bestShip = best->payload;
      TShip* candidateShip = candidate->payload;
      short bestDistance = bestShip->location->GetDistanceTo(*targetZone);
      short candidateDistance = candidateShip->location->GetDistanceTo(*targetZone);
      if (candidateDistance < bestDistance) {
        best = candidate;
      }
    }
  }

  best->active = 1;
  return best->payload;
}

// FUNCTION: IMPERIALISM 0x0053bdd0
void TScatteredShipsMission::GiveOrders() {
  if (orderList != NULL) {
    orderList->active = 0;
    orderList->next->SetChainActiveFlag(0);
  }

  int stepCount = static_cast<int>(g_pSimMgr->GetEconomicTurn()) % 50;

  TZone* zone = g_pMapActionContextListHead;
  while (zone != NULL) {
    if (!zone->IsPortZone() && zone->IsAdjacentToCountry(nationId)) {
      break;
    }
    zone = zone->prev18;
  }
  if (zone == NULL) {
    return;
  }

  TZone* current = g_pMapActionContextListHead;
  while (stepCount-- != 0) {
    TZone* nextZone = current->prev18;
    current = (nextZone != NULL) ? nextZone : g_pMapActionContextListHead;
  }

  while (true) {
    if (!current->IsPortZone() && current->IsAdjacentToCountry(nationId)) {
      TMapOrderChildLinkNode* best = orderList;
      while (best != NULL && best->active != 0) {
        best = best->next;
      }
      if (best == NULL) {
        return;
      }

      for (TMapOrderChildLinkNode* candidate = best->next; candidate != NULL;
           candidate = candidate->next) {
        if (candidate->active == 0) {
          TZone* candidateZone = candidate->payload->location;
          TZone* bestZone = best->payload->location;
          short candidateDistance = candidateZone->GetDistanceTo(current);
          short bestDistance = bestZone->GetDistanceTo(current);
          if (candidateDistance < bestDistance) {
            best = candidate;
          }
        }
      }

      best->active = 1;
      TShip* target = best->payload;
      if (target == NULL) {
        return;
      }
      if (target->location != current) {
        target->DemandExclusiveTaskForce()->OrderSailTowards(current);
      }
    }

    TZone* nextZone = current->prev18;
    current = (nextZone != NULL) ? nextZone : g_pMapActionContextListHead;
  }
}

// FUNCTION: IMPERIALISM 0x0053bf90
TZone* TScatteredShipsMission::PickAmassingZone() {
  return NULL;
}
