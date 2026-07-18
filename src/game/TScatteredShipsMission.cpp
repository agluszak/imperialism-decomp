// TScatteredShipsMission implementations.

#include "game/TScatteredShipsMission.h"
#include "game/TGreatPower.h"
#include "game/TSimMgr.h"
#include "game/TStream.h"
#include "game/TTaskForce.h"
#include "game/TZone.h"
#include "game/global_data_tables.h"

IMPLEMENT_SERIAL(TScatteredShipsMission, TNavyMission, 1)

// SYNTHETIC: IMPERIALISM 0x0053ba60
// TScatteredShipsMission::CreateObject

// SYNTHETIC: IMPERIALISM 0x0053bb20
// TScatteredShipsMission::GetRuntimeClass
// SYNTHETIC: IMPERIALISM 0x005356a0
// TScatteredShipsMission::`scalar deleting destructor'

TScatteredShipsMission::TScatteredShipsMission() : TNavyMission() {}

TScatteredShipsMission::TScatteredShipsMission(TZone* targetZone) : TNavyMission(targetZone) {}

// FUNCTION: IMPERIALISM 0x00535640
char TScatteredShipsMission::ReturnFalseSlot64() {
  return 1;
}

// FUNCTION: IMPERIALISM 0x00535660
char TScatteredShipsMission::ReturnFalseSlot60() {
  return 1;
}

// FUNCTION: IMPERIALISM 0x00535680
char TScatteredShipsMission::ReturnFalseSlot28() {
  return 1;
}

// FUNCTION: IMPERIALISM 0x0053bb90
void TScatteredShipsMission::Call30() {
  marker11 = 0;
  value0c = *reinterpret_cast<const float*>(0x0065a9c8);
}

// FUNCTION: IMPERIALISM 0x0053bbb0
void TScatteredShipsMission::RefreshSlot40() {
  SetStateByte8To2();
  ResetValue0CToZero();
  NoOpSlot3C();
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
void TScatteredShipsMission::ResetValue0CToZero() {
  value0c = *reinterpret_cast<const float*>(0x0065a9c8);
}

// Spreads the fixed g_Populate_Beachhead_Mission_LookupTable_00697958 percentages across
// resourceWeights2c[4], scaled by (1 + this mission's nation's navy-pressure field at +0xb6c,
// region not otherwise recovered yet). AssertValid()s the nation first (same CObject virtual
// slot 0xc dispatch used elsewhere in this file family).
// FUNCTION: IMPERIALISM 0x0053bc40
void TScatteredShipsMission::NoOpSlot3C() {
  TGreatPower* nation = g_apNationStates[nationId04];
  nation->AssertValid();
  float navyPressure = *reinterpret_cast<float*>(reinterpret_cast<char*>(nation) + 0xb6c);
  float scale = (navyPressure + 1.0f) * 0.01f;

  const unsigned short* lookupTable = g_Populate_Beachhead_Mission_LookupTable_00697958;
  for (int i = 0; i < 4; ++i) {
    resourceWeights2c[i] = static_cast<float>(static_cast<short>(lookupTable[i])) * scale;
  }
}

// FUNCTION: IMPERIALISM 0x0053bcc0
char TScatteredShipsMission::MatchesMissionKeySlot4C(int kind, int key, int mode) {
  (void)key;
  (void)mode;
  return kind == 5;
}

// Deactivates the whole existing childOrderList chain, then hunts for a port-zone context
// eligible for this mission's nation (!QueryPortZoneCapability() &&
// HasSecondaryNeighborWithNationTag(nationId04), same eligibility pair the whole
// TControlSeaZoneMission family's NoOpSlot3C/NoOpSlot9C use elsewhere) -- first to confirm
// at least one exists at all (walking g_pMapActionContextListHead via prev18), then re-walks
// from the head, stepped forward g_pSimMgr->GetTurnTickSlot3C() % 50 times (wrapping to the
// head on a null prev18), as the starting point for an unbounded sweep: for every eligible
// zone visited (wrapping forever via prev18), picks the first still-inactive orderList24
// node, then scans the remaining inactive nodes for the one whose (TZone*) reading of
// TTaskForce::attachment is nearest that zone (TZone::GetCachedMapActionContextDistanceOrRecompute),
// marks it active, and -- unless it's already anchored on that same zone -- promotes/queues
// it there. Returns as soon as no inactive node remains (childOrderList is finite, so the
// sweep is bounded even though the zone ring never explicitly stops).
// FUNCTION: IMPERIALISM 0x0053bdd0
void TScatteredShipsMission::MissionSlot44() {
  if (orderList24 != nullptr) {
    orderList24->active = 0;
    orderList24->next->SetChainActiveFlag(0);
  }

  short stepCount = static_cast<short>(g_pSimMgr->GetTurnTickSlot3C() % 50);

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
  for (; stepCount != 0; --stepCount) {
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
          // Both reads are the same genuine cross-type pun of TTaskForce::attachment (the
          // "order/entry kind tag") as a TZone* -- the same dual-purpose pattern already
          // documented on the adjacent `owner` field (PromoteMapOrderChainAndQueue reads
          // it as TZone* too).
          TZone* candidateZone = reinterpret_cast<TZone*>(static_cast<TTaskForce*>(candidate->payload)->attachment);
          TZone* bestZone = reinterpret_cast<TZone*>(static_cast<TTaskForce*>(best->payload)->attachment);
          short candidateDistance =
              candidateZone->GetCachedMapActionContextDistanceOrRecompute(current);
          short bestDistance = bestZone->GetCachedMapActionContextDistanceOrRecompute(current);
          if (candidateDistance < bestDistance) {
            best = candidate;
          }
        }
      }

      best->active = 1;
      TTaskForce* target = static_cast<TTaskForce*>(best->payload);
      if (target == nullptr) {
        return;
      }
      if (reinterpret_cast<TZone*>(target->attachment) != current) {
        target->GetOrCreateMissionOrderEntryForNode()->PromoteMapOrderChainAndQueue(current);
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
