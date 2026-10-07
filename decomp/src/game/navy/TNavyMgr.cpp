#include "game/navy/TNavyMgr.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_military.h"
#include "game/resource_domain_types.h"

#include <mbstring.h>
#include <stdlib.h>

#include "game/navy/TAdmiral.h"
#include "game/military/TArmyMgr.h"
#include "game/city/TCity.h"
#include "game/city_ui/TCountry.h"
#include "game/nation/TGreatPower.h"
#include "game/map/TMapMgr.h"
#include "game/map/TMapUberPicture.h"
#include "game/ui_core/TViewMgr.h"
#include "game/map/map_overlay_geometry.h"
#include "game/navy/TOcean.h"
#include "game/navy/TShip.h"
#include "game/navy_order.h"
#include "game/core/TStream.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/app/TObject.h"
#include "game/ui_screens/TPortZone.h"
#include "game/net/TMultiplayerMgr.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/navy/TTaskForce.h"
#include "game/map/TZone.h"
#include "game/core/CString.h"
#include "game/globals/global_types.h"
#include "game/globals/navy_globals.h"
#include "game/globals/shared_globals.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/military/mapped_flavor_text.h"
#include "game/map_order_battle_snapshot.h"

namespace {

static inline void CopyCStringIntoFixedBuffer(char* dest, int destSize, const char* src) {
  int i = 0;
  for (; i < destSize; ++i) {
    char c = src[i];
    dest[i] = c;
    if (c == '\0') {
      break;
    }
  }
}

static inline void AppendCStringIntoFixedBuffer(char* dest, int destSize, const char* src) {
  int offset = 0;
  while (offset < destSize && dest[offset] != '\0') {
    ++offset;
  }
  while (offset < destSize) {
    char c = src[0];
    dest[offset] = c;
    if (c == '\0') {
      break;
    }
    ++offset;
    ++src;
  }
}

static inline int CountMapOrderChildren(TMapOrderChildLinkNode* head);
static inline int GetAverageShipWeight(TMapOrderChildLinkNode* head);
static inline int GetForceStrength(TShip* ship);

} // namespace

// FUNCTION: IMPERIALISM 0x0054f110
void BuildMapOrderBattleSideSnapshot(MapOrderBattleSnapshot* snapshot, int side,
                                     TTaskForce* entry) {
  snapshot->nationIds[side] = static_cast<unsigned char>(entry->nation);

  CString terrainLabel;
  g_apTerrainTypeDescriptorTable[entry->nation]->FormatOverlayTerrainLabelText(&terrainLabel);
  CopyCStringIntoFixedBuffer(snapshot->nameBuffer[side].data, 0x20,
                             static_cast<LPCSTR>(terrainLabel));

  CString overlayLabel;
  entry->GetSnooperDescription(&overlayLabel);
  CopyCStringIntoFixedBuffer(snapshot->overlayLabel[side].data, 0xff,
                             static_cast<LPCSTR>(overlayLabel));

  short childCount = entry->CountShips();
  snapshot->childCount[side] = childCount;

  MapOrderBattleSideChildRecord* records = NULL;
  if (childCount > 0) {
    records = new MapOrderBattleSideChildRecord[childCount];
  }
  snapshot->childRecords[side] = records;

  int idx = 0;
  for (TMapOrderChildLinkNode* node = entry->shipList; node != NULL; node = node->next) {
    TShip* child = node->payload;
    MapOrderBattleSideChildRecord& rec = records[idx];
    rec.resourceType = child->type;
    rec.stockOrRequired = child->strength;
    CopyCStringIntoFixedBuffer(rec.nameBuffer, 0x20, static_cast<LPCSTR>(child->name));
    rec.detailIdentity = reinterpret_cast<unsigned int>(child);
    rec.strengthBucket = static_cast<short>(child->experience / 100);
    ++idx;
  }
}

// FUNCTION: IMPERIALISM 0x0054f340
void RefreshMapOrderBattleSideSnapshot(MapOrderBattleSnapshot* snapshot, int side,
                                       TTaskForce* entry) {
  short count = snapshot->childCount[side];
  for (int i = 0; i < count; ++i) {
    MapOrderBattleSideChildRecord& rec = snapshot->childRecords[side][i];
    TShip* child = reinterpret_cast<TShip*>(rec.detailIdentity);
    bool stillPresent = entry != NULL && entry->shipList->FindNodeMatching(child) != NULL;
    if (stillPresent) {
      rec.stockOrRequired = child->strength;
      rec.strengthBucket = static_cast<short>(child->experience / 100);
    } else {
      rec.stockOrRequired = 0;
    }
    rec.detailIdentity = kControlTagNavy; // 'navy'
  }

  if (entry != NULL && entry->shipOrders == 5) {
    int cityIndex = static_cast<Province*>(entry->target)->GetIndex();
    g_pMapContextActionManager->CheckForDrownedUnits(snapshot->nationIds[side], cityIndex,
                                                     snapshot);
  }
}

// FUNCTION: IMPERIALISM 0x00550c20
void FormatCommodityCount(CString* out, short commodityCode, short count) {
  short codeGroup = (count < 2) ? 0x2716 : 0x271a;
  g_pSimMgr->GetString(codeGroup, commodityCode, out);
  if (count >= 0) {
    CString numberText;
    numberText.Format(g_szDecimalFormat, static_cast<int>(count));
    *out = numberText + s_szSpaceSeparator + *out;
  }
}

IMPLEMENT_DYNCREATE(TNavyMgr, TObject)

// FUNCTION: IMPERIALISM 0x00556590
TNavyMgr::TNavyMgr() : orderQueueHead(0), executionPhase(-1), pendingOrderEntry(NULL) {}

// FUNCTION: IMPERIALISM 0x005565f0
TNavyMgr::~TNavyMgr() {}

// FUNCTION: IMPERIALISM 0x00556610
void TNavyMgr::INavyMgr() {
  int i;
  for (i = 0; i < 14; ++i) {
    g_NavyResolveOrderRanking[i] = static_cast<short>(i);
    g_NavyPriorityOrderRanking[i] = static_cast<short>(i);
    g_NavyMissionOrderRanking[i] = static_cast<short>(i);
  }
  for (i = 0; i < 13; ++i) {
    for (int j = i + 1; j < 14; ++j) {
      TNavyOrderResourceDescriptor* pi =
          &g_NavyOrderResourceDescriptorTable[g_NavyPriorityOrderRanking[i]];
      TNavyOrderResourceDescriptor* pj =
          &g_NavyOrderResourceDescriptorTable[g_NavyPriorityOrderRanking[j]];
      if (pj->BattleSpeedDword() > pi->BattleSpeedDword()) {
        short t = g_NavyPriorityOrderRanking[i];
        g_NavyPriorityOrderRanking[i] = g_NavyPriorityOrderRanking[j];
        g_NavyPriorityOrderRanking[j] = t;
      }
      TNavyOrderResourceDescriptor* mi =
          &g_NavyOrderResourceDescriptorTable[g_NavyMissionOrderRanking[i]];
      TNavyOrderResourceDescriptor* mj =
          &g_NavyOrderResourceDescriptorTable[g_NavyMissionOrderRanking[j]];
      if (mj->BattleRangeDword() > mi->BattleRangeDword()) {
        short t = g_NavyMissionOrderRanking[i];
        g_NavyMissionOrderRanking[i] = g_NavyMissionOrderRanking[j];
        g_NavyMissionOrderRanking[j] = t;
      }
      TNavyOrderResourceDescriptor* ri =
          &g_NavyOrderResourceDescriptorTable[g_NavyResolveOrderRanking[i]];
      TNavyOrderResourceDescriptor* rj =
          &g_NavyOrderResourceDescriptorTable[g_NavyResolveOrderRanking[j]];
      if (rj->FirepowerDword() > ri->FirepowerDword()) {
        short t = g_NavyResolveOrderRanking[i];
        g_NavyResolveOrderRanking[i] = g_NavyResolveOrderRanking[j];
        g_NavyResolveOrderRanking[j] = t;
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x005567a0
void TNavyMgr::Free() {
  ClearAllOrders();
  delete this;
}

// FUNCTION: IMPERIALISM 0x005568c0
void TNavyMgr::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
  WriteToFilterously(stream, -1);
}

// FUNCTION: IMPERIALISM 0x005568f0
void TNavyMgr::WriteToFilterously(TStream* stream, short nationFilter) {
  int matchCount = 0;
  TShip* tail = g_pNavyPrimaryOrderListHead;
  if (tail != 0) {
    for (TShip* older = tail->next; older != 0; older = older->next) {
      tail = older;
    }
  }
  for (TShip* node = tail; node != 0; node = node->previous) {
    if (nationFilter == -1 || nationFilter == node->nation) {
      ++matchCount;
    }
  }
  stream->WriteBytes(&matchCount, 2);
  tail = g_pNavyPrimaryOrderListHead;
  if (tail != 0) {
    for (TShip* older2 = tail->next; older2 != 0; older2 = older2->next) {
      tail = older2;
    }
  }
  for (TShip* writeNode = tail; writeNode != 0; writeNode = writeNode->previous) {
    if (nationFilter == -1 || nationFilter == writeNode->nation) {
      writeNode->WriteTo(stream);
    }
  }
  matchCount = 0;
  for (TAdmiral* admiral = g_pNavySecondaryOrderListHead; admiral != 0; admiral = admiral->next) {
    if (nationFilter == -1 || nationFilter == admiral->nationSlot) {
      ++matchCount;
    }
  }
  stream->WriteBytes(&matchCount, 2);
  for (TAdmiral* admiral2 = g_pNavySecondaryOrderListHead; admiral2 != 0;
       admiral2 = admiral2->next) {
    if (nationFilter == -1 || nationFilter == admiral2->nationSlot) {
      admiral2->WriteTo(stream);
    }
  }
  matchCount = 0;
  for (TTaskForce* order = orderQueueHead; order != 0; order = order->nextForce) {
    if (nationFilter == -1 || nationFilter == order->nation) {
      ++matchCount;
    }
  }
  stream->WriteBytes(&matchCount, 2);
  for (TTaskForce* order2 = orderQueueHead; order2 != 0; order2 = order2->nextForce) {
    if (nationFilter == -1 || nationFilter == order2->nation) {
      order2->WriteTo(stream);
    }
  }
}

// FUNCTION: IMPERIALISM 0x00556aa0
void TNavyMgr::ReadFrom(TStream* stream) {
  TObject::ReadFrom(stream);
  ReadFromFilterously(stream, -1);
}

// FUNCTION: IMPERIALISM 0x00556ad0
void TNavyMgr::ReadFromFilterously(TStream* stream, short nationFilter) {
  if (nationFilter == -1) {
    while (g_pNavyPrimaryOrderListHead != 0) {
      g_pNavyPrimaryOrderListHead->Free();
    }
    while (g_pNavySecondaryOrderListHead != 0) {
      g_pNavySecondaryOrderListHead->Free();
    }
    if (orderQueueHead != 0) {
      orderQueueHead->nextForce->FreeAll();
      orderQueueHead->Free();
    }
  } else {
    FreeShipsOfNation(nationFilter);
  }

  int pendingCount;
  stream->ReadBytes(&pendingCount, 2);
  while (static_cast<short>(pendingCount--) != 0) {
    TShip* shipNode = new TShip();
    if (shipNode == 0) {
      FailNilPointerWithAssert(s_SourcePathUNavy, 0xd11);
    }
    shipNode->ReadFrom(stream);
    if (nationFilter != -1 && shipNode->nation != nationFilter) {
      shipNode->Free();
    }
  }

  stream->ReadBytes(&pendingCount, 2);
  while (static_cast<short>(pendingCount--) != 0) {
    TAdmiral* admiralNode = new TAdmiral();
    if (admiralNode == 0) {
      FailNilPointerWithAssert(s_SourcePathUNavy, 0xd24);
    }
    admiralNode->ReadFrom(stream);
    if (nationFilter != -1 && admiralNode->nationSlot != nationFilter) {
      admiralNode->Free();
    }
  }

  // orderQueueHead TTaskForce chain.
  stream->ReadBytes(&pendingCount, 2);
  while (static_cast<short>(pendingCount--) != 0) {
    TTaskForce* orderEntry = new TTaskForce();
    if (orderEntry == 0) {
      FailNilPointerWithAssert(s_SourcePathUNavy, 0xd37);
    }
    orderEntry->ReadFrom(stream);
    if (nationFilter != -1 && orderEntry->nation != nationFilter) {
      orderEntry->Free();
    }
    TTaskForce* queueHead = orderQueueHead;
    TTaskForce* queueCursor = queueHead;
    while (queueCursor != 0) {
      if (queueCursor == orderEntry) {
        break;
      }
      queueCursor = queueCursor->nextForce;
    }
    if (queueCursor == 0) {
      int childLinkCount = 0;
      if (orderEntry != 0) {
        for (TMapOrderChildLinkNode* childCursor = orderEntry->shipList; childCursor != 0;
             childCursor = childCursor->next) {
          ++childLinkCount;
        }
      }
      if (static_cast<short>(childLinkCount) <= 0) {
        orderEntry->Free();
      } else {
        if (orderEntry->previousForce != 0) {
          orderEntry->previousForce->nextForce = orderEntry->nextForce;
        }
        if (orderEntry->nextForce != 0) {
          orderEntry->nextForce->previousForce = orderEntry->previousForce;
        }
        orderEntry->previousForce = 0;
        orderEntry->nextForce = queueHead;
        if (queueHead != 0) {
          queueHead->previousForce = orderEntry;
        }
        orderQueueHead = orderEntry;
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x00556f60
void TNavyMgr::FreeShipsOf(short nation) {
  while (orderQueueHead != 0) {
    TTaskForce* matching = orderQueueHead;
    while (matching != 0 && matching->nation != nation) {
      matching = matching->nextForce;
    }
    if (matching == 0) {
      break;
    }
    matching->CancelOrders(1);
  }

  for (TShip* ship = g_pNavyPrimaryOrderListHead; ship != 0; ship = ship->next) {
    if (ship->nation == nation) {
      ship->selection = 0;
    }
  }
}

// FUNCTION: IMPERIALISM 0x00556fd0
void TNavyMgr::ScuttleEverything() {
  for (TShip* ship = g_pNavyPrimaryOrderListHead; ship != NULL; ship = ship->next) {
    ship->taskForce = 0;
  }
  if (orderQueueHead != NULL) {
    orderQueueHead->nextForce->FreeAll();
    orderQueueHead->Free();
  }
  orderQueueHead = NULL;
  g_pActiveMapOrderContext->AssembleUIForce(NULL);
}

// FUNCTION: IMPERIALISM 0x00557040
void TNavyMgr::ClearAllTransientOrders() {
  orderQueueHead = orderQueueHead->RemoveStragglers();
  for (TShip* ship = g_pNavyPrimaryOrderListHead; ship != 0; ship = ship->next) {
    if (ship->selection == 1) {
      ship->selection = 0;
    }
  }
}

// FUNCTION: IMPERIALISM 0x00557080
bool TNavyMgr::CommitForce(TTaskForce* entry) {
  for (TTaskForce* node = orderQueueHead; node != NULL; node = node->nextForce) {
    if (node == entry) {
      return true;
    }
  }

  int childCount = 0;
  if (entry != NULL) {
    for (TMapOrderChildLinkNode* node = entry->shipList; node != NULL; node = node->next) {
      ++childCount;
    }
  }

  if (childCount <= 0) {
    entry->Free();
    return false;
  }

  if (entry->previousForce != NULL) {
    entry->previousForce->nextForce = entry->nextForce;
  }
  if (entry->nextForce != NULL) {
    entry->nextForce->previousForce = entry->previousForce;
  }
  entry->previousForce = NULL;
  entry->nextForce = orderQueueHead;
  if (orderQueueHead != NULL) {
    orderQueueHead->previousForce = entry;
  }
  orderQueueHead = entry;
  return true;
}

// FUNCTION: IMPERIALISM 0x00557120
void TNavyMgr::ForgetForce(TTaskForce* entry) {
  if (this != NULL && orderQueueHead == entry) {
    orderQueueHead = entry->nextForce;
  }
  if (entry->previousForce != NULL) {
    entry->previousForce->nextForce = entry->nextForce;
  }
  if (entry->nextForce != NULL) {
    entry->nextForce->previousForce = entry->previousForce;
  }
  entry->previousForce = NULL;
  entry->nextForce = NULL;
}

// FUNCTION: IMPERIALISM 0x00557170
short TNavyMgr::GetInvasionCapacity(short nationSlot, Province* provinceTarget,
                                    TZone* contextFilter) {
  int total = 0;
  for (TTaskForce* order = orderQueueHead; order != NULL; order = order->nextForce) {
    if (order->nation == nationSlot && order->shipOrders == 5 && order->target == provinceTarget &&
        (contextFilter == NULL || order->location == contextFilter)) {
      int sum = 0;
      for (TMapOrderChildLinkNode* item = order->shipList; item != NULL; item = item->next) {
        TShip* ship = item->payload;
        short contribution = 0;
        if (ship->strength > 0) {
          contribution = g_industryActionCostWeightResCode10[ship->type];
        }
        sum += contribution;
      }
      total += sum;
    }
  }
  return total;
}

// FUNCTION: IMPERIALISM 0x00557210
void TNavyMgr::FreeShipsOfNation(short nationSlot) {
  if (g_pNavyPrimaryOrderListHead != 0) {
    TShip* node = g_pNavyPrimaryOrderListHead;
    for (;;) {
      TShip* cursor = node;
      if (node->nation == nationSlot) {
        cursor = node->next;
        node->Free();
        node = cursor;
        if (node != 0) {
          continue;
        }
      }
      if (cursor == 0 || (node = cursor->next) == 0) {
        break;
      }
    }
  }

  TAdmiral* secondaryOrder = g_pNavySecondaryOrderListHead;
  while (secondaryOrder != 0) {
    TAdmiral* nextSecondaryOrder = secondaryOrder->next;
    if (secondaryOrder->nationSlot == nationSlot) {
      secondaryOrder->Free();
    }
    secondaryOrder = nextSecondaryOrder;
  }

  TTaskForce* taskForceOrder = orderQueueHead;
  while (taskForceOrder != 0) {
    TTaskForce* nextTaskForceOrder = taskForceOrder->nextForce;
    if (taskForceOrder->nation == nationSlot) {
      taskForceOrder->Free();
    }
    taskForceOrder = nextTaskForceOrder;
  }
}

// FUNCTION: IMPERIALISM 0x00557560
void TNavyMgr::MakeSureAllShipsHaveOrders() {
  g_pActiveMapOrderContext->AssembleUIForce(0);
  TZone* zone = g_pMapActionContextListHead;
  if (zone == 0) {
    return;
  }
  do {
    for (short nation = 0; nation < kMajorNationCount; ++nation) {
      if (g_apTerrainTypeDescriptorTable[nation] == 0) {
        continue;
      }
      TTaskForce* entry = zone->AssembleTaskForce(nation);
      if (entry == 0) {
        continue;
      }
      if (zone->IsPortZone()) {
        TMapOrderChildLinkNode* node = entry->shipList;
        if (node != 0) {
          do {
            node->active = node->payload->strength <
                           g_NavyOrderResourceDescriptorTable[node->payload->type].HullPoints();
            node = node->next;
          } while (node != 0);
        }
        entry->shipOrders = 8;
        entry->CommitToOrders();
        entry = zone->AssembleTaskForce(nation);
      }
      if (entry == 0) {
        continue;
      }
      TMapOrderChildLinkNode* node = entry->shipList;
      if (node != 0) {
        do {
          node->active = 1;
          node = node->next;
        } while (node != 0);
      }
      if (entry->location->IsPortZone()) {
        entry->shipOrders = 7;
        entry->FreeAvailables();
        entry->AssertValid();
        if (g_pNavyOrderManager->CommitForce(entry)) {
          g_pActiveMapOrderContext->CommitForce(entry);
        }
      } else {
        node = entry->shipList;
        entry->shipOrders = 4;
        entry->flagship = 0;
        while (node != 0) {
          if (node->active != 0) {
            node = node->next;
          } else {
            node->payload->SetTaskForce(0);
            short bucketIndex =
                g_NavyOrderResourceDescriptorTable[node->payload->type].ToolbarSlot();
            short* bucketCounter = &entry->shipCountsByToolbarSlot[bucketIndex];
            --*bucketCounter;
            if (node == entry->shipList) {
              entry->shipList = node->next;
            }
            node = node->DeleteMapOrderChildLinkAndReturnNext();
          }
        }
        entry->flagship = 0;
        for (node = entry->shipList; node != 0; node = node->next) {
          entry->flagship = node->payload->Finest(entry->flagship, false);
        }
        entry->AssertValid();
        if (g_pNavyOrderManager->CommitForce(entry)) {
          g_pActiveMapOrderContext->CommitForce(entry);
        }
      }
    }
    zone = zone->prev18;
  } while (zone != 0);
}

// FUNCTION: IMPERIALISM 0x005577b0
void TNavyMgr::PrepareToCarryOutAllOrders(short phaseId) {
  for (int provinceIndex = 0; provinceIndex < kProvinceCount; ++provinceIndex) {
    Province* record = &g_pGlobalMapState->cityScoreTable[provinceIndex];
    if (record->exploredByNationMask != 0) {
      record->exploredByNationMask = 0;
      bool shouldInvalidateCity = g_pSimMgr->multiplayerSessionRole == kSessionRoleHost;
      if (shouldInvalidateCity) {
        g_pGameFlowState->DispatchCityRedrawInvalidateEvent(static_cast<short>(provinceIndex));
      }
    }
  }

  executionPhase = phaseId;

  MakeSureAllShipsHaveOrders();

  TTaskForce* head = orderQueueHead;
  if (head != NULL) {
    TTaskForce* following = head->nextForce;
    head->defeated = 0;
    following->RechargeAll();
  }
}

// FUNCTION: IMPERIALISM 0x005578a0
void TNavyMgr::CarryOutOrders() {
  if (pendingOrderEntry != NULL) {
    pendingOrderEntry->Free();
    pendingOrderEntry = NULL;
  }

  // Pass A: 3/4-kind entries vs a matching-context 6-kind entry.
  {
    for (TTaskForce* entry = orderQueueHead; entry != NULL; entry = entry->nextForce) {
      if (entry->shipOrders != 3 && entry->shipOrders != 4)
        continue;
      if (entry->defeated != 0)
        continue;
      for (TTaskForce* other = orderQueueHead; other != NULL; other = other->nextForce) {
        if (other->location != entry->location)
          continue;
        if (!g_pDiplomacyTurnStateManager->AreInEstablishedWar(other->nation, entry->nation)) {
          continue;
        }
        if (other->shipOrders != 6)
          continue;
        bool result = false;
        if (entry->TryToSpot(other) && entry->ResolveEncounterWith(other)) {
          TTaskForce* unresolvedForce;
          result = entry->BattleWith(other, unresolvedForce);
        }
        if (result)
          return;
        if (entry->defeated != 0)
          break;
      }
    }
  }

  // Pass B: 6-kind entries vs a 1-kind entry sharing a location or target zone.
  {
    for (TTaskForce* entry = orderQueueHead; entry != NULL; entry = entry->nextForce) {
      if (entry->shipOrders != 6)
        continue;
      if (entry->defeated != 0)
        continue;
      for (TTaskForce* other = orderQueueHead; other != NULL; other = other->nextForce) {
        if (!g_pDiplomacyTurnStateManager->AreInEstablishedWar(other->nation, entry->nation)) {
          continue;
        }
        bool ownerMatch =
            (other->shipOrders == 1) && (other->location == static_cast<TZone*>(entry->target) ||
                                         other->target == entry->target);
        if (!ownerMatch)
          continue;
        bool result = false;
        if (entry->TryToSpot(other) && entry->ResolveEncounterWith(other)) {
          TTaskForce* unresolvedForce;
          result = entry->BattleWith(other, unresolvedForce);
        }
        if (result)
          return;
        if (entry->defeated != 0)
          break;
      }
    }
  }

  // Pass C: apply type-1 execution effects directly.
  {
    for (TTaskForce* entry = orderQueueHead; entry != NULL; entry = entry->nextForce) {
      if (entry->shipOrders == 1 && entry->defeated == 0) {
        entry->CarryOutOrders();
      }
    }
  }

  {
    for (TTaskForce* entry = orderQueueHead; entry != NULL; entry = entry->nextForce) {
      if (entry->shipOrders != 3 && entry->shipOrders != 4)
        continue;
      if (entry->defeated != 0)
        continue;
      for (TTaskForce* other = orderQueueHead; other != NULL; other = other->nextForce) {
        if (!g_pDiplomacyTurnStateManager->AreInEstablishedWar(other->nation, entry->nation)) {
          continue;
        }
        if (other->location != entry->location)
          continue;
        if (other->shipOrders == 6)
          continue;
        bool result = false;
        if (entry->TryToSpot(other) && entry->ResolveEncounterWith(other)) {
          TTaskForce* unresolvedForce;
          result = entry->BattleWith(other, unresolvedForce);
        }
        if (result)
          return;
        if (entry->defeated != 0)
          break;
      }
    }
  }

  {
    for (TTaskForce* entry = orderQueueHead; entry != NULL; entry = entry->nextForce) {
      if (entry->shipOrders != 1)
        continue;
      if (entry->defeated != 0)
        continue;
      for (TTaskForce* other = orderQueueHead; other != NULL; other = other->nextForce) {
        if (!g_pDiplomacyTurnStateManager->AreInEstablishedWar(other->nation, entry->nation)) {
          continue;
        }
        if (other->location != entry->location)
          continue;
        if (other->shipOrders != 5)
          continue;

        bool proceed;
        if (entry->CountShips() == 0) {
          proceed = false;
        } else if (other->CountShips() == 0) {
          proceed = false;
        } else if (entry->shipOrders == 6 || other->shipOrders == 6 || other->shipOrders == 5) {
          proceed = true;
        } else {
          short threshold =
              static_cast<short>(entry->GetDeciSpeed() + 0x32 - other->GetDeciSpeed());
          int totalChildren = other->CountShips() + entry->CountShips();
          if (totalChildren > 10)
            threshold += (totalChildren - 10);
          proceed = (rand() % 100) < threshold;
        }

        bool result = false;
        if (proceed && entry->ResolveEncounterWith(other)) {
          TTaskForce* unresolvedForce;
          result = entry->BattleWith(other, unresolvedForce);
        }
        if (result)
          return;
        if (entry->defeated != 0)
          break;
      }
    }
  }

  // Pass F: apply type-5/8 execution effects directly.
  {
    for (TTaskForce* entry = orderQueueHead; entry != NULL; entry = entry->nextForce) {
      if ((entry->shipOrders == 5 || entry->shipOrders == 8) && entry->defeated == 0) {
        entry->CarryOutOrders();
      }
    }
  }

  ResolveNavalInteractions(1);
  ResolveNavalInteractions(2);
  orderQueueHead = orderQueueHead->RemoveStragglers();

  for (TShip* ship = g_pNavyPrimaryOrderListHead; ship != NULL; ship = ship->next) {
    if (ship->selection == 1) {
      ship->selection = 0;
    }
  }

  g_pActiveMapOrderContext->UpdateOccupants();
}

// FUNCTION: IMPERIALISM 0x00557e10
TTaskForce* TNavyMgr::AssignEscorts(short requiredCount, short chancePercent) {
  TTaskForce* entry = orderQueueHead;
  while (entry != NULL) {
    if (entry->nation == requiredCount) {
      bool isEscortOrder = entry->shipOrders == 7;
      if (isEscortOrder) {
        break;
      }
    }
    entry = entry->nextForce;
  }

  if (entry != NULL) {
    for (TMapOrderChildLinkNode* node = entry->shipList; node != NULL; node = node->next) {
      TShip* child = node->payload;
      bool active;
      bool isUnderStrength =
          child->strength < g_NavyOrderResourceDescriptorTable[child->type].HullPoints();
      active = !(isUnderStrength || chancePercent <= rand() % 100);
      node->active = active;
    }
  }

  return entry;
}

IMPERIALISM_BEGIN_RETAIL_UNINITIALIZED_READ

// FUNCTION: IMPERIALISM 0x00557f10
bool TNavyMgr::TryMerchantInterception(TMapOrderInteractionSelection* outResult,
                                       TZone* portZoneContext, short nation, short offerAmount) {
  short portOwnerNation = portZoneContext->GetPortOwnerNation();
  TGreatPower* nationState = g_apNationStates[nation];
  short remainingTradeCapacity =
      static_cast<short>(nationState->merchantCapacity - nationState->availableMerchantCapacity);
  short selectionChance = remainingTradeCapacity == 0
                              ? 0
                              : static_cast<short>((offerAmount * 100) / remainingTradeCapacity);

  TTaskForce* nationEntry = orderQueueHead;
  while (nationEntry != NULL) {
    if (nationEntry->nation == nation) {
      bool isEscortOrder = nationEntry->shipOrders == 7;
      if (isEscortOrder) {
        break;
      }
    }
    nationEntry = nationEntry->nextForce;
  }
  if (nationEntry != NULL) {
    for (TMapOrderChildLinkNode* node = nationEntry->shipList; node != NULL; node = node->next) {
      TShip* child = node->payload;
      bool active;
      active = !(child->strength < g_NavyOrderResourceDescriptorTable[child->type].HullPoints() ||
                 selectionChance <= rand() % 100);
      node->active = active;
    }
  }

  for (TTaskForce* entry = orderQueueHead; entry != NULL; entry = entry->nextForce) {
    if (entry->defeated != 0) {
      continue;
    }
    if (CountMapOrderChildren(entry->shipList) <= 0) {
      continue;
    }

    short shipOrders = entry->shipOrders;
    bool contextMatch = shipOrders == 6 && entry->target == portZoneContext;
    bool activeContextMatch = false;
    if (shipOrders == 3) {
      TZone** slot = &portZoneContext->primaryNeighbors[0];
      activeContextMatch = (entry->location == *slot);
    }

    bool relatedToNation = entry->nation != nation &&
                           g_pDiplomacyTurnStateManager->AreInEstablishedWar(entry->nation, nation);
    bool relatedToPortOwner =
        portOwnerNation >= 7 && entry->shipOrders == 6 &&
        g_pDiplomacyTurnStateManager->AreInEstablishedWar(entry->nation, portOwnerNation);

    if (!(contextMatch || activeContextMatch) || !(relatedToNation || relatedToPortOwner)) {
      continue;
    }

    int thresholdBase = shipOrders == 6 ? 0x32 : 0x14;
    short activeChildRating = static_cast<short>(GetAverageShipWeight(entry->shipList));
    TCity* nationCity = nationState != NULL ? nationState->city : NULL;
    short cityWeight1 = nationCity->GetMerchantMarineDeciSpeed();
    short cityWeight0 = nationCity->GetMerchantMarineAverageCargoHold();
    short offerPerCityWeight = cityWeight0;
    if (offerPerCityWeight > 0) {
      offerPerCityWeight = static_cast<short>(offerAmount / offerPerCityWeight);
    }

    int activeNationChildren = 0;
    if (nationEntry != NULL) {
      for (TMapOrderChildLinkNode* node = nationEntry->shipList; node != NULL; node = node->next) {
        if (node->active != 0) {
          ++activeNationChildren;
        }
      }
    }
    int entryChildren = CountMapOrderChildren(entry->shipList);
    short threshold = entryChildren + activeNationChildren + thresholdBase +
                      (activeChildRating - cityWeight1) + offerPerCityWeight - 10;
    if (rand() % 100 >= threshold) {
      continue;
    }

    bool eligible;
    bool nationEntryUnavailable = nationEntry == NULL;
    if (!nationEntryUnavailable) {
      int queuedShipCount =
          nationEntry->shipCountsByToolbarSlot[0] + nationEntry->shipCountsByToolbarSlot[1] +
          nationEntry->shipCountsByToolbarSlot[2] + nationEntry->shipCountsByToolbarSlot[3];
      nationEntryUnavailable = queuedShipCount == 0;
    }
    if (!nationEntryUnavailable) {
      TMapOrderChildLinkNode* activeNode = nationEntry->shipList;
      while (activeNode != NULL && activeNode->active == 0) {
        activeNode = activeNode->next;
      }
      nationEntryUnavailable = activeNode == NULL;
    }

    if (nationEntryUnavailable) {
      eligible = true;
    } else if (g_pDiplomacyTurnStateManager->AreInEstablishedWar(nation, entry->nation)) {
      int candidateStrength = 0;
      for (TMapOrderChildLinkNode* candidateNode = entry->shipList; candidateNode != NULL;
           candidateNode = candidateNode->next) {
        candidateStrength += candidateNode->payload->GetBattleStrengthRating();
      }
      int orderTypePriority[3] = {200, 100, 50};
      short nationStrength = nationEntry->GetBattleStrengthRating();
      if (static_cast<short>(candidateStrength) * 100 <
          orderTypePriority[entry->aggression] * nationStrength) {
        eligible = false;
        MapOrderBattleSnapshot snapshot;
        snapshot.childCount[0] = 0;
        snapshot.childCount[1] = 0;
        snapshot.childRecords[0] = NULL;
        snapshot.childRecords[1] = NULL;
        snapshot.reportKind = kMapContextReportSeaBattle;
        snapshot.targetObject = entry->location;
        snapshot.displayedParticipantIndex = 0;
        snapshot.reportParticipantIndex = 1;
        BuildMapOrderBattleSideSnapshot(&snapshot, 0, entry);
        BuildMapOrderBattleSideSnapshot(&snapshot, 1, nationEntry);
        RefreshMapOrderBattleSideSnapshot(&snapshot, 0, entry);
        RefreshMapOrderBattleSideSnapshot(&snapshot, 1, nationEntry);
        g_pMapContextActionManager->AddBattleRecord(&snapshot, 0);
      } else {
        TTaskForce* survivingEntry;
        if (CountMapOrderChildren(entry->shipList) != 0 && nationEntry->CountShips() != 0 &&
            (g_pSimMgr->preferenceValues[1] == 0 ||
             (g_pSimMgr->GetPlayerCountry() != entry->nation &&
              g_pSimMgr->GetPlayerCountry() != nationEntry->nation))) {
          g_pNavyOrderManager->ResolveStrategicBattle(entry, nationEntry);
          survivingEntry = NULL;
        }
        eligible = survivingEntry == entry;
      }
    } else {
      int nationStrength = 0;
      for (TMapOrderChildLinkNode* nationStrengthNode = nationEntry->shipList;
           nationStrengthNode != NULL; nationStrengthNode = nationStrengthNode->next) {
        nationStrength += GetForceStrength(nationStrengthNode->payload);
      }
      int candidateStrength = 0;
      for (TMapOrderChildLinkNode* candidateStrengthNode = entry->shipList;
           candidateStrengthNode != NULL; candidateStrengthNode = candidateStrengthNode->next) {
        candidateStrength += GetForceStrength(candidateStrengthNode->payload);
      }
      eligible = nationStrength * 3 < candidateStrength;
    }

    if (!eligible) {
      continue;
    }

    unsigned int flags = outResult->directionFlags & 0xfffffffc;
    outResult->offerNationCode = entry->nation;
    outResult->selectedEntry = entry;
    outResult->directionFlags = flags;
    if (!g_pDiplomacyTurnStateManager->AreInEstablishedWar(nation, entry->nation)) {
      return true;
    }
    short roll = rand() % 100;
    short bias = entryChildren + 10;
    if (roll >= bias) {
      if (roll < bias * 2) {
        outResult->directionFlags |= 1;
      }
    } else {
      outResult->directionFlags |= 2;
    }
    return true;
  }
  return false;
}
IMPERIALISM_END_RETAIL_UNINITIALIZED_READ

// FUNCTION: IMPERIALISM 0x00558960
void TNavyMgr::ResolveNavalInteractions(short mode) {
  for (short nation = 0; nation <= 6; ++nation) {
    if (g_apTerrainTypeDescriptorTable[nation] == NULL) {
      continue;
    }
    TGreatPower* state = g_apNationStates[nation];
    TCity* city = (state != NULL) ? state->city : NULL;
    if (city == NULL) {
      continue;
    }
    for (short slot = 0; slot < 17; ++slot) {
      short entryCount = state->GetNumDealsIn(slot);
      for (short ordinal = 1; ordinal <= entryCount; ++ordinal) {
        short entryKind = 0;
        short entryValue = 0;
        short entryTargetNation = 0;
        int entryPayload = 0;
        state->GetDealInfo(slot, ordinal, &entryKind, &entryValue, &entryTargetNation,
                           &entryPayload);
        if (entryValue == 0) {
          continue;
        }

        short offerNation = (entryKind == kTrackedSlotOfferEntry) ? nation : entryTargetNation;
        short acceptNation = (entryKind == kTrackedSlotOfferEntry) ? entryTargetNation : nation;

        short contextNation = (mode == 1) ? nation : entryTargetNation;
        TZone* portZoneContext = g_pActiveMapOrderContext->GetPortZone(contextNation);
        TMapOrderInteractionSelection selection;
        bool eligible = TryMerchantInterception(&selection, portZoneContext, nation, entryValue);
        if (eligible == 0) {
          continue;
        }

        MapOrderBattleSnapshot snapshot;
        snapshot.childCount[0] = 0;
        snapshot.childCount[1] = 0;
        snapshot.childRecords[0] = NULL;
        snapshot.childRecords[1] = NULL;
        snapshot.nationIds[0] = static_cast<unsigned char>(selection.offerNationCode);
        snapshot.nationIds[1] = static_cast<unsigned char>(nation);
        snapshot.reportParticipantIndex = 0;
        snapshot.displayedParticipantIndex = 0;
        snapshot.reportKind = kMapContextReportMerchantInterception;
        snapshot.targetObject = selection.selectedEntry->location;

        CString labelScratch;
        g_apTerrainTypeDescriptorTable[selection.offerNationCode]->FormatOverlayTerrainLabelText(
            &labelScratch);
        CopyCStringIntoFixedBuffer(snapshot.nameBuffer[0].data, 0x20,
                                   static_cast<LPCSTR>(labelScratch));

        g_apTerrainTypeDescriptorTable[nation]->FormatOverlayTerrainLabelText(&labelScratch);
        CopyCStringIntoFixedBuffer(snapshot.nameBuffer[1].data, 0x20,
                                   static_cast<LPCSTR>(labelScratch));

        selection.selectedEntry->GetSnooperDescription(&labelScratch);
        CopyCStringIntoFixedBuffer(snapshot.overlayLabel[0].data, 0xff,
                                   static_cast<LPCSTR>(labelScratch));

        g_apTerrainTypeDescriptorTable[entryTargetNation]->FormatOverlayTerrainLabelText(
            &labelScratch);
        CString entryValueText;
        entryValueText.Format(g_szDecimalFormat, static_cast<int>(entryValue));
        CString commodityName;
        g_pSimMgr->GetCommodityName(slot, &commodityName);
        CString interactionTemplate;
        g_pSimMgr->GetString(0x273c, 0, &interactionTemplate);
        CString interactionText;
        scanBracketExpressions(
            g_pSimMgr, &interactionText, static_cast<LPCSTR>(interactionTemplate),
            static_cast<LPCSTR>(entryValueText), static_cast<LPCSTR>(commodityName),
            static_cast<LPCSTR>(labelScratch));
        CopyCStringIntoFixedBuffer(snapshot.overlayLabel[1].data, 0xff,
                                   static_cast<LPCSTR>(interactionText));

        bool modeIsOffer = (mode == 1);
        bool matchesOfferPass = modeIsOffer && entryKind == kTrackedSlotOfferEntry;
        bool matchesAcceptPass = mode == 2 && entryKind == kTrackedSlotAcceptEntry;
        bool passMismatch = !matchesOfferPass && !matchesAcceptPass;
        bool movedTrackedCounter = false;

        unsigned int directionFlags = selection.directionFlags;
        if ((directionFlags & 3) == 0 && matchesAcceptPass) {
          continue;
        }

        short transferredWeight = 0;
        int strengthDelta = entryValue;
        if ((directionFlags & 3) != 0) {
          short drawnCounts[14] = {0};
          transferredWeight =
              static_cast<short>(city->PickRandomMerchantVictims(entryValue, drawnCounts));
          if (transferredWeight != 0) {
            strengthDelta = static_cast<int>(transferredWeight) * 3 + entryValue;

            if (passMismatch) {
              if (offerNation < kMajorNationCount) {
                g_apNationStates[offerNation]->AddPurchasedItemAmount(
                    slot, static_cast<short>(-transferredWeight));
              }
              movedTrackedCounter = true;
            }

            short detailCount = transferredWeight + 1;
            if (passMismatch && (directionFlags & 2) != 0) {
              ++detailCount;
            }
            snapshot.childCount[1] = detailCount;
            snapshot.childRecords[1] = new MapOrderBattleSideChildRecord[detailCount];

            CString resourceList;
            int reportIndex = 1;
            for (int resourceType = 0; resourceType < kIndustryActionSlotCount; ++resourceType) {
              short resourceCount = drawnCounts[resourceType];
              if (resourceCount == 0) {
                continue;
              }
              if (resourceList.Compare(g_szEmptyString) != 0) {
                resourceList += g_szListSeparator;
              }
              CString resourceLabel;
              FormatCommodityCount(&resourceLabel, static_cast<unsigned int>(resourceType),
                                   resourceCount);
              resourceList += resourceLabel;

              for (int unit = 0; unit < resourceCount; ++unit) {
                MapOrderBattleSideChildRecord& detail = snapshot.childRecords[1][reportIndex];
                detail.resourceType = static_cast<short>(resourceType);
                detail.stockOrRequired = static_cast<short>((directionFlags >> 1) & 1);
                detail.detailIdentity = kControlTagMerc; // 'merc'
                ++reportIndex;
              }
            }

            CString resourceActionText;
            g_pSimMgr->GetString(0x273c, static_cast<short>(2 - ((directionFlags >> 1) & 1)),
                                 &resourceActionText);
            CString resourceSummary =
                s_szLineBreak + resourceActionText + s_szSpaceSeparator + resourceList;
            AppendCStringIntoFixedBuffer(snapshot.overlayLabel[1].data, 0xff,
                                         static_cast<LPCSTR>(resourceSummary));

            if ((directionFlags & 2) != 0) {
              if (passMismatch) {
                CString transferredText;
                transferredText.Format(g_szDecimalFormat, static_cast<int>(transferredWeight));
                CString transferredCommodityName;
                g_pSimMgr->GetCommodityName(slot, &transferredCommodityName);
                CString transferredActionText;
                g_pSimMgr->GetString(0x273c, 3, &transferredActionText);
                CString transferredSummary = s_szLineBreak + transferredActionText +
                                             s_szSpaceSeparator + transferredText +
                                             s_szSpaceSeparator + transferredCommodityName;
                AppendCStringIntoFixedBuffer(snapshot.overlayLabel[1].data, 0xff,
                                             static_cast<LPCSTR>(transferredSummary));

                MapOrderBattleSideChildRecord& item = snapshot.childRecords[1][reportIndex];
                item.resourceType = slot;
                item.stockOrRequired = transferredWeight;
                item.detailIdentity = kControlTagItem; // 'item'
              }

              for (int resourceType2 = 0; resourceType2 < kIndustryActionSlotCount;
                   ++resourceType2) {
                if (drawnCounts[resourceType2] != 0) {
                  g_apNationStates[selection.offerNationCode]
                      ->city->orderCountByType[resourceType2] =
                      static_cast<short>(g_apNationStates[selection.offerNationCode]
                                             ->city->orderCountByType[resourceType2] +
                                         drawnCounts[resourceType2]);
                }
              }
              if (passMismatch) {
                g_apNationStates[selection.offerNationCode]->AddPurchasedItemAmount(
                    slot, transferredWeight);
              }
            }
          }
        }

        if (snapshot.childCount[1] < 1) {
          snapshot.childCount[1] = 1;
          snapshot.childRecords[1] = new MapOrderBattleSideChildRecord[1];
        }

        MapOrderBattleSideChildRecord& interaction = snapshot.childRecords[1][0];
        interaction.resourceType = slot;
        interaction.stockOrRequired = entryValue;
        interaction.strengthBucket = entryTargetNation;
        interaction.detailIdentity = kControlTagRupt; // 'rupt'

        int selectedChildCount = CountMapOrderChildren(selection.selectedEntry->shipList);
        if (selection.selectedEntry->flagship != NULL &&
            selection.selectedEntry->flagship->admiral != NULL) {
          TAdmiral* admiral = selection.selectedEntry->flagship->admiral;
          admiral->experiencePoints = static_cast<short>(admiral->experiencePoints + strengthDelta);
          if (admiral->experiencePoints >= 500) {
            admiral->experiencePoints = 499;
          }
        }
        if (selectedChildCount > 0) {
          short childStrengthDelta = (strengthDelta * 3) / selectedChildCount;
          for (TMapOrderChildLinkNode* childNode = selection.selectedEntry->shipList;
               childNode != NULL; childNode = childNode->next) {
            TShip* ship = childNode->payload;
            ship->experience = static_cast<short>(ship->experience + childStrengthDelta);
            if (ship->experience >= 500) {
              ship->experience = 499;
            }
          }
        }

        if (passMismatch && !movedTrackedCounter) {
          modeIsOffer = true;
          matchesOfferPass = true;
        }

        snapshot.childCount[0] =
            static_cast<short>(CountMapOrderChildren(selection.selectedEntry->shipList));
        if (snapshot.childCount[0] > 0) {
          snapshot.childRecords[0] = new MapOrderBattleSideChildRecord[snapshot.childCount[0]];
        }
        int selectedChildIndex = 0;
        for (TMapOrderChildLinkNode* selectedNode = selection.selectedEntry->shipList;
             selectedNode != NULL; selectedNode = selectedNode->next) {
          TShip* selectedShip = selectedNode->payload;
          MapOrderBattleSideChildRecord& detail = snapshot.childRecords[0][selectedChildIndex];
          detail.resourceType = selectedShip->type;
          detail.stockOrRequired = selectedShip->strength;
          CopyCStringIntoFixedBuffer(detail.nameBuffer, 0x20,
                                     static_cast<LPCSTR>(selectedShip->name));
          detail.strengthBucket = static_cast<short>(selectedShip->experience / 100);
          detail.detailIdentity = kControlTagNavy; // 'navy'
          ++selectedChildIndex;
        }

        g_pMapContextActionManager->AddBattleRecord(&snapshot, 0);

        if (modeIsOffer) {
          int treasuryDelta = static_cast<int>(entryValue) * entryPayload;
          g_apTerrainTypeDescriptorTable[acceptNation]->AddToTreasury(-treasuryDelta);
          g_apTerrainTypeDescriptorTable[offerNation]->AddToTreasury(treasuryDelta);
          if (offerNation < kMajorNationCount) {
            g_apNationStates[offerNation]->budgetPoolDelta -= treasuryDelta;
          }
          if (acceptNation < kMajorNationCount) {
            g_apNationStates[acceptNation]->budgetPoolBase -= treasuryDelta;
          }
        }

        if (matchesOfferPass && acceptNation < kMajorNationCount) {
          g_apNationStates[acceptNation]->AddPurchasedItemAmount(slot, entryValue);
        }

        if (acceptNation < kMajorNationCount) {
          if (movedTrackedCounter) {
            g_apNationStates[acceptNation]->DealInterupted(slot, offerNation, -123456);
          } else if (matchesOfferPass) {
            g_apNationStates[acceptNation]->DealInterupted(slot, offerNation, -123457);
          }
        }
        if (offerNation < kMajorNationCount) {
          if (movedTrackedCounter) {
            g_apNationStates[offerNation]->DealInterupted(slot, acceptNation, -123456);
          } else if (matchesOfferPass) {
            g_apNationStates[offerNation]->DealInterupted(slot, acceptNation, -123459);
          }
        }
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x00559dd0
unsigned short TNavyMgr::ActionCursor(short nTileIndex, int nInputFlags) {
  return static_cast<unsigned short>(
      g_awMapContextActionLabelTokenByCommand[GetMapContextActionCode(nTileIndex, nInputFlags)]);
}

// FUNCTION: IMPERIALISM 0x00559e00
unsigned short TNavyMgr::SelectionCursor(short nTileIndex, int nInputFlags) {
  int actionCode = GetMapContextActionCode(nTileIndex, nInputFlags);
  if (actionCode != 0) {
    return g_awMapContextActionLabelTokenByCommand[actionCode];
  }

  TTaskForce* entry = GetActiveMapOrderEntry();
  if (entry == NULL) {
    return g_awMapContextActionLabelTokenByCommand[0];
  }

  if (g_pGlobalMapState->terrainStateTable[nTileIndex].GetTerrainKind() == kStrategicTerrainWater) {
    TZone* context = g_pActiveMapOrderContext->GetZoneAt(nTileIndex);
    bool canResolve = false;
    if (context != NULL && !entry->IsEmpty()) {
      bool hasActiveChild = false;
      for (TMapOrderChildLinkNode* node = entry->shipList; node != NULL; node = node->next) {
        if (node->active != 0) {
          hasActiveChild = true;
          break;
        }
      }
      if (hasActiveChild) {
        unsigned short minimumWeight = 10000;
        for (TMapOrderChildLinkNode* node = entry->shipList; node != NULL; node = node->next) {
          if (node->active != 0) {
            TShip* ship = node->payload;
            short weight = g_NavyOrderResourceDescriptorTable[ship->type].SailingSpeed();
            if (weight < static_cast<short>(minimumWeight)) {
              minimumWeight = static_cast<unsigned short>(weight);
            }
          }
        }
        short threshold = minimumWeight != 10000 ? static_cast<short>(minimumWeight) : 0;
        short distance = entry->location->GetDistanceTo(context);
        canResolve = distance <= threshold;
      }
    }
    if (canResolve) {
      actionCode = entry->MouseCodeForTarget(context);
      return g_awMapContextActionLabelTokenByCommand[actionCode];
    }
  } else {
    Province* province = GetProvinceByTileIndex(nTileIndex);
    bool canResolve = false;
    if (province != NULL) {
      short* queuedCounts = entry->shipCountsByToolbarSlot;
      if (queuedCounts[0] + queuedCounts[1] + queuedCounts[2] + queuedCounts[3] != 0) {
        for (TMapOrderChildLinkNode* node = entry->shipList; node != NULL; node = node->next) {
          if (node->active != 0) {
            canResolve = province->navyOrderReachable != 0;
            break;
          }
        }
      }
    }
    if (canResolve) {
      bool relationOutOfDate = g_pDiplomacyTurnStateManager->AreInEstablishedWar(
          entry->nation, province->ownerNationCode);
      return g_awMapContextActionLabelTokenByCommand[relationOutOfDate ? 16 : 1];
    }
  }

  return g_awMapContextActionLabelTokenByCommand[1];
}

// FUNCTION: IMPERIALISM 0x0055a020
bool TNavyMgr::SelectionClick(short nTileIndex, int nInputFlags) {
  int actionCode = GetMapContextActionCode(nTileIndex, nInputFlags);
  if (actionCode == 0) {
    return false;
  }
  TMapUberPicture* mapUberPicture = g_pViewMgr->mapUberPicture;
  switch (actionCode) {
  case 9: {
    TZone* zone = g_pActiveMapOrderContext->GetZoneAt(nTileIndex);
    mapUberPicture->FocusOnZone(zone);
    return true;
  }
  case 2:
  case 3:
  case 4:
  case 5:
  case 6:
  case 7:
  case 8: {
    TZone* zone = g_pActiveMapOrderContext->GetZoneAt(nTileIndex);
    mapUberPicture->NavalIntelligenceDialog(zone, static_cast<short>(actionCode - 2),
                                            g_pCachedMapActionContext);
    return true;
  }
  case 11: {
    TTaskForce* entry = orderQueueHead;
    while (entry != 0 && entry->ingotTileIndex != nTileIndex) {
      entry = entry->nextForce;
    }
    mapUberPicture->InspectTaskForceDialog(entry);
    return true;
  }
  case 10: {
    g_pViewMgr->MakeNavyRosterDialog(GetActiveMapOrderEntry());
    return true;
  }
  default:
    return false;
  }
}

// FUNCTION: IMPERIALISM 0x0055a160
int TNavyMgr::DoTileClick(short nTileIndex, int nInputFlags) {
  // A context-only action consumes the click without any queue mutation.
  if (SelectionClick(nTileIndex, nInputFlags)) {
    return 0;
  }
  TTaskForce* entry = GetActiveMapOrderEntry();
  int commandId;
  if (entry == NULL) {
    commandId = 0;
  } else if (g_pGlobalMapState->terrainStateTable[nTileIndex].GetTerrainKind() ==
             kStrategicTerrainWater) {
    TZone* ctx = g_pActiveMapOrderContext->GetZoneAt(nTileIndex);
    bool queueable;
    if (ctx == NULL) {
      queueable = false;
    } else if (!entry->NoSelection()) {
      short dist = entry->location->GetDistanceTo(ctx);
      queueable = dist <= static_cast<short>(entry->GetWorstSpeed());
    } else {
      queueable = false;
    }
    commandId = queueable ? entry->MouseCodeForTarget(ctx) : 1;
  } else {
    Province* province = GetProvinceByTileIndex(nTileIndex);
    commandId = (entry->IsValidTarget(province) == 0) ? 1 : entry->MouseCodeForTarget(province);
  }
  if (commandId == 0) {
    return 0;
  }
  entry = GetActiveMapOrderEntry();
  switch (commandId) {
  case 0x0a:
    g_pViewMgr->MakeNavyRosterDialog(entry);
    break;
  case 0x0c:
    entry->shipOrders = 3;
    entry->FreeAvailables();
    if (g_pNavyOrderManager->CommitForce(entry)) {
      g_pActiveMapOrderContext->CommitForce(entry);
      return 1;
    }
    break;
  case 0x0d: {
    TZone* ctx = g_pActiveMapOrderContext->GetZoneAt(nTileIndex);
    entry->shipOrders = 1;
    entry->target = ctx;
    entry->FreeAvailables();
    if (g_pNavyOrderManager->CommitForce(entry)) {
      g_pActiveMapOrderContext->CommitForce(entry);
      return 1;
    }
    break;
  }
  case 0x0e: {
    TZone* ctx = g_pActiveMapOrderContext->GetZoneAt(nTileIndex);
    entry->shipOrders = 6;
    entry->target = ctx;
    entry->FreeAvailables();
    if (g_pNavyOrderManager->CommitForce(entry)) {
      g_pActiveMapOrderContext->CommitForce(entry);
      return 1;
    }
    break;
  }
  case 0x0f: {
    TZone* ctx = g_pActiveMapOrderContext->GetZoneAt(nTileIndex);
    entry->shipOrders = 1;
    entry->target = ctx;
    entry->FreeAvailables();
    bool alreadyQueued = false;
    for (TTaskForce* node = g_pNavyOrderManager->orderQueueHead; node != NULL;
         node = node->nextForce) {
      if (node == entry) {
        alreadyQueued = true;
        break;
      }
    }
    bool committed;
    if (alreadyQueued) {
      committed = true;
    } else if (entry->CountShips() < 1) {
      entry->Free();
      committed = false;
    } else {
      entry->LinkTo(NULL, g_pNavyOrderManager->orderQueueHead);
      g_pNavyOrderManager->orderQueueHead = entry;
      committed = true;
    }
    if (committed) {
      g_pActiveMapOrderContext->CommitForce(entry);
      return 1;
    }
    break;
  }
  case 0x10:
    entry->shipOrders = 5;
    entry->target = GetProvinceByTileIndex(nTileIndex);
    entry->FreeAvailables();
    if (g_pNavyOrderManager->CommitForce(entry)) {
      g_pActiveMapOrderContext->CommitForce(entry);
      return 1;
    }
    break;
  default:
    return 0;
  }
  return 1;
}

// FUNCTION: IMPERIALISM 0x0055a4d0
TTaskForce* TNavyMgr::WhoseIngotIsAt(short tileIndex) {
  TTaskForce* entry = orderQueueHead;
  while (entry != NULL && entry->ingotTileIndex != tileIndex) {
    entry = entry->nextForce;
  }
  return entry;
}

namespace {

// FUNCTION: IMPERIALISM 0x0055a520
static float SumTaskForceChildPowerAtOrAboveTier(TTaskForce* force, int minTier) {
  float total = 0.0f;
  for (TMapOrderChildLinkNode* node = force->shipList; node != NULL; node = node->next) {
    TShip* child = node->payload;
    const TNavyOrderResourceDescriptor& descriptor =
        g_NavyOrderResourceDescriptorTable[child->type];
    if (descriptor.PriorityTier() < minTier) {
      continue;
    }
    int power = (child->experience / 100 + descriptor.FirepowerDword() * 10 + 5) / 10;
    total += static_cast<float>(power);
  }
  return total;
}

// Count of shipList entries whose resource-type priorityTier is >= minTier.
// FUNCTION: IMPERIALISM 0x0055a5e0
static int CountTaskForceChildrenAtOrAboveTier(TTaskForce* force, int minTier) {
  int count = 0;
  for (TMapOrderChildLinkNode* node = force->shipList; node != NULL; node = node->next) {
    if (g_NavyOrderResourceDescriptorTable[node->payload->type].PriorityTier() >= minTier) {
      ++count;
    }
  }
  return count;
}

// FUNCTION: IMPERIALISM 0x0055a630
static int CountTaskForceChildren(TTaskForce* force) {
  int count = 0;
  if (force != NULL) {
    for (TMapOrderChildLinkNode* node = force->shipList; node != NULL; node = node->next) {
      ++count;
    }
  }
  return count;
}

static inline int CountMapOrderChildren(TMapOrderChildLinkNode* head) {
  int count = 0;
  for (TMapOrderChildLinkNode* node = head; node != NULL; node = node->next) {
    ++count;
  }
  return count;
}

static inline int GetAverageShipWeight(TMapOrderChildLinkNode* head) {
  int sum = 0;
  int count = 0;
  for (TMapOrderChildLinkNode* node = head; node != 0; node = node->next) {
    if (node->active != 0) {
      sum += g_NavyOrderResourceDescriptorTable[node->payload->type].SailingSpeed();
      ++count;
    }
  }
  if (count == 0) {
    return 0;
  }
  return (sum * 10) / count;
}

static inline int GetForceStrength(TShip* ship) {
  const TNavyOrderResourceDescriptor& descriptor = g_NavyOrderResourceDescriptorTable[ship->type];
  short strengthBucket = ship->experience / 100;
  short navyPriorityBucket =
      static_cast<short>((strengthBucket + descriptor.BattleSpeedDword() * 10 + 5) / 10);
  short resolveBucket =
      static_cast<short>((strengthBucket + descriptor.FirepowerDword() * 10 + 5) / 10);
  return ((navyPriorityBucket + descriptor.BattleRange()) * 100 + resolveBucket + ship->strength) /
         descriptor.Armor();
}

// FUNCTION: IMPERIALISM 0x0055a690
static void ApplyTaskForceConflictAttrition(TTaskForce* force, float favorRatio, int target,
                                            int currentCount) {
  if (target <= 0) {
    return;
  }
  int selected = 0;
  do {
    for (TMapOrderChildLinkNode* node = force->shipList; node != NULL && selected < target;
         node = node->next) {
      if (currentCount == target || rand() % currentCount < target) {
        ++selected;
        int roll = rand() % 100 + rand() % 100 + 100;
        TShip* child = node->payload;
        short damage =
            static_cast<short>(0.5 - g_NavyOrderResourceDescriptorTable[child->type].Armor() *
                                         (roll * 0.005) * favorRatio * -0.01);
        child->strength = static_cast<short>(child->strength - damage);
      }
    }
  } while (selected < target);
}

static inline TMapOrderChildLinkNode*
PruneMapOrderConflictHeadAndTail(TMapOrderChildLinkNode* head) {
  if (head == NULL) {
    return NULL;
  }
  TShip* child = head->payload;
  if (child->strength < 1) {
    child->SetTaskForce(NULL);
    child->Free();
    head = head->DeleteMapOrderChildLinkAndReturnNext();
    head = head->PruneDefeatedShips();
  } else {
    head->next->PruneDefeatedShips();
  }
  return head;
}
} // namespace

// FUNCTION: IMPERIALISM 0x0055a780
void TNavyMgr::ResolveStrategicBattle(TTaskForce* leftEntry, TTaskForce* rightEntry) {
  MapOrderBattleSnapshot snapshot;
  snapshot.reportKind = kMapContextReportSeaBattle;
  snapshot.targetObject = leftEntry->location;
  snapshot.displayedParticipantIndex = 0;
  snapshot.childCount[0] = 0;
  snapshot.childCount[1] = 0;
  snapshot.childRecords[0] = 0;
  snapshot.childRecords[1] = 0;
  BuildMapOrderBattleSideSnapshot(&snapshot, 0, leftEntry);
  BuildMapOrderBattleSideSnapshot(&snapshot, 1, rightEntry);

  int leftStartCount = CountMapOrderChildren(leftEntry->shipList);
  int rightStartCount = CountMapOrderChildren(rightEntry->shipList);

  int maxTier = 1;
  for (TMapOrderChildLinkNode* node = leftEntry->shipList; node != NULL; node = node->next) {
    int tier = g_NavyOrderResourceDescriptorTable[node->payload->type].PriorityTier();
    if (tier > maxTier) {
      maxTier = tier;
    }
  }
  for (TMapOrderChildLinkNode* rightNode = rightEntry->shipList; rightNode != NULL;
       rightNode = rightNode->next) {
    int tier = g_NavyOrderResourceDescriptorTable[rightNode->payload->type].PriorityTier();
    if (tier > maxTier) {
      maxTier = tier;
    }
  }

  const float kTierConvergenceThreshold[3] = {1.1f, 0.95f, 0.8f};
  float leftThreshold = kTierConvergenceThreshold[leftEntry->aggression];
  float rightThreshold = kTierConvergenceThreshold[rightEntry->aggression];

  int candidateTier = maxTier;
  bool leftThresholdFailed = false;
  bool rightThresholdFailed = false;

  for (;;) {
    TAdmiral* leftAdmiral =
        leftEntry == 0 || leftEntry->flagship == 0 ? 0 : leftEntry->flagship->admiral;
    int leftBucket = leftAdmiral == 0 ? 0 : leftAdmiral->experiencePoints / 100;
    TAdmiral* rightAdmiral =
        rightEntry == 0 || rightEntry->flagship == 0 ? 0 : rightEntry->flagship->admiral;
    int rightBucket = rightAdmiral == 0 ? 0 : rightAdmiral->experiencePoints / 100;

    int bestLeftFavorTier = 0;
    float bestLeftFavorRatio = 0.0f;
    int bestRightFavorTier = 0;
    float bestRightFavorRatio = 0.0f;
    for (int tier = 1; tier <= maxTier; ++tier) {
      float leftPower =
          SumTaskForceChildPowerAtOrAboveTier(leftEntry, tier) * (1.0f + leftBucket * 0.1f);
      float rightPower =
          SumTaskForceChildPowerAtOrAboveTier(rightEntry, tier) * (1.0f + rightBucket * 0.1f);
      float leftFavorRatio = leftPower / rightPower;
      if (leftFavorRatio > bestLeftFavorRatio) {
        bestLeftFavorTier = tier;
        bestLeftFavorRatio = leftFavorRatio;
      }
      float rightFavorRatio = rightPower / leftPower;
      if (rightFavorRatio > bestRightFavorRatio) {
        bestRightFavorTier = tier;
        bestRightFavorRatio = rightFavorRatio;
      }
    }

    // 0 = tier should drop for this side, 2 = tier should rise, 1 = holds.
    leftThresholdFailed = bestLeftFavorRatio < leftThreshold;
    rightThresholdFailed = bestRightFavorRatio < rightThreshold;
    int leftTierAdjust;
    if (bestLeftFavorTier < candidateTier) {
      leftTierAdjust = 0;
    } else if (leftThresholdFailed || bestLeftFavorTier > candidateTier) {
      leftTierAdjust = 2;
    } else {
      leftTierAdjust = 1;
    }
    int rightTierAdjust;
    if (bestRightFavorTier < candidateTier) {
      rightTierAdjust = 0;
    } else if (rightThresholdFailed || bestRightFavorTier > candidateTier) {
      rightTierAdjust = 2;
    } else {
      rightTierAdjust = 1;
    }

    int leftWeight = (leftBucket + 10) * GetAverageShipWeight(leftEntry->shipList);
    int rightWeight = (rightBucket + 10) * GetAverageShipWeight(rightEntry->shipList);
    int totalWeight = leftWeight + rightWeight;

    if (rand() % totalWeight < leftWeight) {
      if (leftTierAdjust == 0) {
        --candidateTier;
      }
      if (leftTierAdjust == 2) {
        ++candidateTier;
      }
    }
    if (rand() % totalWeight < rightWeight) {
      if (rightTierAdjust == 0) {
        --candidateTier;
      }
      if (rightTierAdjust == 2) {
        ++candidateTier;
      }
    }
    if (candidateTier < 1) {
      candidateTier = 1;
    }

    if (candidateTier > maxTier) {
      break;
    }

    int leftEligible = CountTaskForceChildrenAtOrAboveTier(leftEntry, candidateTier);
    int rightEligible = CountTaskForceChildrenAtOrAboveTier(rightEntry, candidateTier);
    int leftCurrentCount = CountTaskForceChildren(leftEntry);
    int rightCurrentCount = CountTaskForceChildren(rightEntry);

    float leftPower =
        SumTaskForceChildPowerAtOrAboveTier(leftEntry, candidateTier) * (1.0f + leftBucket * 0.1f);
    float rightPower = SumTaskForceChildPowerAtOrAboveTier(rightEntry, candidateTier) *
                       (1.0f + rightBucket * 0.1f);
    int leftAttritionTarget = rightEligible < leftCurrentCount ? rightEligible : leftCurrentCount;
    int rightAttritionTarget = leftEligible < rightCurrentCount ? leftEligible : rightCurrentCount;
    ApplyTaskForceConflictAttrition(leftEntry, rightPower / static_cast<float>(leftAttritionTarget),
                                    leftAttritionTarget, leftCurrentCount);
    ApplyTaskForceConflictAttrition(rightEntry,
                                    leftPower / static_cast<float>(rightAttritionTarget),
                                    rightAttritionTarget, rightCurrentCount);

    leftEntry->shipList = PruneMapOrderConflictHeadAndTail(leftEntry->shipList);
    leftEntry->ElectFlagship();
    bool leftEmpty = leftEntry->shipList == NULL;
    if (leftEmpty) {
      leftEntry->defeated = 1;
    }

    rightEntry->shipList = PruneMapOrderConflictHeadAndTail(rightEntry->shipList);
    rightEntry->ElectFlagship();
    bool rightEmpty = rightEntry->shipList == NULL;
    if (rightEmpty) {
      rightEntry->defeated = 1;
    }

    if (leftEmpty || rightEmpty) {
      break;
    }
  }

  bool leftEliminated = leftEntry->shipList == NULL;
  bool rightEliminated = rightEntry->shipList == NULL;
  signed char outcome;
  if (leftEliminated) {
    outcome = static_cast<signed char>(rightEliminated ? -1 : 1);
  } else if (rightEliminated) {
    outcome = 0;
  } else if (leftThresholdFailed) {
    outcome = static_cast<signed char>(rightThresholdFailed ? -1 : 1);
  } else {
    outcome = static_cast<signed char>(rightThresholdFailed ? 0 : -1);
  }
  snapshot.reportParticipantIndex = static_cast<unsigned char>(outcome);
  if (outcome != -1) {
    TTaskForce* loser = outcome == 1 ? leftEntry : rightEntry;
    TTaskForce* winner = outcome == 1 ? rightEntry : leftEntry;
    int loserStart = outcome == 1 ? leftStartCount : rightStartCount;
    int loserRemaining = CountMapOrderChildren(loser->shipList);
    int bump = (loserStart - loserRemaining) * 5 + loserRemaining;
    int winnerCount = CountMapOrderChildren(winner->shipList);
    if (winnerCount > 0) {
      TAdmiral* winningAdmiral = winner->flagship == 0 ? 0 : winner->flagship->admiral;
      if (winningAdmiral != 0) {
        winningAdmiral->experiencePoints =
            static_cast<short>(winningAdmiral->experiencePoints + bump);
        if (winningAdmiral->experiencePoints > 499) {
          winningAdmiral->experiencePoints = 499;
        }
      }
      for (TMapOrderChildLinkNode* node = winner->shipList; node != NULL; node = node->next) {
        node->payload->Victory(static_cast<short>((bump * 3) / winnerCount));
      }
    }
    loser->defeated = 1;
  }

  RefreshMapOrderBattleSideSnapshot(&snapshot, 0, leftEntry->shipList != NULL ? leftEntry : NULL);
  RefreshMapOrderBattleSideSnapshot(&snapshot, 1, rightEntry->shipList != NULL ? rightEntry : NULL);
  g_pMapContextActionManager->AddBattleRecord(&snapshot, 0);
}
