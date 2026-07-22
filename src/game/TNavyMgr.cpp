#include "game/TNavyMgr.h"

#include <stdlib.h>

#include "game/TAdmiral.h"
#include "game/TArmyMgr.h"
#include "game/TCity.h"
#include "game/TCountry.h"
#include "game/TGreatPower.h"
#include "game/TMapMgr.h"
#include "game/TMapUberPicture.h"
#include "game/TViewMgr.h"
#include "game/map_overlay_geometry.h"
#include "game/TOcean.h"
#include "game/TShip.h"
#include "game/navy_order.h"
#include "game/TStream.h"
#include "game/TDiplomacyMgr.h"
#include "game/TObject.h"
#include "game/TPortZone.h"
#include "game/TMultiplayerMgr.h"
#include "game/TSimMgr.h"
#include "game/TTaskForce.h"
#include "game/TZone.h"
#include "game/CString.h"
#include "game/global_data_tables.h"
#include "game/ui_invalidation_guard.h"
#include "game/mapped_flavor_text.h"
#include "game/map_order_battle_snapshot.h"

// 0x00563360 -- __stdcall free resolver (defined in TMapMgr.cpp); used by the
// reattributed DoTileClick below.
Province* __stdcall GetProvinceByTileIndex(short nTileIndex);

// Resolves a raw Province* back into its index in
// g_pGlobalMapState's cityScoreTable. Real __fastcall: the single arg arrives in ecx
// and no original callsite pushes anything.
// FUNCTION: IMPERIALISM 0x0050e2c0
int __fastcall GetProvinceIndex(Province* province) {
  return static_cast<int>(province - g_pGlobalMapState->cityScoreTable);
}

namespace {

// Shared by BuildMapOrderBattleSideSnapshot's two fixed-size name/label copies and its
// per-child name copy: copies up to destSize-1 chars of `src` into `dest`, stopping at
// the first NUL (matching the original's own byte-at-a-time copy loop).
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

// Sum, over shipList entries whose resource-type priorityTier is >= minTier, of
// (child experience/100 + resolveWeight*10 + 5)/10 -- the per-child "combat power"
// term ResolveStrategicBattle's tier-scoring loop accumulates as a float.
static inline float SumMapOrderChildPowerAtOrAboveTier(TMapOrderChildLinkNode* head, int minTier) {
  float total = 0.0f;
  for (TMapOrderChildLinkNode* node = head; node != nullptr; node = node->next) {
    TShip* child = static_cast<TShip*>(node->payload);
    const TNavyOrderResourceDescriptor& descriptor =
        g_NavyOrderResourceDescriptorTable[child->type];
    if (descriptor.priorityTier < minTier) {
      continue;
    }
    int power = (child->experience / 100 + descriptor.resolveWeight * 10 + 5) / 10;
    total += static_cast<float>(power);
  }
  return total;
}

// Count of shipList entries whose resource-type priorityTier is >= minTier.
static inline int CountMapOrderChildrenAtOrAboveTier(TMapOrderChildLinkNode* head, int minTier) {
  int count = 0;
  for (TMapOrderChildLinkNode* node = head; node != nullptr; node = node->next) {
    if (g_NavyOrderResourceDescriptorTable[static_cast<TShip*>(node->payload)->type].priorityTier >=
        minTier) {
      ++count;
    }
  }
  return count;
}

static inline int CountMapOrderChildren(TMapOrderChildLinkNode* head) {
  int count = 0;
  for (TMapOrderChildLinkNode* node = head; node != nullptr; node = node->next) {
    ++count;
  }
  return count;
}

static inline int CalculateActiveChildAverageDescriptorWeightX10(TMapOrderChildLinkNode* head) {
  int sum = 0;
  int count = 0;
  for (TMapOrderChildLinkNode* node = head; node != 0; node = node->next) {
    if (node->active != 0) {
      sum += g_NavyOrderResourceDescriptorTable[static_cast<TShip*>(node->payload)->type]
                 .descriptorWeight;
      ++count;
    }
  }
  if (count == 0) {
    return 0;
  }
  return (sum * 10) / count;
}

// The selector's non-hostile comparison branch expands this same integer score at both
// child-list walks instead of calling TShip::GetBattleStrengthRating.
static inline int CalculateMapOrderInteractionShipStrength(TShip* ship) {
  const TNavyOrderResourceDescriptor& descriptor = g_NavyOrderResourceDescriptorTable[ship->type];
  short strengthBucket = static_cast<short>(ship->experience / 100);
  short navyPriorityBucket =
      static_cast<short>((strengthBucket + descriptor.navyPriorityWeight * 10 + 5) / 10);
  short resolveBucket =
      static_cast<short>((strengthBucket + descriptor.resolveWeight * 10 + 5) / 10);
  return ((navyPriorityBucket + descriptor.calculateWeight) * 100 + resolveBucket +
          ship->strength) /
         descriptor.taskForceWeight;
}

// Randomly applies a resource-weighted attrition roll (0x55ae70/0x55af36) to up to
// `target` of `head`'s children: for each candidate node, rolls
// rand()%currentCount < target to select it, restarting at the head until exactly
// `target` children have been selected, then reduces its nation by
// 0.5 + taskForceWeight[child->type] * ((rand()%100+rand()%100+100) * 0.005) *
// favorRatio * 0.01 (the confirmed real float constants at 0x65c3a8/0x65c3b0/0x65c3b8).
static inline void ApplyMapOrderConflictAttrition(TMapOrderChildLinkNode* head, int currentCount,
                                                  int target, float favorRatio) {
  if (target <= 0) {
    return;
  }
  int selected = 0;
  do {
    for (TMapOrderChildLinkNode* node = head; node != nullptr && selected < target;
         node = node->next) {
      if (currentCount == target || static_cast<int>(rand()) % currentCount < target) {
        ++selected;
        int roll = static_cast<int>(rand()) % 100 + static_cast<int>(rand()) % 100 + 100;
        TShip* child = static_cast<TShip*>(node->payload);
        float delta = 0.5f + g_NavyOrderResourceDescriptorTable[child->type].taskForceWeight *
                                 (roll * 0.005f) * favorRatio * -0.01f;
        child->strength = static_cast<short>(child->strength - static_cast<short>(delta));
      }
    }
  } while (selected < target);
}

// Removes a depleted (nation < 1) list head and prunes any other depleted entries
// further down the chain; matches the real call sequence at 0x55afff/0x55b06e
// (SetMapOrderActiveChildEntry(nullptr) + Free() + DeleteMapOrderChildLinkAndReturnNext on a
// depleted head, else a side-effect-only PruneDefeatedMapOrderChildrenAndReturnHead(head->next)
// call on a still-alive head) rather than TTaskForce::PruneDefeatedMapOrderChildrenAndReturnHead's
// own equivalent-but-differently-sequenced internal logic.
static inline TMapOrderChildLinkNode*
PruneMapOrderConflictHeadAndTail(TMapOrderChildLinkNode* head) {
  if (head == nullptr) {
    return nullptr;
  }
  TShip* child = static_cast<TShip*>(head->payload);
  if (child->strength < 1) {
    child->SetTaskForce(nullptr);
    child->Free();
    head = head->DeleteMapOrderChildLinkAndReturnNext();
    head = head->PruneDefeatedMapOrderChildrenAndReturnHead();
  } else {
    head->next->PruneDefeatedMapOrderChildrenAndReturnHead();
  }
  return head;
}
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

  short childCount = static_cast<short>(entry->CountShips());
  snapshot->childCount[side] = childCount;

  MapOrderBattleSideChildRecord* records = nullptr;
  if (childCount > 0) {
    records = new MapOrderBattleSideChildRecord[childCount];
    // Original only zeroes each record's first byte (a stride-0x2c loop writing one
    // byte per record), not the whole record -- reproduced verbatim.
    for (int i = 0; i < childCount; ++i) {
      reinterpret_cast<char*>(&records[i])[0] = 0;
    }
  }
  snapshot->childRecords[side] = records;

  int idx = 0;
  for (TMapOrderChildLinkNode* node = entry->shipList; node != nullptr; node = node->next) {
    // These children are TShip primary-order nodes (not nested TTaskForce entries --
    // confirmed via the CString read at +0x18, which only lines up with
    // TShip::name; TTaskForce's own +0x18 is location, an int).
    TShip* child = static_cast<TShip*>(node->payload);
    MapOrderBattleSideChildRecord& rec = records[idx];
    rec.resourceType = child->type;
    rec.stockOrRequired = child->strength;
    CopyCStringIntoFixedBuffer(rec.nameBuffer, 0x20, static_cast<LPCSTR>(child->name));
    rec.detailIdentity.sourceObject = child;
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
    TShip* child = static_cast<TShip*>(rec.detailIdentity.sourceObject);
    bool stillPresent = entry != nullptr && entry->shipList->FindNodeMatching(child) != nullptr;
    if (stillPresent) {
      rec.stockOrRequired = child->strength;
      rec.strengthBucket = static_cast<short>(child->experience / 100);
    } else {
      rec.stockOrRequired = 0;
    }
    // Finalize the working pointer slot into the report-row category consumed by
    // TBatRepDetLine::InstallViews.
    rec.detailIdentity.categoryTag = 0x6e617679; // 'navy'
  }

  if (entry != nullptr && entry->shipOrders == 5) {
    int cityIndex = GetProvinceIndex(entry->target.asProvince);
    g_pMapContextActionManager->TrimExcessNavyOrderSupportAndRebuildOrderBuffer(
        snapshot->nationIds[side], cityIndex, snapshot);
  }
}

// Formats "<count><sep><commodity name>" into `out`: fetches the commodity's
// localized name (singular string group 0x2716 for count < 2, plural 0x271a
// otherwise) into `out`, then, for a non-negative count, prefixes the decimal count
// and the shared separator string using the real MFC CString::Format and operator+.
// FUNCTION: IMPERIALISM 0x00550c20
void FormatLocalizedCommodityCountLabelByIndex(CString* out, unsigned int commodityCode,
                                               short count) {
  short codeGroup = (count < 2) ? 0x2716 : 0x271a;
  g_pSimMgr->GetString(codeGroup, static_cast<short>(commodityCode), out);
  if (count >= 0) {
    CString numberText;
    numberText.Format(g_szDecimalFormat, static_cast<int>(count));
    *out = numberText + s_szSpaceSeparator_00695794 + *out;
  }
}

// SYNTHETIC: IMPERIALISM 0x00556530
// TNavyMgr::CreateObject

// SYNTHETIC: IMPERIALISM 0x00556570
// TNavyMgr::GetRuntimeClass

IMPLEMENT_DYNCREATE(TNavyMgr, TObject)

// FUNCTION: IMPERIALISM 0x00556590
TNavyMgr::TNavyMgr() : orderQueueHead(0), executionPhase(-1), pendingOrderEntry(nullptr) {}

// SYNTHETIC: IMPERIALISM 0x005565c0
// TNavyMgr::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x005565f0
TNavyMgr::~TNavyMgr() {}

// Seeds the three navy order-type ranking tables with the identity permutation, then
// selection-sorts each by descending descriptor weight (resolve / calculate-mission /
// navy-priority). The weight columns are read as dwords from the descriptor table, matching
// the original's g_..._LookupTable_006981xx int views.
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
      if (pj->navyPriorityWeight > pi->navyPriorityWeight) {
        short t = g_NavyPriorityOrderRanking[i];
        g_NavyPriorityOrderRanking[i] = g_NavyPriorityOrderRanking[j];
        g_NavyPriorityOrderRanking[j] = t;
      }
      TNavyOrderResourceDescriptor* mi =
          &g_NavyOrderResourceDescriptorTable[g_NavyMissionOrderRanking[i]];
      TNavyOrderResourceDescriptor* mj =
          &g_NavyOrderResourceDescriptorTable[g_NavyMissionOrderRanking[j]];
      if (mj->calculateWeightDword > mi->calculateWeightDword) {
        short t = g_NavyMissionOrderRanking[i];
        g_NavyMissionOrderRanking[i] = g_NavyMissionOrderRanking[j];
        g_NavyMissionOrderRanking[j] = t;
      }
      TNavyOrderResourceDescriptor* ri =
          &g_NavyOrderResourceDescriptorTable[g_NavyResolveOrderRanking[i]];
      TNavyOrderResourceDescriptor* rj =
          &g_NavyOrderResourceDescriptorTable[g_NavyResolveOrderRanking[j]];
      if (rj->resolveWeightDword > ri->resolveWeightDword) {
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
  stream->WriteBytesSlot78(&matchCount, 2);
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
  stream->WriteBytesSlot78(&matchCount, 2);
  for (TAdmiral* admiral2 = g_pNavySecondaryOrderListHead; admiral2 != 0;
       admiral2 = admiral2->next) {
    if (nationFilter == -1 || nationFilter == admiral2->nationSlot) {
      admiral2->WriteTo(stream);
    }
  }
  matchCount = 0;
  // +0x1c is nation in TTaskForce.h but every navy-order reader (see
  // RemoveMatchingTaskForceOrders) treats it as the entry's nation slot.
  for (TTaskForce* order = orderQueueHead; order != 0; order = order->nextForce) {
    if (nationFilter == -1 || nationFilter == order->nation) {
      ++matchCount;
    }
  }
  stream->WriteBytesSlot78(&matchCount, 2);
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

static void RemoveMatchingSecondaryOrders(short nationSlot) {
  TAdmiral* node = g_pNavySecondaryOrderListHead;
  while (node != 0) {
    TAdmiral* nextNode = node->next;
    if (node->nationSlot == nationSlot) {
      node->Free();
    }
    node = nextNode;
  }
}

static void RemoveMatchingTaskForceOrders(TNavyMgr* navyManager, short nationSlot) {
  TTaskForce* node = navyManager->orderQueueHead;
  while (node != nullptr) {
    TTaskForce* nextNode = node->nextForce;
    if (node->nation == nationSlot) {
      node->Free();
    }
    node = nextNode;
  }
}

// FUNCTION: IMPERIALISM 0x00556ad0
void TNavyMgr::ReadFromFilterously(TStream* stream, short nationFilter) {
  if (nationFilter == -1) {
    // Full resync: drop every existing entry from all three navy order lists first
    // (each Free() unlinks the head, so the loops drain the chains).
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
    RemoveOrdersByNationFromPrimarySecondaryAndTaskForceLists(nationFilter);
  }

  // Primary TShip chain (16-bit count, written tail-first by the serializer; TShip()
  // itself prepends each node to g_pNavyPrimaryOrderListHead, restoring the order).
  // Only the low word of pendingCount is ever written/tested, mirroring the original's
  // 2-byte read into a 4-byte slot.
  int pendingCount;
  stream->ReadBytes(&pendingCount, 2);
  while (static_cast<short>(pendingCount--) != 0) {
    TShip* shipNode = new TShip();
    if (shipNode == 0) {
      FailNilPointerWithAssert(s_SourcePathUNavy_006983C8, 0xd11);
    }
    shipNode->ReadFrom(stream);
    if (nationFilter != -1 && shipNode->nation != nationFilter) {
      shipNode->Free();
    }
  }

  // TAdmiral secondary chain (the ctor links each node into
  // g_pNavySecondaryOrderListHead).
  stream->ReadBytes(&pendingCount, 2);
  while (static_cast<short>(pendingCount--) != 0) {
    TAdmiral* admiralNode = new TAdmiral();
    if (admiralNode == 0) {
      FailNilPointerWithAssert(s_SourcePathUNavy_006983C8, 0xd24);
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
      FailNilPointerWithAssert(s_SourcePathUNavy_006983C8, 0xd37);
    }
    orderEntry->ReadFrom(stream);
    if (nationFilter != -1 && orderEntry->nation != nationFilter) {
      orderEntry->Free();
    }
    // Open-coded CommitForce (0x557080) - the original emits
    // this logic inline here (registers carry across it), not as a call: if the entry
    // is not already queued, free it when it has no children, else unlink it and push
    // it to the queue head.
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

// Mac oracle: TNavyMgr::FreeShipsOf(short).
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
  for (TShip* ship = g_pNavyPrimaryOrderListHead; ship != nullptr; ship = ship->next) {
    ship->taskForce = 0;
  }
  if (orderQueueHead != nullptr) {
    orderQueueHead->FreeAll();
  }
  orderQueueHead = nullptr;
  g_pActiveMapOrderContext->EnsureSelectedTaskForceForOrderOwnerAndRefresh(nullptr);
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
  for (TTaskForce* node = orderQueueHead; node != nullptr; node = node->nextForce) {
    if (node == entry) {
      return true;
    }
  }

  int childCount = 0;
  if (entry != nullptr) {
    for (TMapOrderChildLinkNode* node = entry->shipList; node != nullptr; node = node->next) {
      ++childCount;
    }
  }

  if (childCount <= 0) {
    entry->Free();
    return false;
  }

  if (entry->previousForce != nullptr) {
    entry->previousForce->nextForce = entry->nextForce;
  }
  if (entry->nextForce != nullptr) {
    entry->nextForce->previousForce = entry->previousForce;
  }
  entry->previousForce = nullptr;
  entry->nextForce = orderQueueHead;
  if (orderQueueHead != nullptr) {
    orderQueueHead->previousForce = entry;
  }
  orderQueueHead = entry;
  return true;
}

// FUNCTION: IMPERIALISM 0x00557170
short TNavyMgr::GetInvasionCapacity(short nationSlot, Province* provinceTarget,
                                    TZone* contextFilter) {
  int total = 0;
  for (TTaskForce* order = orderQueueHead; order != nullptr; order = order->nextForce) {
    if (order->nation == nationSlot && order->shipOrders == 5 &&
        order->target.asProvince == provinceTarget &&
        (contextFilter == nullptr || order->location == contextFilter)) {
      int sum = 0;
      for (TMapOrderChildLinkNode* item = order->shipList; item != nullptr; item = item->next) {
        TShip* ship = static_cast<TShip*>(item->payload);
        short contribution = 0;
        if (ship->strength > 0) {
          contribution = g_industryActionCostWeightResCode10[ship->type];
        }
        sum += contribution;
      }
      total += sum;
    }
  }
  return static_cast<short>(total);
}

// FUNCTION: IMPERIALISM 0x00557210
void TNavyMgr::RemoveOrdersByNationFromPrimarySecondaryAndTaskForceLists(short nationSlot) {
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

  RemoveMatchingSecondaryOrders(nationSlot);
  RemoveMatchingTaskForceOrders(this, nationSlot);
}

// Per-turn map-order revalidation sweep: for every map-action context zone and
// great-power slot, rebuild the nation's candidate order entry from its navy
// orders, gate each child on the shared per-order-type stock cap when the zone
// still has port capability, and requeue/rebuild+finalize the surviving entry.
// FUNCTION: IMPERIALISM 0x00557560
void TNavyMgr::MakeSureAllShipsHaveOrders() {
  g_pActiveMapOrderContext->EnsureSelectedTaskForceForOrderOwnerAndRefresh(0);
  TZone* zone = g_pMapActionContextListHead;
  if (zone == 0) {
    return;
  }
  do {
    for (short nation = 0; nation < 7; ++nation) {
      if (g_apTerrainTypeDescriptorTable[nation] == 0) {
        continue;
      }
      TTaskForce* entry = zone->CreateTaskForceFromNavyOrdersForNationIfEligible(nation);
      if (entry == 0) {
        continue;
      }
      if (zone->QueryPortZoneCapability()) {
        TMapOrderChildLinkNode* node = entry->shipList;
        if (node != 0) {
          do {
            node->active =
                static_cast<TShip*>(node->payload)->strength <
                g_NavyOrderResourceDescriptorTable[static_cast<TShip*>(node->payload)->type]
                    .stockCap;
            node = node->next;
          } while (node != 0);
        }
        entry->shipOrders = 8;
        entry->CommitToOrders();
        entry = zone->CreateTaskForceFromNavyOrdersForNationIfEligible(nation);
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
      // location (+0x18) is the entry's owning map-action context TZone* (see
      // TTaskForce.h); slot 0x54 is TZone::QueryPortZoneCapability.
      if (entry->location->QueryPortZoneCapability()) {
        entry->shipOrders = 7;
        entry->FreeAvailables();
        entry->AssertValid();
        if (g_pNavyOrderManager->CommitForce(entry)) {
          g_pActiveMapOrderContext->FinalizeQueuedMapOrderEntry(entry);
        }
      } else {
        node = entry->shipList;
        entry->shipOrders = 4;
        entry->flagship = 0;
        while (node != 0) {
          if (node->active != 0) {
            node = node->next;
          } else {
            static_cast<TShip*>(node->payload)->SetTaskForce(0);
            short bucketIndex = static_cast<short>(
                g_NavyOrderResourceDescriptorTable[static_cast<TShip*>(node->payload)->type]
                    .enabledFlagOrBucketOffset);
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
          entry->flagship = static_cast<TShip*>(node->payload)->Finest(entry->flagship, 0);
        }
        entry->AssertValid();
        if (g_pNavyOrderManager->CommitForce(entry)) {
          g_pActiveMapOrderContext->FinalizeQueuedMapOrderEntry(entry);
        }
      }
    }
    zone = zone->prev18;
  } while (zone != 0);
}

// FUNCTION: IMPERIALISM 0x005577b0
void TNavyMgr::PrepareToCarryOutAllOrders(short phaseId) {
  for (int provinceIndex = 0; provinceIndex < 0x180; ++provinceIndex) {
    Province* record = &g_pGlobalMapState->cityScoreTable[provinceIndex];
    if (record->exploredByNationMaskA1 != 0) {
      record->exploredByNationMaskA1 = 0;
      unsigned char shouldInvalidateCity = g_pSimMgr->multiplayerSessionRole == 1;
      if (shouldInvalidateCity) {
        g_pGameFlowState->DispatchCityRedrawInvalidateEvent(static_cast<short>(provinceIndex));
      }
    }
  }

  executionPhase = phaseId;

  MakeSureAllShipsHaveOrders();

  TTaskForce* head = orderQueueHead;
  if (head != nullptr) {
    TTaskForce* following = head->nextForce;
    head->defeated = 0;
    following->RechargeAll();
  }
}

// Per-turn-phase map-order conflict resolver. Six filter/inner-loop passes over
// orderQueueHead, each pairing an outer "kind" filter against an inner-loop match,
// then attempting a resolution chain (TryToSpot ->
// ResolveEncounterWith -> BattleWith);
// any pairwise resolution that reports a nonzero result ends the whole function
// immediately. Passes A/B/D share that 3-method chain shape; Pass E's "should attempt"
// gate is a separate inline computation (not a call to TryToSpot
// -- both sides go through GetDeciSpeed here, unlike that
// method's own manual self-side sum) feeding directly into the 2-method
// TryMarkLosing/TryResolve chain. Passes C/F apply execution effects directly with no
// pairing. Finishes with the two-pass nation-interaction sweep, a queue-head rebuild via
// RemoveStragglers, a primary TShip list flag-clear pass, and an
// overlay refresh.
// FUNCTION: IMPERIALISM 0x005578a0
void TNavyMgr::CarryOutOrders() {
  if (pendingOrderEntry != nullptr) {
    pendingOrderEntry->Free();
    pendingOrderEntry = nullptr;
  }

  // Pass A: 3/4-kind entries vs a matching-context 6-kind entry.
  {
    for (TTaskForce* entry = orderQueueHead; entry != nullptr; entry = entry->nextForce) {
      if (!(entry->shipOrders == 3 || entry->shipOrders == 4))
        continue;
      if (entry->defeated != 0)
        continue;
      for (TTaskForce* other = orderQueueHead; other != nullptr; other = other->nextForce) {
        if (other->location != entry->location)
          continue;
        if (!g_pDiplomacyTurnStateManager->IsNationPairRelationTurnStampOutOfDate(other->nation,
                                                                                  entry->nation)) {
          continue;
        }
        if (other->shipOrders != 6)
          continue;
        char result = 0;
        if (entry->TryToSpot(other) && entry->ResolveEncounterWith(other)) {
          TTaskForce* unresolvedForce;
          result = entry->BattleWith(other, unresolvedForce);
        }
        if (result != 0)
          return;
        if (entry->defeated != 0)
          break;
      }
    }
  }

  // Pass B: 6-kind entries vs a 1-kind entry sharing a location or target zone.
  {
    for (TTaskForce* entry = orderQueueHead; entry != nullptr; entry = entry->nextForce) {
      if (entry->shipOrders != 6)
        continue;
      if (entry->defeated != 0)
        continue;
      for (TTaskForce* other = orderQueueHead; other != nullptr; other = other->nextForce) {
        if (!g_pDiplomacyTurnStateManager->IsNationPairRelationTurnStampOutOfDate(other->nation,
                                                                                  entry->nation)) {
          continue;
        }
        bool ownerMatch =
            (other->shipOrders == 1) && (other->location == entry->target.asZone ||
                                         other->target.asZone == entry->target.asZone);
        if (!ownerMatch)
          continue;
        char result = 0;
        if (entry->TryToSpot(other) && entry->ResolveEncounterWith(other)) {
          TTaskForce* unresolvedForce;
          result = entry->BattleWith(other, unresolvedForce);
        }
        if (result != 0)
          return;
        if (entry->defeated != 0)
          break;
      }
    }
  }

  // Pass C: apply type-1 execution effects directly.
  {
    for (TTaskForce* entry = orderQueueHead; entry != nullptr; entry = entry->nextForce) {
      if (entry->shipOrders == 1 && entry->defeated == 0) {
        entry->CarryOutOrders();
      }
    }
  }

  // Pass D: 3/4-kind entries vs a matching-context NON-6-kind entry. Same outer filter
  // as Pass A; the diplomacy/location check order is swapped and the inner
  // ship-order check is inverted, matching the disassembly's distinct compiled shape.
  {
    for (TTaskForce* entry = orderQueueHead; entry != nullptr; entry = entry->nextForce) {
      if (!(entry->shipOrders == 3 || entry->shipOrders == 4))
        continue;
      if (entry->defeated != 0)
        continue;
      for (TTaskForce* other = orderQueueHead; other != nullptr; other = other->nextForce) {
        if (!g_pDiplomacyTurnStateManager->IsNationPairRelationTurnStampOutOfDate(other->nation,
                                                                                  entry->nation)) {
          continue;
        }
        if (other->location != entry->location)
          continue;
        if (other->shipOrders == 6)
          continue;
        char result = 0;
        if (entry->TryToSpot(other) && entry->ResolveEncounterWith(other)) {
          TTaskForce* unresolvedForce;
          result = entry->BattleWith(other, unresolvedForce);
        }
        if (result != 0)
          return;
        if (entry->defeated != 0)
          break;
      }
    }
  }

  // Pass E: 1-kind entries vs a matching-context 5-kind entry. The "should attempt" gate
  // is an inline duplicate of TryToSpot's shape (not a call to
  // it), feeding straight into ResolveEncounterWith (no
  // ShouldAttempt call in this pass's chain).
  {
    for (TTaskForce* entry = orderQueueHead; entry != nullptr; entry = entry->nextForce) {
      if (entry->shipOrders != 1)
        continue;
      if (entry->defeated != 0)
        continue;
      for (TTaskForce* other = orderQueueHead; other != nullptr; other = other->nextForce) {
        if (!g_pDiplomacyTurnStateManager->IsNationPairRelationTurnStampOutOfDate(other->nation,
                                                                                  entry->nation)) {
          continue;
        }
        if (other->location != entry->location)
          continue;
        if (other->shipOrders != 5)
          continue;

        char proceed;
        if (entry->CountShips() == 0) {
          proceed = 0;
        } else if (other->CountShips() == 0) {
          proceed = 0;
        } else if (entry->shipOrders == 6 || other->shipOrders == 6 || other->shipOrders == 5) {
          proceed = 1;
        } else {
          short threshold =
              static_cast<short>(entry->GetDeciSpeed() + 0x32 - other->GetDeciSpeed());
          int totalChildren = other->CountShips() + entry->CountShips();
          if (totalChildren > 10)
            threshold = static_cast<short>(threshold + (totalChildren - 10));
          proceed = (rand() % 100) < threshold;
        }

        char result = 0;
        if (proceed && entry->ResolveEncounterWith(other)) {
          TTaskForce* unresolvedForce;
          result = entry->BattleWith(other, unresolvedForce);
        }
        if (result != 0)
          return;
        if (entry->defeated != 0)
          break;
      }
    }
  }

  // Pass F: apply type-5/8 execution effects directly.
  {
    for (TTaskForce* entry = orderQueueHead; entry != nullptr; entry = entry->nextForce) {
      if ((entry->shipOrders == 5 || entry->shipOrders == 8) && entry->defeated == 0) {
        entry->CarryOutOrders();
      }
    }
  }

  ProcessNationMapOrderInteractionsAndApplyOutcomes(1);
  ProcessNationMapOrderInteractionsAndApplyOutcomes(2);
  orderQueueHead = orderQueueHead->RemoveStragglers();

  for (TShip* ship = g_pNavyPrimaryOrderListHead; ship != nullptr; ship = ship->next) {
    if (ship->selection == 1) {
      ship->selection = 0;
    }
  }

  g_pActiveMapOrderContext->RefreshMapActionContextNationOverlaysAndOrderRanks();
}

// FUNCTION: IMPERIALISM 0x00557e10
TTaskForce* TNavyMgr::AssignEscorts(short requiredCount, short chancePercent) {
  TTaskForce* entry = orderQueueHead;
  while (entry != nullptr) {
    if (entry->nation == requiredCount && entry->shipOrders == 7) {
      break;
    }
    entry = entry->nextForce;
  }

  if (entry != nullptr) {
    for (TMapOrderChildLinkNode* node = entry->shipList; node != nullptr; node = node->next) {
      TShip* child = static_cast<TShip*>(node->payload);
      unsigned char active;
      if (child->strength < g_NavyOrderResourceDescriptorTable[child->type].stockCap ||
          chancePercent <= rand() % 100) {
        active = 0;
      } else {
        active = 1;
      }
      node->active = active;
    }
  }

  return entry;
}

// FUNCTION: IMPERIALISM 0x00557f10
char TNavyMgr::SelectEligibleMapOrderInteractionForNationAndContext(
    TMapOrderInteractionSelection* outResult, TZone* portZoneContext, short nation,
    short offerAmount) {
  short portOwnerNation = portZoneContext->GetPortZoneOwnerNationCodeFromMissionField48();
  TGreatPower* nationState = g_apNationStates[nation];
  short remainingTradeCapacity =
      static_cast<short>(nationState->tradeCapacity - nationState->diplomacyCounterA2);
  short selectionChance = remainingTradeCapacity == 0
                              ? 0
                              : static_cast<short>((offerAmount * 100) / remainingTradeCapacity);

  TTaskForce* nationEntry = orderQueueHead;
  while (nationEntry != nullptr) {
    if (nationEntry->nation == nation) {
      bool isEscortOrder = nationEntry->shipOrders == 7;
      if (isEscortOrder) {
        break;
      }
    }
    nationEntry = nationEntry->nextForce;
  }
  if (nationEntry != nullptr) {
    for (TMapOrderChildLinkNode* node = nationEntry->shipList; node != nullptr; node = node->next) {
      TShip* child = static_cast<TShip*>(node->payload);
      unsigned char active;
      if (child->strength < g_NavyOrderResourceDescriptorTable[child->type].stockCap ||
          selectionChance <= rand() % 100) {
        active = 0;
      } else {
        active = 1;
      }
      node->active = active;
    }
  }

  for (TTaskForce* entry = orderQueueHead; entry != nullptr; entry = entry->nextForce) {
    if (entry->defeated != 0) {
      continue;
    }
    if (CountMapOrderChildren(entry->shipList) <= 0) {
      continue;
    }

    short shipOrders = static_cast<short>(entry->shipOrders);
    bool contextMatch = shipOrders == 6 && entry->target.asZone == portZoneContext;
    bool activeContextMatch = false;
    if (shipOrders == 3) {
      TZone** slot = portZoneContext->primaryNeighbors.EnsureSlotAllocatedAndReturnPointer(0);
      activeContextMatch = (entry->location == *slot);
    }

    bool relatedToNation = entry->nation != nation &&
                           g_pDiplomacyTurnStateManager->IsNationPairRelationTurnStampOutOfDate(
                               entry->nation, nation) != 0;
    bool relatedToPortOwner = portOwnerNation >= 7 && entry->shipOrders == 6 &&
                              g_pDiplomacyTurnStateManager->IsNationPairRelationTurnStampOutOfDate(
                                  entry->nation, portOwnerNation) != 0;

    if (!(contextMatch || activeContextMatch) || !(relatedToNation || relatedToPortOwner)) {
      continue;
    }

    int thresholdBase = shipOrders == 6 ? 0x32 : 0x14;
    short activeChildRating =
        static_cast<short>(CalculateActiveChildAverageDescriptorWeightX10(entry->shipList));
    TCity* nationCity = nationState != nullptr ? nationState->city : nullptr;
    short cityWeight1 =
        static_cast<short>(nationCity->ComputeAverageWeightWord1TimesTenFromResourceCounts());
    short cityWeight0 =
        static_cast<short>(nationCity->ComputeAverageWeightWord0TimesTenFromResourceCounts());
    short offerPerCityWeight = cityWeight0;
    if (offerPerCityWeight > 0) {
      offerPerCityWeight = static_cast<short>(offerAmount / offerPerCityWeight);
    }

    int activeNationChildren = 0;
    if (nationEntry != nullptr) {
      for (TMapOrderChildLinkNode* node = nationEntry->shipList; node != nullptr;
           node = node->next) {
        if (node->active != 0) {
          ++activeNationChildren;
        }
      }
    }
    int entryChildren = CountMapOrderChildren(entry->shipList);
    int threshold = entryChildren + activeNationChildren + thresholdBase +
                    (activeChildRating - cityWeight1) + offerPerCityWeight - 10;
    if (rand() % 100 >= static_cast<short>(threshold)) {
      continue;
    }

    bool eligible;
    bool nationEntryUnavailable = nationEntry == nullptr;
    if (!nationEntryUnavailable) {
      int queuedShipCount =
          nationEntry->shipCountsByToolbarSlot[0] + nationEntry->shipCountsByToolbarSlot[1] +
          nationEntry->shipCountsByToolbarSlot[2] + nationEntry->shipCountsByToolbarSlot[3];
      nationEntryUnavailable = queuedShipCount == 0;
    }
    if (!nationEntryUnavailable) {
      TMapOrderChildLinkNode* activeNode = nationEntry->shipList;
      while (activeNode != nullptr && activeNode->active == 0) {
        activeNode = activeNode->next;
      }
      nationEntryUnavailable = activeNode == nullptr;
    }

    if (nationEntryUnavailable) {
      eligible = true;
    } else if (g_pDiplomacyTurnStateManager->IsNationPairRelationTurnStampOutOfDate(
                   nation, entry->nation) != 0) {
      int candidateStrength = 0;
      for (TMapOrderChildLinkNode* candidateNode = entry->shipList; candidateNode != nullptr;
           candidateNode = candidateNode->next) {
        candidateStrength += static_cast<TShip*>(candidateNode->payload)->GetBattleStrengthRating();
      }
      int orderTypePriority[3] = {200, 100, 50};
      short nationStrength = static_cast<short>(nationEntry->GetBattleStrengthRating());
      if (static_cast<short>(candidateStrength) * 100 <
          orderTypePriority[entry->aggression] * nationStrength) {
        eligible = false;
        MapOrderBattleSnapshot snapshot;
        snapshot.childCount[0] = 0;
        snapshot.childCount[1] = 0;
        snapshot.childRecords[0] = nullptr;
        snapshot.childRecords[1] = nullptr;
        snapshot.actionType04 = 1;
        snapshot.targetContext08.object = entry->location;
        snapshot.reservedByte03 = 0;
        snapshot.participantIndex02 = 1;
        BuildMapOrderBattleSideSnapshot(&snapshot, 0, entry);
        BuildMapOrderBattleSideSnapshot(&snapshot, 1, nationEntry);
        RefreshMapOrderBattleSideSnapshot(&snapshot, 0, entry);
        RefreshMapOrderBattleSideSnapshot(&snapshot, 1, nationEntry);
        g_pMapContextActionManager->AppendMapContextActionRecordAndResetWorkingFields(&snapshot, 0);
      } else {
        TTaskForce* survivingEntry;
        if (CountMapOrderChildren(entry->shipList) != 0 && nationEntry->CountShips() != 0 &&
            (g_pSimMgr->preferenceValues[1] == 0 ||
             (g_pSimMgr->GetActiveNationId() != entry->nation &&
              g_pSimMgr->GetActiveNationId() != nationEntry->nation))) {
          g_pNavyOrderManager->ResolveStrategicBattle(entry, nationEntry);
          survivingEntry = nullptr;
        }
        // The retail body only initializes this temporary after resolving a battle;
        // the untouched path compares the existing stack slot verbatim.
        eligible = survivingEntry == entry;
      }
    } else {
      int nationStrength = 0;
      for (TMapOrderChildLinkNode* nationStrengthNode = nationEntry->shipList;
           nationStrengthNode != nullptr; nationStrengthNode = nationStrengthNode->next) {
        nationStrength += CalculateMapOrderInteractionShipStrength(
            static_cast<TShip*>(nationStrengthNode->payload));
      }
      int candidateStrength = 0;
      for (TMapOrderChildLinkNode* candidateStrengthNode = entry->shipList;
           candidateStrengthNode != nullptr; candidateStrengthNode = candidateStrengthNode->next) {
        candidateStrength += CalculateMapOrderInteractionShipStrength(
            static_cast<TShip*>(candidateStrengthNode->payload));
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
    if (g_pDiplomacyTurnStateManager->IsNationPairRelationTurnStampOutOfDate(nation,
                                                                             entry->nation) == 0) {
      return 1;
    }
    short roll = static_cast<short>(static_cast<int>(rand()) % 100);
    short bias = static_cast<short>(entryChildren + 10);
    if (roll >= bias) {
      if (roll < bias * 2) {
        outResult->directionFlags |= 1;
      }
    } else {
      outResult->directionFlags |= 2;
    }
    return 1;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x00558960
void TNavyMgr::ProcessNationMapOrderInteractionsAndApplyOutcomes(short mode) {
  for (short nation = 0; nation <= 6; ++nation) {
    if (g_apTerrainTypeDescriptorTable[nation] == nullptr) {
      continue;
    }
    TGreatPower* state = g_apNationStates[nation];
    TCity* city = (state != nullptr) ? state->city : nullptr;
    if (city == nullptr) {
      continue;
    }
    for (short slot = 0; slot < 0x11; ++slot) {
      short entryCount = state->GetTrackedSlotEntryCountLow(slot);
      for (short ordinal = 1; ordinal <= entryCount; ++ordinal) {
        short entryKind = 0;
        short entryValue = 0;
        short entryTargetNation = 0;
        int entryPayload = 0;
        state->ReadTrackedSlotEntryFields(slot, ordinal, &entryKind, &entryValue,
                                          &entryTargetNation, &entryPayload);
        if (entryValue == 0) {
          continue;
        }

        short offerNation = (entryKind == 1) ? nation : entryTargetNation;
        short acceptNation = (entryKind == 1) ? entryTargetNation : nation;

        short contextNation = (mode == 1) ? nation : entryTargetNation;
        TZone* portZoneContext =
            g_pActiveMapOrderContext->FindFirstPortZoneContextByNation(contextNation);
        TMapOrderInteractionSelection selection;
        char eligible = SelectEligibleMapOrderInteractionForNationAndContext(
            &selection, portZoneContext, nation, entryValue);
        if (eligible == 0) {
          continue;
        }

        MapOrderBattleSnapshot snapshot;
        snapshot.childCount[0] = 0;
        snapshot.childCount[1] = 0;
        snapshot.childRecords[0] = nullptr;
        snapshot.childRecords[1] = nullptr;
        snapshot.nationIds[0] = static_cast<unsigned char>(selection.offerNationCode);
        snapshot.nationIds[1] = static_cast<unsigned char>(nation);
        snapshot.participantIndex02 = 0;
        snapshot.reservedByte03 = 0;
        snapshot.actionType04 = 2;
        snapshot.targetContext08.object = selection.selectedEntry->location;

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
        g_pSimMgr->GetStringPrelude(slot, &commodityName);
        CString interactionTemplate;
        g_pSimMgr->GetString(0x273c, 0, &interactionTemplate);
        CString interactionText;
        scanBracketExpressions(
            g_pSimMgr, &interactionText, static_cast<LPCSTR>(interactionTemplate),
            static_cast<LPCSTR>(entryValueText), static_cast<LPCSTR>(commodityName),
            static_cast<LPCSTR>(labelScratch));
        CopyCStringIntoFixedBuffer(snapshot.overlayLabel[1].data, 0xff,
                                   static_cast<LPCSTR>(interactionText));

        char modeIsOffer = (mode == 1);
        char matchesOfferPass = modeIsOffer && entryKind == 1;
        char matchesAcceptPass = mode == 2 && entryKind == 0;
        char passMismatch = !matchesOfferPass && !matchesAcceptPass;
        char movedTrackedCounter = 0;

        unsigned int directionFlags = selection.directionFlags;
        if ((directionFlags & 3) == 0 && matchesAcceptPass) {
          continue;
        }

        short transferredWeight = 0;
        int strengthDelta = entryValue;
        if ((directionFlags & 3) != 0) {
          short drawnCounts[0x0e] = {0};
          transferredWeight = static_cast<short>(
              city->AllocateRandomResourceCountsWithinWeightBudget(entryValue, drawnCounts));
          if (transferredWeight != 0) {
            strengthDelta = static_cast<int>(transferredWeight) * 3 + entryValue;

            if (passMismatch) {
              if (offerNation < 7) {
                g_apNationStates[offerNation]->AddShortDeltaToNationCounterAtOffset198(
                    slot, static_cast<short>(-transferredWeight));
              }
              movedTrackedCounter = 1;
            }

            short detailCount = static_cast<short>(transferredWeight + 1);
            if (passMismatch && (directionFlags & 2) != 0) {
              detailCount = static_cast<short>(detailCount + 1);
            }
            snapshot.childCount[1] = detailCount;
            snapshot.childRecords[1] = new MapOrderBattleSideChildRecord[detailCount];
            for (int detailIndex = 0; detailIndex < detailCount; ++detailIndex) {
              snapshot.childRecords[1][detailIndex].nameBuffer[0] = 0;
            }

            CString resourceList;
            int reportIndex = 1;
            for (int resourceType = 0; resourceType < 0x0e; ++resourceType) {
              short resourceCount = drawnCounts[resourceType];
              if (resourceCount == 0) {
                continue;
              }
              if (resourceList != g_szEmptyString) {
                resourceList += g_szListSeparator_00695760;
              }
              CString resourceLabel;
              FormatLocalizedCommodityCountLabelByIndex(
                  &resourceLabel, static_cast<unsigned int>(resourceType), resourceCount);
              resourceList += resourceLabel;

              for (int unit = 0; unit < resourceCount; ++unit) {
                MapOrderBattleSideChildRecord& detail = snapshot.childRecords[1][reportIndex];
                detail.resourceType = static_cast<short>(resourceType);
                detail.stockOrRequired = static_cast<short>((directionFlags >> 1) & 1);
                detail.detailIdentity.categoryTag = 0x6d657263; // 'merc'
                ++reportIndex;
              }
            }

            CString resourceActionText;
            g_pSimMgr->GetString(0x273c, static_cast<short>(2 - ((directionFlags >> 1) & 1)),
                                 &resourceActionText);
            CString resourceSummary = s_szLineBreak_00695880 + resourceActionText +
                                      s_szSpaceSeparator_00695794 + resourceList;
            AppendCStringIntoFixedBuffer(snapshot.overlayLabel[1].data, 0xff,
                                         static_cast<LPCSTR>(resourceSummary));

            if ((directionFlags & 2) != 0) {
              if (passMismatch) {
                CString transferredText;
                transferredText.Format(g_szDecimalFormat, static_cast<int>(transferredWeight));
                CString transferredCommodityName;
                g_pSimMgr->GetStringPrelude(slot, &transferredCommodityName);
                CString transferredActionText;
                g_pSimMgr->GetString(0x273c, 3, &transferredActionText);
                CString transferredSummary = s_szLineBreak_00695880 + transferredActionText +
                                             s_szSpaceSeparator_00695794 + transferredText +
                                             s_szSpaceSeparator_00695794 + transferredCommodityName;
                AppendCStringIntoFixedBuffer(snapshot.overlayLabel[1].data, 0xff,
                                             static_cast<LPCSTR>(transferredSummary));

                MapOrderBattleSideChildRecord& item = snapshot.childRecords[1][reportIndex];
                item.resourceType = slot;
                item.stockOrRequired = transferredWeight;
                item.detailIdentity.categoryTag = 0x6974656d; // 'item'
              }

              for (int resourceType2 = 0; resourceType2 < 0x0e; ++resourceType2) {
                if (drawnCounts[resourceType2] != 0) {
                  g_apNationStates[selection.offerNationCode]
                      ->city->orderCountByType5c[resourceType2] =
                      static_cast<short>(g_apNationStates[selection.offerNationCode]
                                             ->city->orderCountByType5c[resourceType2] +
                                         drawnCounts[resourceType2]);
                }
              }
              if (passMismatch) {
                g_apNationStates[selection.offerNationCode]
                    ->AddShortDeltaToNationCounterAtOffset198(slot, transferredWeight);
              }
            }
          }
        }

        if (snapshot.childCount[1] < 1) {
          snapshot.childCount[1] = 1;
          snapshot.childRecords[1] = new MapOrderBattleSideChildRecord[1];
          snapshot.childRecords[1][0].nameBuffer[0] = 0;
        }

        MapOrderBattleSideChildRecord& interaction = snapshot.childRecords[1][0];
        interaction.resourceType = slot;
        interaction.stockOrRequired = entryValue;
        interaction.strengthBucket = entryTargetNation;
        interaction.detailIdentity.categoryTag = 0x72757074; // 'rupt'

        int selectedChildCount = CountMapOrderChildren(selection.selectedEntry->shipList);
        if (selection.selectedEntry->flagship != nullptr &&
            selection.selectedEntry->flagship->admiral != nullptr) {
          TAdmiral* admiral = selection.selectedEntry->flagship->admiral;
          admiral->experiencePoints = static_cast<short>(admiral->experiencePoints + strengthDelta);
          if (admiral->experiencePoints >= 500) {
            admiral->experiencePoints = 499;
          }
        }
        if (selectedChildCount > 0) {
          short childStrengthDelta = static_cast<short>((strengthDelta * 3) / selectedChildCount);
          for (TMapOrderChildLinkNode* childNode = selection.selectedEntry->shipList;
               childNode != nullptr; childNode = childNode->next) {
            TShip* ship = static_cast<TShip*>(childNode->payload);
            ship->experience = static_cast<short>(ship->experience + childStrengthDelta);
            if (ship->experience >= 500) {
              ship->experience = 499;
            }
          }
        }

        if (passMismatch && !movedTrackedCounter) {
          modeIsOffer = 1;
          matchesOfferPass = 1;
        }

        snapshot.childCount[0] =
            static_cast<short>(CountMapOrderChildren(selection.selectedEntry->shipList));
        if (snapshot.childCount[0] > 0) {
          snapshot.childRecords[0] = new MapOrderBattleSideChildRecord[snapshot.childCount[0]];
          for (int childIndex = 0; childIndex < snapshot.childCount[0]; ++childIndex) {
            snapshot.childRecords[0][childIndex].nameBuffer[0] = 0;
          }
        }
        int selectedChildIndex = 0;
        for (TMapOrderChildLinkNode* selectedNode = selection.selectedEntry->shipList;
             selectedNode != nullptr; selectedNode = selectedNode->next) {
          TShip* selectedShip = static_cast<TShip*>(selectedNode->payload);
          MapOrderBattleSideChildRecord& detail = snapshot.childRecords[0][selectedChildIndex];
          detail.resourceType = selectedShip->type;
          detail.stockOrRequired = selectedShip->strength;
          CopyCStringIntoFixedBuffer(detail.nameBuffer, 0x20,
                                     static_cast<LPCSTR>(selectedShip->name));
          detail.strengthBucket = static_cast<short>(selectedShip->experience / 100);
          detail.detailIdentity.categoryTag = 0x6e617679; // 'navy'
          ++selectedChildIndex;
        }

        g_pMapContextActionManager->AppendMapContextActionRecordAndResetWorkingFields(&snapshot, 0);

        if (modeIsOffer) {
          int treasuryDelta = static_cast<int>(entryValue) * entryPayload;
          g_apTerrainTypeDescriptorTable[acceptNation]->AddToTreasury(-treasuryDelta);
          g_apTerrainTypeDescriptorTable[offerNation]->AddToTreasury(treasuryDelta);
          if (offerNation < 7) {
            g_apNationStates[offerNation]->budgetPoolDelta -= treasuryDelta;
          }
          if (acceptNation < 7) {
            g_apNationStates[acceptNation]->budgetPoolBase -= treasuryDelta;
          }
        }

        if (matchesOfferPass && acceptNation < 7) {
          g_apNationStates[acceptNation]->AddShortDeltaToNationCounterAtOffset198(slot, entryValue);
        }

        if (acceptNation < 7) {
          if (movedTrackedCounter) {
            g_apNationStates[acceptNation]->AssignPayloadToTrackedSlotEntryMatchingField2(
                slot, offerNation, -123456);
          } else if (matchesOfferPass) {
            g_apNationStates[acceptNation]->AssignPayloadToTrackedSlotEntryMatchingField2(
                slot, offerNation, -123457);
          }
        }
        if (offerNation < 7) {
          if (movedTrackedCounter) {
            g_apNationStates[offerNation]->AssignPayloadToTrackedSlotEntryMatchingField2(
                slot, acceptNation, -123456);
          } else if (matchesOfferPass) {
            g_apNationStates[offerNation]->AssignPayloadToTrackedSlotEntryMatchingField2(
                slot, acceptNation, -123459);
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
  if (entry == nullptr) {
    return g_awMapContextActionLabelTokenByCommand[0];
  }

  if (g_pGlobalMapState->terrainStateTable[nTileIndex].terrainType00 == 5) {
    TZone* context = g_pActiveMapOrderContext->GetLinkedZoneForSeaTile(nTileIndex);
    bool canResolve = false;
    if (context != nullptr && entry->IsEmpty() == 0) {
      bool hasActiveChild = false;
      for (TMapOrderChildLinkNode* node = entry->shipList; node != nullptr; node = node->next) {
        if (node->active != 0) {
          hasActiveChild = true;
          break;
        }
      }
      if (hasActiveChild) {
        unsigned short minimumWeight = 10000;
        for (TMapOrderChildLinkNode* node = entry->shipList; node != nullptr; node = node->next) {
          if (node->active != 0) {
            TShip* ship = static_cast<TShip*>(node->payload);
            short weight = g_NavyOrderResourceDescriptorTable[ship->type].descriptorWeight;
            if (weight < static_cast<short>(minimumWeight)) {
              minimumWeight = static_cast<unsigned short>(weight);
            }
          }
        }
        short threshold = minimumWeight != 10000 ? static_cast<short>(minimumWeight) : 0;
        short distance = entry->location->GetCachedMapActionContextDistanceOrRecompute(context);
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
    if (province != nullptr) {
      short* queuedCounts = entry->shipCountsByToolbarSlot;
      if (queuedCounts[0] + queuedCounts[1] + queuedCounts[2] + queuedCounts[3] != 0) {
        for (TMapOrderChildLinkNode* node = entry->shipList; node != nullptr; node = node->next) {
          if (node->active != 0) {
            canResolve = province->navyOrderReachableA0 != 0;
            break;
          }
        }
      }
    }
    if (canResolve) {
      char relationOutOfDate = g_pDiplomacyTurnStateManager->IsNationPairRelationTurnStampOutOfDate(
          entry->nation, province->ownerNationCode00);
      return g_awMapContextActionLabelTokenByCommand[relationOutOfDate != 0 ? 16 : 1];
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
  TMapUberPicture* mapUberPicture = g_pUiRuntimeContext->mapUberPictureF0;
  switch (actionCode) {
  case 9: {
    TZone* zone = g_pActiveMapOrderContext->GetLinkedZoneForSeaTile(nTileIndex);
    mapUberPicture->SetActiveMapOrderEntry(zone);
    return true;
  }
  case 2:
  case 3:
  case 4:
  case 5:
  case 6:
  case 7:
  case 8: {
    TZone* zone = g_pActiveMapOrderContext->GetLinkedZoneForSeaTile(nTileIndex);
    mapUberPicture->NavalIntelligenceDialog(zone, static_cast<short>(actionCode - 2),
                                            g_pCachedMapActionContext);
    return true;
  }
  case 11: {
    TTaskForce* entry = this->orderQueueHead;
    while (entry != 0 && entry->ingotTileIndex != nTileIndex) {
      entry = entry->nextForce;
    }
    mapUberPicture->InspectTaskForceDialog(entry);
    return true;
  }
  case 10: {
    g_pUiRuntimeContext->MakeNavyRosterDialog(GetActiveMapOrderEntry());
    return true;
  }
  default:
    return false;
  }
}

// Queues a map order for a clicked tile when immediate context handling does not consume
// the click: resolves a command id (action-context path for sea tiles, province-context
// path otherwise) off the active map-order entry, then dispatches by command id, setting
// the entry's order kind + target context and running the rebuild/queue/finalize pipeline.
// FUNCTION: IMPERIALISM 0x0055a160
int TNavyMgr::DoTileClick(short nTileIndex, int nInputFlags) {
  // A context-only action consumes the click without any queue mutation.
  if (SelectionClick(nTileIndex, nInputFlags) != 0) {
    return 0;
  }
  TTaskForce* entry = GetActiveMapOrderEntry();
  int commandId;
  if (entry == nullptr) {
    commandId = 0;
  } else if (g_pGlobalMapState->terrainStateTable[nTileIndex].terrainType00 == 5) {
    TZone* ctx = g_pActiveMapOrderContext->GetLinkedZoneForSeaTile(nTileIndex);
    bool queueable;
    if (ctx == nullptr) {
      queueable = false;
    } else if (entry->NoSelection() == 0) {
      short dist = entry->location->GetCachedMapActionContextDistanceOrRecompute(ctx);
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
    g_pUiRuntimeContext->MakeNavyRosterDialog(entry);
    break;
  case 0x0c:
    entry->shipOrders = 3;
    entry->FreeAvailables();
    if (g_pNavyOrderManager->CommitForce(entry)) {
      g_pActiveMapOrderContext->FinalizeQueuedMapOrderEntry(entry);
      return 1;
    }
    break;
  case 0x0d: {
    TZone* ctx = g_pActiveMapOrderContext->GetLinkedZoneForSeaTile(nTileIndex);
    entry->shipOrders = 1;
    entry->target.asZone = ctx;
    entry->FreeAvailables();
    if (g_pNavyOrderManager->CommitForce(entry)) {
      g_pActiveMapOrderContext->FinalizeQueuedMapOrderEntry(entry);
      return 1;
    }
    break;
  }
  case 0x0e: {
    TZone* ctx = g_pActiveMapOrderContext->GetLinkedZoneForSeaTile(nTileIndex);
    entry->shipOrders = 6;
    entry->target.asZone = ctx;
    entry->FreeAvailables();
    if (g_pNavyOrderManager->CommitForce(entry)) {
      g_pActiveMapOrderContext->FinalizeQueuedMapOrderEntry(entry);
      return 1;
    }
    break;
  }
  case 0x0f: {
    TZone* ctx = g_pActiveMapOrderContext->GetLinkedZoneForSeaTile(nTileIndex);
    entry->shipOrders = 1;
    entry->target.asZone = ctx;
    entry->FreeAvailables();
    bool alreadyQueued = false;
    for (TTaskForce* node = g_pNavyOrderManager->orderQueueHead; node != nullptr;
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
      entry->LinkTo(nullptr, g_pNavyOrderManager->orderQueueHead);
      g_pNavyOrderManager->orderQueueHead = entry;
      committed = true;
    }
    if (committed) {
      g_pActiveMapOrderContext->FinalizeQueuedMapOrderEntry(entry);
      return 1;
    }
    break;
  }
  case 0x10:
    entry->shipOrders = 5;
    entry->target.asProvince = GetProvinceByTileIndex(nTileIndex);
    entry->FreeAvailables();
    if (g_pNavyOrderManager->CommitForce(entry)) {
      g_pActiveMapOrderContext->FinalizeQueuedMapOrderEntry(entry);
      return 1;
    }
    break;
  default:
    return 0;
  }
  return 1;
}

// FUNCTION: IMPERIALISM 0x0055a780
void TNavyMgr::ResolveStrategicBattle(TTaskForce* leftEntry, TTaskForce* rightEntry) {
  MapOrderBattleSnapshot snapshot;
  snapshot.childCount[0] = 0;
  snapshot.childCount[1] = 0;
  snapshot.childRecords[0] = 0;
  snapshot.childRecords[1] = 0;
  BuildMapOrderBattleSideSnapshot(&snapshot, 0, leftEntry);
  BuildMapOrderBattleSideSnapshot(&snapshot, 1, rightEntry);

  int leftStartCount = CountMapOrderChildren(leftEntry->shipList);
  int rightStartCount = CountMapOrderChildren(rightEntry->shipList);

  int maxTier = 1;
  for (TMapOrderChildLinkNode* node = leftEntry->shipList; node != nullptr; node = node->next) {
    int tier =
        g_NavyOrderResourceDescriptorTable[static_cast<TShip*>(node->payload)->type].priorityTier;
    if (tier > maxTier) {
      maxTier = tier;
    }
  }
  for (TMapOrderChildLinkNode* rightNode = rightEntry->shipList; rightNode != nullptr;
       rightNode = rightNode->next) {
    int tier = g_NavyOrderResourceDescriptorTable[static_cast<TShip*>(rightNode->payload)->type]
                   .priorityTier;
    if (tier > maxTier) {
      maxTier = tier;
    }
  }

  // Per-order-type "convergence tolerance" the winning-tier ratio must clear for that side
  // to be judged to have genuinely won the tier (the real {1.1,0.95,0.8} float table,
  // indexed by the force's eAgro dword at +0x04.
  const float kTierConvergenceThreshold[3] = {1.1f, 0.95f, 0.8f};
  float leftThreshold = kTierConvergenceThreshold[leftEntry->aggression];
  float rightThreshold = kTierConvergenceThreshold[rightEntry->aggression];

  int candidateTier = maxTier;
  bool tierUnreachable = false;

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
      float leftPower = SumMapOrderChildPowerAtOrAboveTier(leftEntry->shipList, tier) *
                        (1.0f + leftBucket * 0.1f);
      float rightPower = SumMapOrderChildPowerAtOrAboveTier(rightEntry->shipList, tier) *
                         (1.0f + rightBucket * 0.1f);
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
    int leftTierAdjust;
    if (bestLeftFavorTier < candidateTier) {
      leftTierAdjust = 0;
    } else if (bestLeftFavorRatio >= leftThreshold || bestLeftFavorTier > candidateTier) {
      leftTierAdjust = 2;
    } else {
      leftTierAdjust = 1;
    }
    int rightTierAdjust;
    if (bestRightFavorTier < candidateTier) {
      rightTierAdjust = 0;
    } else if (bestRightFavorRatio >= rightThreshold || bestRightFavorTier > candidateTier) {
      rightTierAdjust = 2;
    } else {
      rightTierAdjust = 1;
    }

    int leftWeight =
        (leftBucket + 10) * CalculateActiveChildAverageDescriptorWeightX10(leftEntry->shipList);
    int rightWeight =
        (rightBucket + 10) * CalculateActiveChildAverageDescriptorWeightX10(rightEntry->shipList);
    int totalWeight = leftWeight + rightWeight;

    if (static_cast<int>(rand()) % totalWeight < leftWeight) {
      if (leftTierAdjust == 0) {
        --candidateTier;
      }
      if (leftTierAdjust == 2) {
        ++candidateTier;
      }
    }
    if (static_cast<int>(rand()) % totalWeight < rightWeight) {
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
      tierUnreachable = true;
      break;
    }

    int leftEligible = CountMapOrderChildrenAtOrAboveTier(leftEntry->shipList, candidateTier);
    int rightEligible = CountMapOrderChildrenAtOrAboveTier(rightEntry->shipList, candidateTier);
    int leftCurrentCount = CountMapOrderChildren(leftEntry->shipList);
    int rightCurrentCount = CountMapOrderChildren(rightEntry->shipList);

    int leftAttritionTarget = rightEligible < leftCurrentCount ? rightEligible : leftCurrentCount;
    ApplyMapOrderConflictAttrition(leftEntry->shipList, leftCurrentCount, leftAttritionTarget,
                                   bestLeftFavorRatio);
    int rightAttritionTarget = leftEligible < rightCurrentCount ? leftEligible : rightCurrentCount;
    ApplyMapOrderConflictAttrition(rightEntry->shipList, rightCurrentCount, rightAttritionTarget,
                                   bestRightFavorRatio);

    leftEntry->shipList = PruneMapOrderConflictHeadAndTail(leftEntry->shipList);
    leftEntry->ElectFlagship();
    bool leftEmpty = leftEntry->shipList == nullptr;

    rightEntry->shipList = PruneMapOrderConflictHeadAndTail(rightEntry->shipList);
    rightEntry->ElectFlagship();
    bool rightEmpty = rightEntry->shipList == nullptr;

    if (leftEmpty || rightEmpty) {
      break;
    }
  }

  bool leftEliminated = leftEntry->shipList == nullptr;
  bool rightEliminated = rightEntry->shipList == nullptr;
  if (!tierUnreachable && (leftEliminated != rightEliminated)) {
    TTaskForce* loser = leftEliminated ? leftEntry : rightEntry;
    TTaskForce* winner = leftEliminated ? rightEntry : leftEntry;
    int loserStart = leftEliminated ? leftStartCount : rightStartCount;
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
      for (TMapOrderChildLinkNode* node = winner->shipList; node != nullptr; node = node->next) {
        static_cast<TShip*>(node->payload)->Victory(static_cast<short>((bump * 3) / winnerCount));
      }
    }
    loser->defeated = 1;
  }

  RefreshMapOrderBattleSideSnapshot(&snapshot, 0,
                                    leftEntry->shipList != nullptr ? leftEntry : nullptr);
  RefreshMapOrderBattleSideSnapshot(&snapshot, 1,
                                    rightEntry->shipList != nullptr ? rightEntry : nullptr);
  g_pMapContextActionManager->AppendMapContextActionRecordAndResetWorkingFields(&snapshot, 0);
}
