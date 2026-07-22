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
// reattributed TryQueueMapOrderFromTileAction below.
TGlobalMapCityScoreRecord* __stdcall GetProvinceByTileIndex(short nTileIndex);

// Resolves a raw TGlobalMapCityScoreRecord* back into its index in
// g_pGlobalMapState's cityScoreTable. Real __fastcall: the single arg arrives in ecx
// and no original callsite pushes anything.
// FUNCTION: IMPERIALISM 0x0050e2c0
int __fastcall GetCityIndexFromCityStatePointer(TGlobalMapCityScoreRecord* cityState) {
  return static_cast<int>(cityState - g_pGlobalMapState->cityScoreTable);
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

// Sum, over childOrderList entries whose resource-type priorityTier is >= minTier, of
// (child->field30/100 + resolveWeight*10 + 5)/10 -- the per-child "combat power"
// term ResolveMapOrderPairConflictStep's tier-scoring loop accumulates as a float.
static inline float SumMapOrderChildPowerAtOrAboveTier(TMapOrderChildLinkNode* head, int minTier) {
  float total = 0.0f;
  for (TMapOrderChildLinkNode* node = head; node != nullptr; node = node->next) {
    TShip* child = static_cast<TShip*>(node->payload);
    const TNavyOrderResourceDescriptor& descriptor =
        g_NavyOrderResourceDescriptorTable[child->resourceType04];
    if (descriptor.priorityTier < minTier) {
      continue;
    }
    int power = (child->field30 / 100 + descriptor.resolveWeight * 10 + 5) / 10;
    total += static_cast<float>(power);
  }
  return total;
}

// Count of childOrderList entries whose resource-type priorityTier is >= minTier.
static inline int CountMapOrderChildrenAtOrAboveTier(TMapOrderChildLinkNode* head, int minTier) {
  int count = 0;
  for (TMapOrderChildLinkNode* node = head; node != nullptr; node = node->next) {
    if (g_NavyOrderResourceDescriptorTable[static_cast<TShip*>(node->payload)->resourceType04]
            .priorityTier >= minTier) {
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
      sum += g_NavyOrderResourceDescriptorTable[static_cast<TShip*>(node->payload)->resourceType04]
                 .descriptorWeight;
      ++count;
    }
  }
  if (count == 0) {
    return 0;
  }
  return (sum * 10) / count;
}

// Randomly applies a resource-weighted attrition roll (0x55ae70/0x55af36) to up to
// `target` of `head`'s children: for each candidate node, rolls
// rand()%currentCount < target to select it, restarting at the head until exactly
// `target` children have been selected, then reduces its required_count by
// 0.5 + taskForceWeight[child->resourceType04] * ((rand()%100+rand()%100+100) * 0.005) *
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
        float delta =
            0.5f + g_NavyOrderResourceDescriptorTable[child->resourceType04].taskForceWeight *
                       (roll * 0.005f) * favorRatio * -0.01f;
        child->stockLevel1c = static_cast<short>(child->stockLevel1c - static_cast<short>(delta));
      }
    }
  } while (selected < target);
}

// Removes a depleted (required_count < 1) list head and prunes any other depleted entries
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
  if (child->stockLevel1c < 1) {
    child->SetOwnerOrderEntryAndCacheType(nullptr);
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
  snapshot->nationIds[side] = static_cast<unsigned char>(entry->required_count);

  CString terrainLabel;
  g_apTerrainTypeDescriptorTable[entry->required_count]->FormatOverlayTerrainLabelText(
      &terrainLabel);
  CopyCStringIntoFixedBuffer(snapshot->nameBuffer[side].data, 0x20,
                             static_cast<LPCSTR>(terrainLabel));

  CString overlayLabel;
  entry->BuildTaskForceSelectionOverlayLabelText(&overlayLabel);
  CopyCStringIntoFixedBuffer(snapshot->overlayLabel[side].data, 0xff,
                             static_cast<LPCSTR>(overlayLabel));

  short childCount = static_cast<short>(entry->GetMapOrderEntryChildCount());
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
  for (TMapOrderChildLinkNode* node = entry->childOrderList; node != nullptr; node = node->next) {
    // These children are TShip primary-order nodes (not nested TTaskForce entries --
    // confirmed via the CString read at +0x18, which only lines up with
    // TShip::displayName18; TTaskForce's own +0x18 is contextAnchor, an int).
    TShip* child = static_cast<TShip*>(node->payload);
    MapOrderBattleSideChildRecord& rec = records[idx];
    rec.resourceType = child->resourceType04;
    rec.stockOrRequired = child->stockLevel1c;
    CopyCStringIntoFixedBuffer(rec.nameBuffer, 0x20, static_cast<LPCSTR>(child->displayName18));
    rec.detailIdentity.sourceObject = child;
    rec.strengthBucket = static_cast<short>(child->field30 / 100);
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
    bool stillPresent = entry != nullptr && entry->childOrderList->FindNodeMatching(
                                                reinterpret_cast<TTaskForce*>(child)) != nullptr;
    if (stillPresent) {
      rec.stockOrRequired = child->stockLevel1c;
      rec.strengthBucket = static_cast<short>(child->field30 / 100);
    } else {
      rec.stockOrRequired = 0;
    }
    // Finalize the working pointer slot into the report-row category consumed by
    // TBatRepDetLine::InstallViews.
    rec.detailIdentity.categoryTag = 0x6e617679; // 'navy'
  }

  if (entry != nullptr && entry->attachment == 5) {
    int cityIndex = GetCityIndexFromCityStatePointer(entry->owner.asCityTarget);
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
TNavyMgr::TNavyMgr() : orderListHead04(0), field08(-1), field0c(nullptr) {}

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
      if (*reinterpret_cast<int*>(&mj->calculateWeight) >
          *reinterpret_cast<int*>(&mi->calculateWeight)) {
        short t = g_NavyMissionOrderRanking[i];
        g_NavyMissionOrderRanking[i] = g_NavyMissionOrderRanking[j];
        g_NavyMissionOrderRanking[j] = t;
      }
      TNavyOrderResourceDescriptor* ri =
          &g_NavyOrderResourceDescriptorTable[g_NavyResolveOrderRanking[i]];
      TNavyOrderResourceDescriptor* rj =
          &g_NavyOrderResourceDescriptorTable[g_NavyResolveOrderRanking[j]];
      if (*reinterpret_cast<int*>(&rj->resolveWeight) >
          *reinterpret_cast<int*>(&ri->resolveWeight)) {
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
  SerializeNavyOrderListsByNation(stream, -1);
}

// FUNCTION: IMPERIALISM 0x005568f0
void TNavyMgr::SerializeNavyOrderListsByNation(TStream* stream, short nationFilter) {
  int matchCount = 0;
  TShip* tail = g_pNavyPrimaryOrderListHead;
  if (tail != 0) {
    for (TShip* older = tail->nextOlder24; older != 0; older = older->nextOlder24) {
      tail = older;
    }
  }
  for (TShip* node = tail; node != 0; node = node->prevNewer28) {
    if (nationFilter == -1 || nationFilter == node->ownerNationSlot14) {
      ++matchCount;
    }
  }
  stream->WriteBytesSlot78(&matchCount, 2);
  tail = g_pNavyPrimaryOrderListHead;
  if (tail != 0) {
    for (TShip* older2 = tail->nextOlder24; older2 != 0; older2 = older2->nextOlder24) {
      tail = older2;
    }
  }
  for (TShip* writeNode = tail; writeNode != 0; writeNode = writeNode->prevNewer28) {
    if (nationFilter == -1 || nationFilter == writeNode->ownerNationSlot14) {
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
  // +0x1c is required_count in TTaskForce.h but every navy-order reader (see
  // RemoveMatchingTaskForceOrders) treats it as the entry's nation slot.
  for (TTaskForce* order = orderListHead04; order != 0; order = order->queue_next) {
    if (nationFilter == -1 || nationFilter == order->required_count) {
      ++matchCount;
    }
  }
  stream->WriteBytesSlot78(&matchCount, 2);
  for (TTaskForce* order2 = orderListHead04; order2 != 0; order2 = order2->queue_next) {
    if (nationFilter == -1 || nationFilter == order2->required_count) {
      order2->WriteTo(stream);
    }
  }
}

// FUNCTION: IMPERIALISM 0x00556aa0
void TNavyMgr::ReadFrom(TStream* stream) {
  TObject::ReadFrom(stream);
  DeserializeNavyOrderListsByNation(stream, -1);
}

static void RemoveMatchingSecondaryOrders(short nationSlot) {
  int* node = reinterpret_cast<int*>(g_pNavySecondaryOrderListHead);
  while (node != 0) {
    int* nextNode = reinterpret_cast<int*>(node[5]);
    if (static_cast<short>(node[1]) == nationSlot) {
      reinterpret_cast<TObject*>(node)->Free();
    }
    node = nextNode;
  }
}

static void RemoveMatchingTaskForceOrders(TNavyMgr* navyManager, short nationSlot) {
  int* node = reinterpret_cast<int*>(navyManager->orderListHead04);
  while (node != 0) {
    int* nextNode = reinterpret_cast<int*>(node[0xb]);
    if (static_cast<short>(node[7]) == nationSlot) {
      reinterpret_cast<TObject*>(node)->Free();
    }
    node = nextNode;
  }
}

// FUNCTION: IMPERIALISM 0x00556ad0
void TNavyMgr::DeserializeNavyOrderListsByNation(TStream* stream, short nationFilter) {
  if (nationFilter == -1) {
    // Full resync: drop every existing entry from all three navy order lists first
    // (each Free() unlinks the head, so the loops drain the chains).
    while (g_pNavyPrimaryOrderListHead != 0) {
      g_pNavyPrimaryOrderListHead->Free();
    }
    while (g_pNavySecondaryOrderListHead != 0) {
      g_pNavySecondaryOrderListHead->Free();
    }
    if (orderListHead04 != 0) {
      orderListHead04->queue_next->DestroyNavyOrderAndChildren();
      orderListHead04->Free();
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
    if (nationFilter != -1 && shipNode->ownerNationSlot14 != nationFilter) {
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

  // orderListHead04 TTaskForce chain.
  stream->ReadBytes(&pendingCount, 2);
  while (static_cast<short>(pendingCount--) != 0) {
    TTaskForce* orderEntry = new TTaskForce();
    if (orderEntry == 0) {
      FailNilPointerWithAssert(s_SourcePathUNavy_006983C8, 0xd37);
    }
    orderEntry->ReadFrom(stream);
    if (nationFilter != -1 && orderEntry->required_count != nationFilter) {
      orderEntry->Free();
    }
    // Open-coded MoveMapOrderEntryToQueueHeadIfValid (0x557080) - the original emits
    // this logic inline here (registers carry across it), not as a call: if the entry
    // is not already queued, free it when it has no children, else unlink it and push
    // it to the queue head.
    TTaskForce* queueHead = orderListHead04;
    TTaskForce* queueCursor = queueHead;
    while (queueCursor != 0) {
      if (queueCursor == orderEntry) {
        break;
      }
      queueCursor = queueCursor->queue_next;
    }
    if (queueCursor == 0) {
      int childLinkCount = 0;
      if (orderEntry != 0) {
        for (TMapOrderChildLinkNode* childCursor = orderEntry->childOrderList; childCursor != 0;
             childCursor = childCursor->next) {
          ++childLinkCount;
        }
      }
      if (static_cast<short>(childLinkCount) <= 0) {
        orderEntry->Free();
      } else {
        if (orderEntry->queue_prev != 0) {
          orderEntry->queue_prev->queue_next = orderEntry->queue_next;
        }
        if (orderEntry->queue_next != 0) {
          orderEntry->queue_next->queue_prev = orderEntry->queue_prev;
        }
        orderEntry->queue_prev = 0;
        orderEntry->queue_next = queueHead;
        if (queueHead != 0) {
          queueHead->queue_prev = orderEntry;
        }
        orderListHead04 = orderEntry;
      }
    }
  }
}

// Mac oracle: TNavyMgr::FreeShipsOf(short).
// FUNCTION: IMPERIALISM 0x00556f60
void TNavyMgr::FreeShipsOf(short nation) {
  while (orderListHead04 != 0) {
    TTaskForce* matching = orderListHead04;
    while (matching != 0 && matching->required_count != nation) {
      matching = matching->queue_next;
    }
    if (matching == 0) {
      break;
    }
    matching->CancelOrders(1);
  }

  for (TShip* ship = g_pNavyPrimaryOrderListHead; ship != 0; ship = ship->nextOlder24) {
    if (ship->ownerNationSlot14 == nation) {
      ship->field34 = 0;
    }
  }
}

// FUNCTION: IMPERIALISM 0x00556fd0
void TNavyMgr::ResetPrimaryOrderActiveFlagsAndClearManagerState() {
  for (TShip* ship = g_pNavyPrimaryOrderListHead; ship != nullptr; ship = ship->nextOlder24) {
    ship->ownerOrderEntry0c = 0;
  }
  if (orderListHead04 != nullptr) {
    orderListHead04->DestroyNavyOrderAndChildren();
  }
  orderListHead04 = nullptr;
  g_pActiveMapOrderContext->EnsureSelectedTaskForceForOrderOwnerAndRefresh(nullptr);
}

// FUNCTION: IMPERIALISM 0x00557040
void TNavyMgr::ClearAllTransientOrders() {
  orderListHead04 = orderListHead04->PruneNavyOrderIfUnserviceableOrNoChildren();
  for (TShip* ship = g_pNavyPrimaryOrderListHead; ship != 0; ship = ship->nextOlder24) {
    if (ship->field34 == 1) {
      ship->field34 = 0;
    }
  }
}

// FUNCTION: IMPERIALISM 0x00557080
bool TNavyMgr::MoveMapOrderEntryToQueueHeadIfValid(TTaskForce* entry) {
  for (TTaskForce* node = orderListHead04; node != nullptr; node = node->queue_next) {
    if (node == entry) {
      return true;
    }
  }

  int childCount = 0;
  if (entry != nullptr) {
    for (TMapOrderChildLinkNode* node = entry->childOrderList; node != nullptr; node = node->next) {
      ++childCount;
    }
  }

  if (childCount <= 0) {
    entry->Free();
    return false;
  }

  if (entry->queue_prev != nullptr) {
    entry->queue_prev->queue_next = entry->queue_next;
  }
  if (entry->queue_next != nullptr) {
    entry->queue_next->queue_prev = entry->queue_prev;
  }
  entry->queue_prev = nullptr;
  entry->queue_next = orderListHead04;
  if (orderListHead04 != nullptr) {
    orderListHead04->queue_prev = entry;
  }
  orderListHead04 = entry;
  return true;
}

// FUNCTION: IMPERIALISM 0x00557170
short TNavyMgr::ComputeAggregateWeightedChildCostForMatchingType5NavyOrders(short nationSlot,
                                                                            void* cityRecordPtr,
                                                                            int filterValue) {
  int total = 0;
  int* node = reinterpret_cast<int*>(orderListHead04);
  while (node != 0) {
    if (static_cast<short>(node[7]) == nationSlot && node[2] == 5 &&
        node[3] == reinterpret_cast<int>(cityRecordPtr) &&
        (filterValue == 0 || node[6] == filterValue)) {
      int sum = 0;
      int* item = reinterpret_cast<int*>(node[4]);
      while (item != 0) {
        TShip* ship = reinterpret_cast<TShip*>(item[0]);
        short contribution = 0;
        if (ship->stockLevel1c > 0) {
          contribution = g_industryActionCostWeightResCode10[ship->resourceType04];
        }
        sum += contribution;
        item = reinterpret_cast<int*>(item[1]);
      }
      total += sum;
    }
    node = reinterpret_cast<int*>(node[0xb]);
  }
  return static_cast<short>(total);
}

// FUNCTION: IMPERIALISM 0x00557210
void TNavyMgr::RemoveOrdersByNationFromPrimarySecondaryAndTaskForceLists(short nationSlot) {
  if (g_pNavyPrimaryOrderListHead != 0) {
    TShip* node = g_pNavyPrimaryOrderListHead;
    for (;;) {
      TShip* cursor = node;
      if (node->ownerNationSlot14 == nationSlot) {
        cursor = node->nextOlder24;
        node->Free();
        node = cursor;
        if (node != 0) {
          continue;
        }
      }
      if (cursor == 0 || (node = cursor->nextOlder24) == 0) {
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
void RevalidateAndRequeueMapOrdersForTurn() {
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
        TMapOrderChildLinkNode* node = entry->childOrderList;
        if (node != 0) {
          do {
            node->active = static_cast<TShip*>(node->payload)->stockLevel1c <
                           g_NavyOrderResourceDescriptorTable[static_cast<TShip*>(node->payload)
                                                                  ->resourceType04]
                               .stockCap;
            node = node->next;
          } while (node != 0);
        }
        entry->attachment = 8;
        entry->RequeueMapOrderEntry();
        entry = zone->CreateTaskForceFromNavyOrdersForNationIfEligible(nation);
      }
      if (entry == 0) {
        continue;
      }
      TMapOrderChildLinkNode* node = entry->childOrderList;
      if (node != 0) {
        do {
          node->active = 1;
          node = node->next;
        } while (node != 0);
      }
      // contextAnchor (+0x18) is the entry's owning map-action context TZone* (see
      // TTaskForce.h); slot 0x54 is TZone::QueryPortZoneCapability.
      if (entry->contextAnchor->QueryPortZoneCapability()) {
        entry->attachment = 7;
        entry->RebuildMapOrderEntryChildren();
        entry->AssertValid();
        if (g_pNavyOrderManager->MoveMapOrderEntryToQueueHeadIfValid(entry)) {
          g_pActiveMapOrderContext->FinalizeQueuedMapOrderEntry(entry);
        }
      } else {
        node = entry->childOrderList;
        entry->attachment = 4;
        entry->activeChildEntry = 0;
        while (node != 0) {
          if (node->active != 0) {
            node = node->next;
          } else {
            static_cast<TShip*>(node->payload)->SetOwnerOrderEntryAndCacheType(0);
            short bucketIndex = static_cast<short>(
                g_NavyOrderResourceDescriptorTable[static_cast<TShip*>(node->payload)
                                                       ->resourceType04]
                    .enabledFlagOrBucketOffset);
            short* bucketCounter = &entry->shipCountsByClass[bucketIndex];
            --*bucketCounter;
            if (node == entry->childOrderList) {
              entry->childOrderList = node->next;
            }
            node = node->DeleteMapOrderChildLinkAndReturnNext();
          }
        }
        entry->activeChildEntry = 0;
        for (node = entry->childOrderList; node != 0; node = node->next) {
          entry->activeChildEntry =
              static_cast<TShip*>(node->payload)
                  ->SelectPreferredMapOrderEntryByPriorityRules(entry->activeChildEntry, 0);
        }
        entry->AssertValid();
        if (g_pNavyOrderManager->MoveMapOrderEntryToQueueHeadIfValid(entry)) {
          g_pActiveMapOrderContext->FinalizeQueuedMapOrderEntry(entry);
        }
      }
    }
    zone = zone->prev18;
  } while (zone != 0);
}

// FUNCTION: IMPERIALISM 0x005577b0
void TNavyMgr::PrepareMapOrdersForExecutionPhase(short phaseId) {
  for (int provinceIndex = 0; provinceIndex < 0x180; ++provinceIndex) {
    TGlobalMapCityScoreRecord* record = &g_pGlobalMapState->cityScoreTable[provinceIndex];
    if (record->exploredByNationMaskA1 != 0) {
      record->exploredByNationMaskA1 = 0;
      if (g_pSimMgr->multiplayerSessionRole == 1) {
        g_pGameFlowState->DispatchCityRedrawInvalidateEvent(static_cast<short>(provinceIndex));
      }
    }
  }

  field08 = phaseId;

  RevalidateAndRequeueMapOrdersForTurn();

  if (orderListHead04 != nullptr) {
    orderListHead04->eliminatedFlag26 = 0;
    orderListHead04->queue_next->ClearMapOrderProcessedFlagsChain();
  }
}

// Per-turn-phase map-order conflict resolver. Six filter/inner-loop passes over
// orderListHead04, each pairing an outer "kind" filter against an inner-loop match,
// then attempting a resolution chain (ShouldAttemptMapOrderPairResolution ->
// TryMarkLosingMapOrderEntryFromForceBalance -> TryResolveMapOrderEntryPairExecution);
// any pairwise resolution that reports a nonzero result ends the whole function
// immediately. Passes A/B/D share that 3-method chain shape; Pass E's "should attempt"
// gate is a separate inline computation (not a call to ShouldAttemptMapOrderPairResolution
// -- both sides go through CalculateMapOrderEntryAverageChildRatingX10 here, unlike that
// method's own manual self-side sum) feeding directly into the 2-method
// TryMarkLosing/TryResolve chain. Passes C/F apply execution effects directly with no
// pairing. Finishes with the two-pass nation-interaction sweep, a queue-head rebuild via
// PruneNavyOrderIfUnserviceableOrNoChildren, a primary TShip list flag-clear pass, and an
// overlay refresh.
// FUNCTION: IMPERIALISM 0x005578a0
void TNavyMgr::ResolveMapOrderChainsForTurnPhase() {
  if (field0c != nullptr) {
    field0c->Free();
    field0c = nullptr;
  }

  // Pass A: 3/4-kind entries vs a matching-context 6-kind entry.
  {
    for (TTaskForce* entry = orderListHead04; entry != nullptr; entry = entry->queue_next) {
      if (!(entry->attachment == 3 || entry->attachment == 4))
        continue;
      if (entry->eliminatedFlag26 != 0)
        continue;
      for (TTaskForce* other = orderListHead04; other != nullptr; other = other->queue_next) {
        if (other->contextAnchor != entry->contextAnchor)
          continue;
        if (!g_pDiplomacyTurnStateManager->IsNationPairRelationTurnStampOutOfDate(
                other->required_count, entry->required_count)) {
          continue;
        }
        if (other->attachment != 6)
          continue;
        char result = 0;
        if (entry->ShouldAttemptMapOrderPairResolution(other) &&
            entry->TryMarkLosingMapOrderEntryFromForceBalance(other)) {
          int resolvedFlag;
          result = entry->TryResolveMapOrderEntryPairExecution(other, &resolvedFlag);
        }
        if (result != 0)
          return;
        if (entry->eliminatedFlag26 != 0)
          break;
      }
    }
  }

  // Pass B: 6-kind entries vs a 1-kind entry sharing owner (via contextAnchor or owner).
  {
    for (TTaskForce* entry = orderListHead04; entry != nullptr; entry = entry->queue_next) {
      if (entry->attachment != 6)
        continue;
      if (entry->eliminatedFlag26 != 0)
        continue;
      for (TTaskForce* other = orderListHead04; other != nullptr; other = other->queue_next) {
        if (!g_pDiplomacyTurnStateManager->IsNationPairRelationTurnStampOutOfDate(
                other->required_count, entry->required_count)) {
          continue;
        }
        bool ownerMatch =
            (other->attachment == 1) &&
            (other->contextAnchor == entry->owner.asZone || other->owner.raw == entry->owner.raw);
        if (!ownerMatch)
          continue;
        char result = 0;
        if (entry->ShouldAttemptMapOrderPairResolution(other) &&
            entry->TryMarkLosingMapOrderEntryFromForceBalance(other)) {
          int resolvedFlag;
          result = entry->TryResolveMapOrderEntryPairExecution(other, &resolvedFlag);
        }
        if (result != 0)
          return;
        if (entry->eliminatedFlag26 != 0)
          break;
      }
    }
  }

  // Pass C: apply type-1 execution effects directly.
  {
    for (TTaskForce* entry = orderListHead04; entry != nullptr; entry = entry->queue_next) {
      if (entry->attachment == 1 && entry->eliminatedFlag26 == 0) {
        entry->ApplyMapOrderTypeExecutionEffects();
      }
    }
  }

  // Pass D: 3/4-kind entries vs a matching-context NON-6-kind entry. Same outer filter
  // as Pass A; the diplomacy/contextAnchor check order is swapped and the inner
  // attachment check is inverted, matching the disassembly's distinct compiled shape.
  {
    for (TTaskForce* entry = orderListHead04; entry != nullptr; entry = entry->queue_next) {
      if (!(entry->attachment == 3 || entry->attachment == 4))
        continue;
      if (entry->eliminatedFlag26 != 0)
        continue;
      for (TTaskForce* other = orderListHead04; other != nullptr; other = other->queue_next) {
        if (!g_pDiplomacyTurnStateManager->IsNationPairRelationTurnStampOutOfDate(
                other->required_count, entry->required_count)) {
          continue;
        }
        if (other->contextAnchor != entry->contextAnchor)
          continue;
        if (other->attachment == 6)
          continue;
        char result = 0;
        if (entry->ShouldAttemptMapOrderPairResolution(other) &&
            entry->TryMarkLosingMapOrderEntryFromForceBalance(other)) {
          int resolvedFlag;
          result = entry->TryResolveMapOrderEntryPairExecution(other, &resolvedFlag);
        }
        if (result != 0)
          return;
        if (entry->eliminatedFlag26 != 0)
          break;
      }
    }
  }

  // Pass E: 1-kind entries vs a matching-context 5-kind entry. The "should attempt" gate
  // is an inline duplicate of ShouldAttemptMapOrderPairResolution's shape (not a call to
  // it), feeding straight into TryMarkLosingMapOrderEntryFromForceBalance (no
  // ShouldAttempt call in this pass's chain).
  {
    for (TTaskForce* entry = orderListHead04; entry != nullptr; entry = entry->queue_next) {
      if (entry->attachment != 1)
        continue;
      if (entry->eliminatedFlag26 != 0)
        continue;
      for (TTaskForce* other = orderListHead04; other != nullptr; other = other->queue_next) {
        if (!g_pDiplomacyTurnStateManager->IsNationPairRelationTurnStampOutOfDate(
                other->required_count, entry->required_count)) {
          continue;
        }
        if (other->contextAnchor != entry->contextAnchor)
          continue;
        if (other->attachment != 5)
          continue;

        char proceed;
        if (entry->GetMapOrderEntryChildCount() == 0) {
          proceed = 0;
        } else if (other->GetMapOrderEntryChildCount() == 0) {
          proceed = 0;
        } else if (entry->attachment == 6 || other->attachment == 6 || other->attachment == 5) {
          proceed = 1;
        } else {
          short threshold =
              static_cast<short>(entry->CalculateMapOrderEntryAverageChildRatingX10() + 0x32 -
                                 other->CalculateMapOrderEntryAverageChildRatingX10());
          int totalChildren =
              other->GetMapOrderEntryChildCount() + entry->GetMapOrderEntryChildCount();
          if (totalChildren > 10)
            threshold = static_cast<short>(threshold + (totalChildren - 10));
          proceed = (rand() % 100) < threshold;
        }

        char result = 0;
        if (proceed && entry->TryMarkLosingMapOrderEntryFromForceBalance(other)) {
          int resolvedFlag;
          result = entry->TryResolveMapOrderEntryPairExecution(other, &resolvedFlag);
        }
        if (result != 0)
          return;
        if (entry->eliminatedFlag26 != 0)
          break;
      }
    }
  }

  // Pass F: apply type-5/8 execution effects directly.
  {
    for (TTaskForce* entry = orderListHead04; entry != nullptr; entry = entry->queue_next) {
      if ((entry->attachment == 5 || entry->attachment == 8) && entry->eliminatedFlag26 == 0) {
        entry->ApplyMapOrderTypeExecutionEffects();
      }
    }
  }

  ProcessNationMapOrderInteractionsAndApplyOutcomes(1);
  ProcessNationMapOrderInteractionsAndApplyOutcomes(2);
  orderListHead04 = orderListHead04->PruneNavyOrderIfUnserviceableOrNoChildren();

  for (TShip* ship = g_pNavyPrimaryOrderListHead; ship != nullptr; ship = ship->nextOlder24) {
    if (ship->field34 == 1) {
      ship->field34 = 0;
    }
  }

  g_pActiveMapOrderContext->RefreshMapActionContextNationOverlaysAndOrderRanks();
}

// FUNCTION: IMPERIALISM 0x00557e10
TTaskForce* TNavyMgr::UpdateType7NavyOrderChildSelectionByChanceThreshold(short requiredCount,
                                                                          short chancePercent) {
  TTaskForce* entry = orderListHead04;
  while (entry != nullptr) {
    if (entry->required_count == requiredCount && entry->attachment == 7) {
      break;
    }
    entry = entry->queue_next;
  }

  if (entry != nullptr) {
    for (TMapOrderChildLinkNode* node = entry->childOrderList; node != nullptr; node = node->next) {
      TShip* child = static_cast<TShip*>(node->payload);
      bool notSelected = child->stockLevel1c <
                             g_NavyOrderResourceDescriptorTable[child->resourceType04].stockCap ||
                         chancePercent <= rand() % 100;
      node->active = notSelected ? 0 : 1;
    }
  }

  return entry;
}

// FUNCTION: IMPERIALISM 0x00557f10
char TNavyMgr::SelectEligibleMapOrderInteractionForNationAndContext(
    TMapOrderInteractionSelection* outResult, int portZoneContext, short nation,
    short offerAmount) {
  // The port-zone context's owning nation code.
  short ownerCode = 0;
  if (portZoneContext != 0) {
    ownerCode =
        reinterpret_cast<TZone*>(portZoneContext)->GetPortZoneOwnerNationCodeFromMissionField48();
  }

  // Priority ratio: fraction of this nation's remaining diplomacy capacity the offered
  // amount represents (x100).
  TGreatPower* nationState = g_apNationStates[nation];
  int capDiff = nationState->needCapA6 - nationState->diplomacyCounterA2;
  short priorityRatio = (capDiff == 0) ? 0 : static_cast<short>((offerAmount * 100) / capDiff);

  // Locate this nation's own type-7 order entry and gate each active child by a
  // priority-vs-descriptor-stock roll.
  TTaskForce* nationEntry = orderListHead04;
  while (nationEntry != nullptr &&
         !(nationEntry->required_count == nation && nationEntry->attachment == 7)) {
    nationEntry = nationEntry->queue_next;
  }
  if (nationEntry != nullptr) {
    for (TMapOrderChildLinkNode* node = nationEntry->childOrderList; node != nullptr;
         node = node->next) {
      TShip* child = static_cast<TShip*>(node->payload);
      char active = 1;
      if (child->stockLevel1c <
              g_NavyOrderResourceDescriptorTable[child->resourceType04].stockCap ||
          static_cast<int>(priorityRatio) <= static_cast<int>(rand()) % 100) {
        active = 0;
      }
      node->active = active;
    }
  }

  // Walk every queued order entry; return the first eligible interaction.
  for (TTaskForce* entry = orderListHead04; entry != nullptr; entry = entry->queue_next) {
    if (entry->eliminatedFlag26 != 0) {
      continue;
    }
    if (entry->GetMapOrderEntryChildCount() <= 0) {
      continue;
    }

    short attachment = entry->attachment;
    bool contextMatch = (attachment == 6 && entry->owner.raw == portZoneContext);
    // attachment 3 matches when this entry's contextAnchor equals the port zone's first
    // primary-neighbor slot (the active map-order context head).
    bool activeContextMatch = false;
    if (attachment == 3 && portZoneContext != 0) {
      TZone** slot = reinterpret_cast<TZone*>(portZoneContext)
                         ->primaryNeighbors.EnsureSlotAllocatedAndReturnPointer(0);
      activeContextMatch = (entry->contextAnchor == *slot);
    }

    // Diplomacy eligibility: the entry's nation must relate to the port-zone owner or
    // the querying nation.
    bool relatedToOwner = (entry->required_count == ownerCode ||
                           g_pDiplomacyTurnStateManager->IsNationPairRelationTurnStampOutOfDate(
                               ownerCode, entry->required_count) != 0);
    bool relatedToNation = (ownerCode >= 7 && entry->attachment == 6 &&
                            g_pDiplomacyTurnStateManager->IsNationPairRelationTurnStampOutOfDate(
                                entry->required_count, ownerCode) != 0);

    if (!(contextMatch || activeContextMatch) || !(relatedToOwner || relatedToNation)) {
      continue;
    }

    // Aggregate this entry's active-child descriptorWeight rating (x10) and roll a
    // gap-based threshold that also folds in the offer size relative to the entry's
    // per-child heuristic score.
    int ratingSum = 0;
    int activeCount = 0;
    for (TMapOrderChildLinkNode* node = entry->childOrderList; node != nullptr; node = node->next) {
      if (node->active != 0) {
        ratingSum +=
            g_NavyOrderResourceDescriptorTable[static_cast<TShip*>(node->payload)->resourceType04]
                .descriptorWeight;
        ++activeCount;
      }
    }
    short rating = (activeCount == 0) ? 0 : static_cast<short>((ratingSum * 10) / activeCount);
    // The original scores the entry's HEAD CHILD ship (ecx = [childOrderList->payload],
    // 0x5582a2), not the entry itself; score stays 0 with no children.
    short entryScore = 0;
    if (entry->childOrderList != nullptr) {
      entryScore = static_cast<short>(static_cast<TShip*>(entry->childOrderList->payload)
                                          ->ComputeMapOrderEntryHeuristicScore());
    }
    short perChildOffer = static_cast<short>(entry->ComputeTaskForceOrderAggregateScore());
    if (perChildOffer > 0) {
      perChildOffer = static_cast<short>(offerAmount / perChildOffer);
    }
    int entryChildren = entry->GetMapOrderEntryChildCount();
    int nationChildren = (nationEntry != nullptr) ? nationEntry->GetMapOrderEntryChildCount() : 0;
    int threshold = entryChildren + nationChildren + (attachment != 6 ? -0x1e : 0) +
                    (rating - entryScore) + 0x28 + perChildOffer;
    if (static_cast<int>(rand()) % 100 >= threshold) {
      continue;
    }

    // Eligible: publish the chosen entry and set the packed direction flags, then a
    // final diplomacy relation + child-count roll decides the exchange direction bit.
    unsigned int flags = outResult->directionFlags & 0xfffffffc;
    outResult->offerNationCode = entry->required_count;
    outResult->selectedEntry = entry;
    outResult->directionFlags = flags;
    if (g_pDiplomacyTurnStateManager->IsNationPairRelationTurnStampOutOfDate(
            nation, entry->required_count) == 0) {
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
            &selection, reinterpret_cast<int>(portZoneContext), nation, entryValue);
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
        snapshot.targetContext08.object = selection.selectedEntry->contextAnchor;

        CString labelScratch;
        g_apTerrainTypeDescriptorTable[selection.offerNationCode]->FormatOverlayTerrainLabelText(
            &labelScratch);
        CopyCStringIntoFixedBuffer(snapshot.nameBuffer[0].data, 0x20,
                                   static_cast<LPCSTR>(labelScratch));

        g_apTerrainTypeDescriptorTable[nation]->FormatOverlayTerrainLabelText(&labelScratch);
        CopyCStringIntoFixedBuffer(snapshot.nameBuffer[1].data, 0x20,
                                   static_cast<LPCSTR>(labelScratch));

        selection.selectedEntry->BuildTaskForceSelectionOverlayLabelText(&labelScratch);
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

        int selectedChildCount = CountMapOrderChildren(selection.selectedEntry->childOrderList);
        if (selection.selectedEntry->activeChildEntry != nullptr &&
            selection.selectedEntry->activeChildEntry->admiralBacklink20 != nullptr) {
          TAdmiral* admiral = selection.selectedEntry->activeChildEntry->admiralBacklink20;
          admiral->experiencePoints = static_cast<short>(admiral->experiencePoints + strengthDelta);
          if (admiral->experiencePoints >= 500) {
            admiral->experiencePoints = 499;
          }
        }
        if (selectedChildCount > 0) {
          short childStrengthDelta = static_cast<short>((strengthDelta * 3) / selectedChildCount);
          for (TMapOrderChildLinkNode* childNode = selection.selectedEntry->childOrderList;
               childNode != nullptr; childNode = childNode->next) {
            TShip* ship = static_cast<TShip*>(childNode->payload);
            ship->field30 = static_cast<short>(ship->field30 + childStrengthDelta);
            if (ship->field30 >= 500) {
              ship->field30 = 499;
            }
          }
        }

        if (passMismatch && !movedTrackedCounter) {
          modeIsOffer = 1;
          matchesOfferPass = 1;
        }

        snapshot.childCount[0] =
            static_cast<short>(CountMapOrderChildren(selection.selectedEntry->childOrderList));
        if (snapshot.childCount[0] > 0) {
          snapshot.childRecords[0] = new MapOrderBattleSideChildRecord[snapshot.childCount[0]];
          for (int childIndex = 0; childIndex < snapshot.childCount[0]; ++childIndex) {
            snapshot.childRecords[0][childIndex].nameBuffer[0] = 0;
          }
        }
        int selectedChildIndex = 0;
        for (TMapOrderChildLinkNode* selectedNode = selection.selectedEntry->childOrderList;
             selectedNode != nullptr; selectedNode = selectedNode->next) {
          TShip* selectedShip = static_cast<TShip*>(selectedNode->payload);
          MapOrderBattleSideChildRecord& detail = snapshot.childRecords[0][selectedChildIndex];
          detail.resourceType = selectedShip->resourceType04;
          detail.stockOrRequired = selectedShip->stockLevel1c;
          CopyCStringIntoFixedBuffer(detail.nameBuffer, 0x20,
                                     static_cast<LPCSTR>(selectedShip->displayName18));
          detail.strengthBucket = static_cast<short>(selectedShip->field30 / 100);
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
unsigned short TNavyMgr::GetMapContextActionLabelTokenByActionCode(short nTileIndex,
                                                                   int nInputFlags) {
  return static_cast<unsigned short>(
      g_awMapContextActionLabelTokenByCommand[GetMapContextActionCode(nTileIndex, nInputFlags)]);
}

// FUNCTION: IMPERIALISM 0x00559e00
unsigned short TNavyMgr::GetMapContextActionLabelToken(short nTileIndex, int nInputFlags) {
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
    if (context != nullptr && entry->HasNoMapOrderEntryChildrenQueued() == 0) {
      bool hasActiveChild = false;
      for (TMapOrderChildLinkNode* node = entry->childOrderList; node != nullptr;
           node = node->next) {
        if (node->active != 0) {
          hasActiveChild = true;
          break;
        }
      }
      if (hasActiveChild) {
        unsigned short minimumWeight = 10000;
        for (TMapOrderChildLinkNode* node = entry->childOrderList; node != nullptr;
             node = node->next) {
          if (node->active != 0) {
            TShip* ship = static_cast<TShip*>(node->payload);
            short weight =
                g_NavyOrderResourceDescriptorTable[ship->resourceType04].descriptorWeight;
            if (weight < static_cast<short>(minimumWeight)) {
              minimumWeight = static_cast<unsigned short>(weight);
            }
          }
        }
        short threshold = minimumWeight != 10000 ? static_cast<short>(minimumWeight) : 0;
        short distance =
            entry->contextAnchor->GetCachedMapActionContextDistanceOrRecompute(context);
        canResolve = distance <= threshold;
      }
    }
    if (canResolve) {
      actionCode = entry->ResolveMapOrderCommandFromActionContext(context);
      return g_awMapContextActionLabelTokenByCommand[actionCode];
    }
  } else {
    TGlobalMapCityScoreRecord* province = GetProvinceByTileIndex(nTileIndex);
    bool canResolve = false;
    if (province != nullptr) {
      short* queuedCounts = entry->shipCountsByClass;
      if (queuedCounts[0] + queuedCounts[1] + queuedCounts[2] + queuedCounts[3] != 0) {
        for (TMapOrderChildLinkNode* node = entry->childOrderList; node != nullptr;
             node = node->next) {
          if (node->active != 0) {
            canResolve = province->navyOrderReachableA0 != 0;
            break;
          }
        }
      }
    }
    if (canResolve) {
      char relationOutOfDate = g_pDiplomacyTurnStateManager->IsNationPairRelationTurnStampOutOfDate(
          entry->required_count, province->ownerNationCode00);
      return g_awMapContextActionLabelTokenByCommand[relationOutOfDate != 0 ? 16 : 1];
    }
  }

  return g_awMapContextActionLabelTokenByCommand[1];
}

// FUNCTION: IMPERIALISM 0x0055a020
bool TNavyMgr::TryHandleMapContextAction(short nTileIndex, int nInputFlags) {
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
    TTaskForce* entry = this->orderListHead04;
    while (entry != 0 && entry->tiebreak_strength != nTileIndex) {
      entry = entry->queue_next;
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
int TNavyMgr::TryQueueMapOrderFromTileAction(short nTileIndex, int nInputFlags) {
  // A context-only action consumes the click without any queue mutation.
  if (TryHandleMapContextAction(nTileIndex, nInputFlags) != 0) {
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
    } else if (entry->HasActiveMapOrderEntryChildren() == 0) {
      short dist = entry->contextAnchor->GetCachedMapActionContextDistanceOrRecompute(ctx);
      queueable = dist <= static_cast<short>(entry->GetMinActionThresholdFromEntryChildren());
    } else {
      queueable = false;
    }
    commandId = queueable ? entry->ResolveMapOrderCommandFromActionContext(ctx) : 1;
  } else {
    void* province = GetProvinceByTileIndex(nTileIndex);
    commandId = (entry->CanQueueMapOrderForProvinceContext(province) == 0)
                    ? 1
                    : entry->ResolveMapOrderCommandFromProvinceContext(province);
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
    entry->attachment = 3;
    entry->RebuildMapOrderEntryChildren();
    if (g_pNavyOrderManager->MoveMapOrderEntryToQueueHeadIfValid(entry)) {
      g_pActiveMapOrderContext->FinalizeQueuedMapOrderEntry(entry);
      return 1;
    }
    break;
  case 0x0d: {
    TZone* ctx = g_pActiveMapOrderContext->GetLinkedZoneForSeaTile(nTileIndex);
    entry->attachment = 1;
    entry->owner.asZone = ctx;
    entry->RebuildMapOrderEntryChildren();
    if (g_pNavyOrderManager->MoveMapOrderEntryToQueueHeadIfValid(entry)) {
      g_pActiveMapOrderContext->FinalizeQueuedMapOrderEntry(entry);
      return 1;
    }
    break;
  }
  case 0x0e: {
    TZone* ctx = g_pActiveMapOrderContext->GetLinkedZoneForSeaTile(nTileIndex);
    entry->attachment = 6;
    entry->owner.asZone = ctx;
    entry->RebuildMapOrderEntryChildren();
    if (g_pNavyOrderManager->MoveMapOrderEntryToQueueHeadIfValid(entry)) {
      g_pActiveMapOrderContext->FinalizeQueuedMapOrderEntry(entry);
      return 1;
    }
    break;
  }
  case 0x0f: {
    TZone* ctx = g_pActiveMapOrderContext->GetLinkedZoneForSeaTile(nTileIndex);
    entry->attachment = 1;
    entry->owner.asZone = ctx;
    entry->RebuildMapOrderEntryChildren();
    bool alreadyQueued = false;
    for (TTaskForce* node = g_pNavyOrderManager->orderListHead04; node != nullptr;
         node = node->queue_next) {
      if (node == entry) {
        alreadyQueued = true;
        break;
      }
    }
    bool committed;
    if (alreadyQueued) {
      committed = true;
    } else if (entry->GetMapOrderEntryChildCount() < 1) {
      entry->Free();
      committed = false;
    } else {
      entry->RelinkMapOrderQueueNodeBetween(nullptr, g_pNavyOrderManager->orderListHead04);
      g_pNavyOrderManager->orderListHead04 = entry;
      committed = true;
    }
    if (committed) {
      g_pActiveMapOrderContext->FinalizeQueuedMapOrderEntry(entry);
      return 1;
    }
    break;
  }
  case 0x10:
    entry->attachment = 5;
    entry->owner.asCityTarget = GetProvinceByTileIndex(nTileIndex);
    entry->RebuildMapOrderEntryChildren();
    if (g_pNavyOrderManager->MoveMapOrderEntryToQueueHeadIfValid(entry)) {
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
void TNavyMgr::ResolveMapOrderPairConflictStep(TTaskForce* leftEntry, TTaskForce* rightEntry) {
  MapOrderBattleSnapshot snapshot;
  snapshot.childCount[0] = 0;
  snapshot.childCount[1] = 0;
  snapshot.childRecords[0] = 0;
  snapshot.childRecords[1] = 0;
  BuildMapOrderBattleSideSnapshot(&snapshot, 0, leftEntry);
  BuildMapOrderBattleSideSnapshot(&snapshot, 1, rightEntry);

  int leftStartCount = CountMapOrderChildren(leftEntry->childOrderList);
  int rightStartCount = CountMapOrderChildren(rightEntry->childOrderList);

  int maxTier = 1;
  for (TMapOrderChildLinkNode* node = leftEntry->childOrderList; node != nullptr;
       node = node->next) {
    int tier =
        g_NavyOrderResourceDescriptorTable[static_cast<TShip*>(node->payload)->resourceType04]
            .priorityTier;
    if (tier > maxTier) {
      maxTier = tier;
    }
  }
  for (TMapOrderChildLinkNode* rightNode = rightEntry->childOrderList; rightNode != nullptr;
       rightNode = rightNode->next) {
    int tier =
        g_NavyOrderResourceDescriptorTable[static_cast<TShip*>(rightNode->payload)->resourceType04]
            .priorityTier;
    if (tier > maxTier) {
      maxTier = tier;
    }
  }

  // Per-attachment "convergence tolerance" the winning-tier ratio must clear for that side
  // to be judged to have genuinely won the tier (the real {1.1,0.95,0.8} float table,
  // indexed by the (order_type, order_strength) short pair at +0x04/+0x06 read together as
  // one dword index here -- two adjacent shorts read as a bulk index, one meaning per short,
  // not one slot with two overlaid types).
  const float kTierConvergenceThreshold[3] = {1.1f, 0.95f, 0.8f};
  float leftThreshold = kTierConvergenceThreshold[leftEntry->packedOrderTypeAndStrength];
  float rightThreshold = kTierConvergenceThreshold[rightEntry->packedOrderTypeAndStrength];

  int candidateTier = maxTier;
  bool tierUnreachable = false;

  for (;;) {
    TAdmiral* leftAdmiral = leftEntry == 0 || leftEntry->activeChildEntry == 0
                                ? 0
                                : leftEntry->activeChildEntry->admiralBacklink20;
    int leftBucket = leftAdmiral == 0 ? 0 : leftAdmiral->experiencePoints / 100;
    TAdmiral* rightAdmiral = rightEntry == 0 || rightEntry->activeChildEntry == 0
                                 ? 0
                                 : rightEntry->activeChildEntry->admiralBacklink20;
    int rightBucket = rightAdmiral == 0 ? 0 : rightAdmiral->experiencePoints / 100;

    int bestLeftFavorTier = 0;
    float bestLeftFavorRatio = 0.0f;
    int bestRightFavorTier = 0;
    float bestRightFavorRatio = 0.0f;
    for (int tier = 1; tier <= maxTier; ++tier) {
      float leftPower = SumMapOrderChildPowerAtOrAboveTier(leftEntry->childOrderList, tier) *
                        (1.0f + leftBucket * 0.1f);
      float rightPower = SumMapOrderChildPowerAtOrAboveTier(rightEntry->childOrderList, tier) *
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

    int leftWeight = (leftBucket + 10) *
                     CalculateActiveChildAverageDescriptorWeightX10(leftEntry->childOrderList);
    int rightWeight = (rightBucket + 10) *
                      CalculateActiveChildAverageDescriptorWeightX10(rightEntry->childOrderList);
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

    int leftEligible = CountMapOrderChildrenAtOrAboveTier(leftEntry->childOrderList, candidateTier);
    int rightEligible =
        CountMapOrderChildrenAtOrAboveTier(rightEntry->childOrderList, candidateTier);
    int leftCurrentCount = CountMapOrderChildren(leftEntry->childOrderList);
    int rightCurrentCount = CountMapOrderChildren(rightEntry->childOrderList);

    int leftAttritionTarget = rightEligible < leftCurrentCount ? rightEligible : leftCurrentCount;
    ApplyMapOrderConflictAttrition(leftEntry->childOrderList, leftCurrentCount, leftAttritionTarget,
                                   bestLeftFavorRatio);
    int rightAttritionTarget = leftEligible < rightCurrentCount ? leftEligible : rightCurrentCount;
    ApplyMapOrderConflictAttrition(rightEntry->childOrderList, rightCurrentCount,
                                   rightAttritionTarget, bestRightFavorRatio);

    leftEntry->childOrderList = PruneMapOrderConflictHeadAndTail(leftEntry->childOrderList);
    leftEntry->RecomputeMapOrderChildAggregateMetric();
    bool leftEmpty = leftEntry->childOrderList == nullptr;

    rightEntry->childOrderList = PruneMapOrderConflictHeadAndTail(rightEntry->childOrderList);
    rightEntry->RecomputeMapOrderChildAggregateMetric();
    bool rightEmpty = rightEntry->childOrderList == nullptr;

    if (leftEmpty || rightEmpty) {
      break;
    }
  }

  bool leftEliminated = leftEntry->childOrderList == nullptr;
  bool rightEliminated = rightEntry->childOrderList == nullptr;
  if (!tierUnreachable && (leftEliminated != rightEliminated)) {
    TTaskForce* loser = leftEliminated ? leftEntry : rightEntry;
    TTaskForce* winner = leftEliminated ? rightEntry : leftEntry;
    int loserStart = leftEliminated ? leftStartCount : rightStartCount;
    int loserRemaining = CountMapOrderChildren(loser->childOrderList);
    int bump = (loserStart - loserRemaining) * 5 + loserRemaining;
    int winnerCount = CountMapOrderChildren(winner->childOrderList);
    if (winnerCount > 0) {
      TAdmiral* winningAdmiral =
          winner->activeChildEntry == 0 ? 0 : winner->activeChildEntry->admiralBacklink20;
      if (winningAdmiral != 0) {
        winningAdmiral->experiencePoints =
            static_cast<short>(winningAdmiral->experiencePoints + bump);
        if (winningAdmiral->experiencePoints > 499) {
          winningAdmiral->experiencePoints = 499;
        }
      }
      for (TMapOrderChildLinkNode* node = winner->childOrderList; node != nullptr;
           node = node->next) {
        static_cast<TShip*>(node->payload)
            ->AdjustMapOrderNodeStatCapped499(static_cast<short>((bump * 3) / winnerCount));
      }
    }
    loser->eliminatedFlag26 = 1;
  }

  RefreshMapOrderBattleSideSnapshot(&snapshot, 0,
                                    leftEntry->childOrderList != nullptr ? leftEntry : nullptr);
  RefreshMapOrderBattleSideSnapshot(&snapshot, 1,
                                    rightEntry->childOrderList != nullptr ? rightEntry : nullptr);
  g_pMapContextActionManager->AppendMapContextActionRecordAndResetWorkingFields(&snapshot, 0);
}
