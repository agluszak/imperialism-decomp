#include "game/TNavyMgr.h"

#include "game/TAdmiral.h"
#include "game/TArmyMgr.h"
#include "game/TCity.h"
#include "game/TCountry.h"
#include "game/TGreatPower.h"
#include "game/TMapMgr.h"
#include "game/TOcean.h"
#include "game/TShip.h"
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
#include "game/localization_text_helpers.h"
#include "game/map_order_battle_snapshot.h"

extern "C" int __cdecl rand(void);

extern "C" TShip* g_pNavyPrimaryOrderListHead;
extern "C" TAdmiral* g_pNavySecondaryOrderListHead;

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
void CopyCStringIntoFixedBuffer(char* dest, int destSize, const char* src) {
  int i = 0;
  for (; i < destSize; ++i) {
    char c = src[i];
    dest[i] = c;
    if (c == '\0') {
      break;
    }
  }
}

// Sum, over childOrderList entries whose resource-type priorityTier is >= minTier, of
// (child->tiebreak_strength/100 + resolveWeight*10 + 5)/10 -- the per-child "combat power"
// term ResolveMapOrderPairConflictStep's tier-scoring loop accumulates as a float.
float SumMapOrderChildPowerAtOrAboveTier(TMapOrderChildLinkNode* head, int minTier) {
  float total = 0.0f;
  for (TMapOrderChildLinkNode* node = head; node != nullptr; node = node->next) {
    TTaskForce* child = node->object_ptr;
    const TNavyOrderResourceDescriptor& descriptor =
        g_NavyOrderResourceDescriptorTable[child->order_type];
    if (descriptor.priorityTier < minTier) {
      continue;
    }
    int power = (child->tiebreak_strength / 100 + descriptor.resolveWeight * 10 + 5) / 10;
    total += static_cast<float>(power);
  }
  return total;
}

// Count of childOrderList entries whose resource-type priorityTier is >= minTier.
int CountMapOrderChildrenAtOrAboveTier(TMapOrderChildLinkNode* head, int minTier) {
  int count = 0;
  for (TMapOrderChildLinkNode* node = head; node != nullptr; node = node->next) {
    if (g_NavyOrderResourceDescriptorTable[node->object_ptr->order_type].priorityTier >= minTier) {
      ++count;
    }
  }
  return count;
}

int CountMapOrderChildren(TMapOrderChildLinkNode* head) {
  int count = 0;
  for (TMapOrderChildLinkNode* node = head; node != nullptr; node = node->next) {
    ++count;
  }
  return count;
}

// Randomly applies a resource-weighted attrition roll (0x55ae70/0x55af36) to up to
// `target` of `*headSlot`'s children: for each candidate node, rolls
// rand()%currentCount < target to select it (a single-pass approximation of the real
// per-node selection gate), then reduces its required_count by
// 0.5 + taskForceWeight[child->order_type] * ((rand()%100+rand()%100+100) * 0.005) *
// favorRatio * 0.01 (the confirmed real float constants at 0x65c3a8/0x65c3b0/0x65c3b8).
void ApplyMapOrderConflictAttrition(TMapOrderChildLinkNode* head, int currentCount, int target,
                                    float favorRatio) {
  if (target <= 0) {
    return;
  }
  int selected = 0;
  for (TMapOrderChildLinkNode* node = head; node != nullptr && selected < target;
       node = node->next) {
    if (currentCount == target || static_cast<int>(rand()) % currentCount < target) {
      ++selected;
      int roll = static_cast<int>(rand()) % 100 + static_cast<int>(rand()) % 100 + 100;
      TTaskForce* child = node->object_ptr;
      float delta = 0.5f + g_NavyOrderResourceDescriptorTable[child->order_type].taskForceWeight *
                               (roll * 0.005f) * favorRatio * -0.01f;
      child->required_count = static_cast<short>(child->required_count - static_cast<short>(delta));
    }
  }
}

// Removes a depleted (required_count < 1) list head and prunes any other depleted entries
// further down the chain; matches the real call sequence at 0x55afff/0x55b06e
// (SetMapOrderActiveChildEntry(nullptr) + Free() + DeleteMapOrderChildLinkAndReturnNext on a
// depleted head, else a side-effect-only PruneDefeatedMapOrderChildrenAndReturnHead(head->next)
// call on a still-alive head) rather than TTaskForce::PruneDefeatedMapOrderChildrenAndReturnHead's
// own equivalent-but-differently-sequenced internal logic.
TMapOrderChildLinkNode* PruneMapOrderConflictHeadAndTail(TMapOrderChildLinkNode* head) {
  if (head == nullptr) {
    return nullptr;
  }
  TTaskForce* child = head->object_ptr;
  if (child->required_count < 1) {
    child->SetMapOrderActiveChildEntry(nullptr);
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
  snapshot->requiredCountByte[side] = static_cast<char>(entry->required_count);

  CString terrainLabel;
  g_apTerrainTypeDescriptorTable[entry->required_count]->FormatOverlayTerrainLabelText(
      &terrainLabel);
  CopyCStringIntoFixedBuffer(snapshot->nameBuffer[side], 0x20, static_cast<LPCSTR>(terrainLabel));

  CString overlayLabel;
  entry->BuildTaskForceSelectionOverlayLabelText(&overlayLabel);
  CopyCStringIntoFixedBuffer(snapshot->overlayLabel[side], 0xff, static_cast<LPCSTR>(overlayLabel));

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
    TShip* child = reinterpret_cast<TShip*>(node->object_ptr);
    MapOrderBattleSideChildRecord& rec = records[idx];
    rec.resourceType = child->resourceType04;
    rec.stockOrRequired = child->stockLevel1c;
    CopyCStringIntoFixedBuffer(rec.nameBuffer, 0x20, static_cast<LPCSTR>(child->displayName18));
    rec.childPtr = child;
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
    TShip* child = reinterpret_cast<TShip*>(rec.childPtr);
    bool stillPresent = entry != nullptr && entry->childOrderList->FindNodeMatching(
                                                reinterpret_cast<TTaskForce*>(child)) != nullptr;
    if (stillPresent) {
      rec.stockOrRequired = child->stockLevel1c;
      rec.strengthBucket = static_cast<short>(child->field30 / 100);
    } else {
      rec.stockOrRequired = 0;
    }
    // Sentinel/debug marker written unconditionally each pass, matching the original's
    // own literal write (ASCII bytes "yvan", real meaning not recovered).
    rec.childPtr = reinterpret_cast<void*>(0x6e617679);
  }

  if (entry != nullptr && entry->attachment == 5) {
    int cityIndex = GetCityIndexFromCityStatePointer(
        reinterpret_cast<TGlobalMapCityScoreRecord*>(entry->owner));
    g_pMapContextActionManager->TrimExcessNavyOrderSupportAndRebuildOrderBuffer(
        snapshot->requiredCountByte[side], cityIndex);
  }
}

// Formats "<count><sep><commodity name>" into `out`: fetches the commodity's
// localized name (singular string group 0x2716 for count < 2, plural 0x271a
// otherwise) into `out`, then, for a non-negative count, prefixes the decimal count
// and the shared separator string. The concat/format helpers Ghidra names
// AssignSharedStringConcat*/_Format_CString are MFC CString operator+/Format.
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

void TNavyMgr::Free() {}

void TNavyMgr::WriteTo(TStream* stream) {
  (void)stream;
}

void TNavyMgr::ReadFrom(TStream* stream) {
  (void)stream;
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

// Seeds the three navy order-type ranking tables with the identity permutation, then
// selection-sorts each by descending descriptor weight (resolve / calculate-mission /
// navy-priority). The weight columns are read as dwords from the descriptor table, matching
// the original's g_..._LookupTable_006981xx int views.
// FUNCTION: IMPERIALISM 0x00556610
void InitializeNavyOrderPriorityTables() {
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
    if (nationFilter == -1 || nationFilter == admiral->terrainType) {
      ++matchCount;
    }
  }
  stream->WriteBytesSlot78(&matchCount, 2);
  for (TAdmiral* admiral2 = g_pNavySecondaryOrderListHead; admiral2 != 0;
       admiral2 = admiral2->next) {
    if (nationFilter == -1 || nationFilter == admiral2->terrainType) {
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
    if (nationFilter != -1 && admiralNode->terrainType != nationFilter) {
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
            node->active_flag =
                node->object_ptr->required_count <
                g_NavyOrderResourceDescriptorTable[node->object_ptr->order_type].stockCap;
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
          node->active_flag = 1;
          node = node->next;
        } while (node != 0);
      }
      // contextAnchor is the entry's owning map-order context here (the same
      // dual-purpose +0x18 slot TControlSeaZoneMission reinterprets as TZone*).
      if (reinterpret_cast<TZone*>(entry->contextAnchor)->QueryPortZoneCapability()) {
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
          if (node->active_flag != 0) {
            node = node->next;
          } else {
            node->object_ptr->SetMapOrderActiveChildEntry(0);
            short bucketIndex =
                static_cast<short>(g_NavyOrderResourceDescriptorTable[node->object_ptr->order_type]
                                       .enabledFlagOrBucketOffset);
            short* bucketCounter = reinterpret_cast<short*>(entry->pad_1e) + bucketIndex;
            --*bucketCounter;
            if (node == entry->childOrderList) {
              entry->childOrderList = node->next;
            }
            node = node->DeleteMapOrderChildLinkAndReturnNext();
          }
        }
        entry->activeChildEntry = 0;
        for (node = entry->childOrderList; node != 0; node = node->next) {
          entry->activeChildEntry = node->object_ptr->SelectPreferredMapOrderEntryByPriorityRules(
              entry->activeChildEntry, 0);
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
      if (g_pSimMgr->field44 == 1) {
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
        bool ownerMatch = (other->attachment == 1) &&
                          (other->contextAnchor == reinterpret_cast<int>(entry->owner) ||
                           other->owner == entry->owner);
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
      TTaskForce* child = node->object_ptr;
      bool notSelected =
          child->required_count < g_NavyOrderResourceDescriptorTable[child->order_type].stockCap ||
          chancePercent <= rand() % 100;
      node->active_flag = notSelected ? 0 : 1;
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
      TTaskForce* child = node->object_ptr;
      char active = 1;
      if (child->required_count < g_NavyOrderResourceDescriptorTable[child->order_type].stockCap ||
          static_cast<int>(priorityRatio) <= static_cast<int>(rand()) % 100) {
        active = 0;
      }
      node->active_flag = active;
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
    bool contextMatch = (attachment == 6 && reinterpret_cast<int>(entry->owner) == portZoneContext);
    // attachment 3 matches when this entry's contextAnchor equals the port zone's first
    // primary-neighbor slot (the active map-order context head).
    bool activeContextMatch = false;
    if (attachment == 3 && portZoneContext != 0) {
      TZone** slot = reinterpret_cast<TZone*>(portZoneContext)
                         ->primaryNeighbors.EnsureSlotAllocatedAndReturnPointer(0);
      activeContextMatch = (entry->contextAnchor == reinterpret_cast<int>(*slot));
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
      if (node->active_flag != 0) {
        ratingSum +=
            g_NavyOrderResourceDescriptorTable[node->object_ptr->order_type].descriptorWeight;
        ++activeCount;
      }
    }
    short rating = (activeCount == 0) ? 0 : static_cast<short>((ratingSum * 10) / activeCount);
    short entryScore = static_cast<short>(entry->ComputeMapOrderEntryHeuristicScore());
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
  // Query skeleton (fully ported): iterate the 7 playable nations that have a live
  // city, then each nation's 17 tracked map-order interaction slots, reading every
  // queued entry via TGreatPower's tracked-slot virtuals. `slot` is passed to
  // GetTrackedSlotEntryCountLow (slot 0x6d) and, with the 1-based ordinal, to
  // ReadTrackedSlotEntryFields (slot 0x6f), which unpacks the entry's
  // {kind, value, targetNation, payload} tuple. Confirmed against the disassembly:
  // count call PUSHes the slot index, the field-read PUSHes (slot, ordinal, &kind,
  // &value, &targetNation, &payload).
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

        // `entryKind` carries the exchange direction (1 = order offered by this
        // nation, 0 = order offered to it); `entryPayload` is the offered order
        // entry, `entryValue` the transferred amount.
        short orderMode = entryKind;
        short offerNation = (orderMode != 1) ? entryTargetNation : nation;
        short acceptNation = (orderMode != 1) ? nation : entryTargetNation;
        TTaskForce* orderEntry = reinterpret_cast<TTaskForce*>(entryPayload);

        // Resolve the port-zone context and filter interactions the map-order context
        // deems ineligible (order-score comparison + diplomacy relation gate).
        TZone* portZoneContext = g_pActiveMapOrderContext->FindFirstPortZoneContextByNation(nation);
        TMapOrderInteractionSelection eligibilityResult = {0};
        char eligible = SelectEligibleMapOrderInteractionForNationAndContext(
            &eligibilityResult, reinterpret_cast<int>(portZoneContext), nation, entryValue);
        if (eligible == 0) {
          continue;
        }

        // Build the localized order-exchange event message: the transferred commodity
        // label spliced into the base template (GetString group 0x273c) expanded
        // through g_pSimMgr's bracket-expression helper.
        CString commodityLabel;
        FormatLocalizedCommodityCountLabelByIndex(&commodityLabel, entryTargetNation, entryValue);
        CString exchangeMessage;
        g_pSimMgr->GetString(0x273c, 0, &exchangeMessage);
        scanBracketExpressions(g_pSimMgr, &exchangeMessage, static_cast<LPCSTR>(commodityLabel));

        // `mode` runs two complementary passes: pass 1 handles offered orders,
        // pass 2 handles accepted ones. Only the pass matching this entry's
        // direction applies its exchange outcome.
        bool isOfferPass = (mode == 1) && (orderMode == 1);
        bool isAcceptPass = (mode == 2) && (orderMode == 0);
        if (!isOfferPass && !isAcceptPass) {
          continue;
        }

        // Draw a randomized transferred resource count within the order's weight
        // budget from the offering nation's city resource counters.
        short drawnCounts[0x0e] = {0};
        int transferredCount =
            city->AllocateRandomResourceCountsWithinWeightBudget(entryValue, drawnCounts);

        // Apply the exchange to the offered order entry's children: bump the active
        // child's tiebreak stat and each child's strength, both capped at 499
        // (the same AdjustMapOrderNodeStatCapped499 pattern the conflict resolver uses).
        if (orderEntry != nullptr) {
          if (orderEntry->activeChildEntry != nullptr) {
            orderEntry->activeChildEntry->tiebreak_strength = static_cast<short>(
                orderEntry->activeChildEntry->tiebreak_strength + transferredCount);
            if (orderEntry->activeChildEntry->tiebreak_strength > 499) {
              orderEntry->activeChildEntry->tiebreak_strength = 499;
            }
          }
          int childCount = CountMapOrderChildren(orderEntry->childOrderList);
          if (childCount > 0) {
            for (TMapOrderChildLinkNode* node = orderEntry->childOrderList; node != nullptr;
                 node = node->next) {
              node->object_ptr->tiebreak_strength = static_cast<short>(
                  node->object_ptr->tiebreak_strength + (transferredCount * 3) / childCount);
              if (node->object_ptr->tiebreak_strength > 499) {
                node->object_ptr->tiebreak_strength = 499;
              }
            }
          }
        }

        // Credit the accepting nation's per-source order-transfer counter with the
        // transferred amount (offered nation is the source index).
        if (offerNation < 7 && acceptNation < 7 && g_apNationStates[acceptNation] != nullptr) {
          g_apNationStates[acceptNation]->AddShortDeltaToNationCounterAtOffset198(
              offerNation, static_cast<short>(transferredCount));
        }
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x0055a780
void TNavyMgr::ResolveMapOrderPairConflictStep(TTaskForce* leftEntry, TTaskForce* rightEntry) {
  MapOrderBattleSnapshot snapshot;
  BuildMapOrderBattleSideSnapshot(&snapshot, 0, leftEntry);
  BuildMapOrderBattleSideSnapshot(&snapshot, 1, rightEntry);

  int leftStartCount = CountMapOrderChildren(leftEntry->childOrderList);
  int rightStartCount = CountMapOrderChildren(rightEntry->childOrderList);

  int maxTier = 1;
  for (TMapOrderChildLinkNode* node = leftEntry->childOrderList; node != nullptr;
       node = node->next) {
    int tier = g_NavyOrderResourceDescriptorTable[node->object_ptr->order_type].priorityTier;
    if (tier > maxTier) {
      maxTier = tier;
    }
  }
  for (TMapOrderChildLinkNode* rightNode = rightEntry->childOrderList; rightNode != nullptr;
       rightNode = rightNode->next) {
    int tier = g_NavyOrderResourceDescriptorTable[rightNode->object_ptr->order_type].priorityTier;
    if (tier > maxTier) {
      maxTier = tier;
    }
  }

  // Per-attachment "convergence tolerance" the winning-tier ratio must clear for that side
  // to be judged to have genuinely won the tier (the real {1.1,0.95,0.8} float table,
  // indexed by the packed order_type/order_strength dword at +0x04 -- a single offset
  // reused as two shorts elsewhere and as one combined int here, matching the
  // type-modeling guardrail's dual-purpose-offset exception).
  static const float kTierConvergenceThreshold[3] = {1.1f, 0.95f, 0.8f};
  float leftThreshold = kTierConvergenceThreshold[*reinterpret_cast<int*>(&leftEntry->order_type)];
  float rightThreshold =
      kTierConvergenceThreshold[*reinterpret_cast<int*>(&rightEntry->order_type)];

  int candidateTier = maxTier;
  bool tierUnreachable = false;

  for (;;) {
    // Each side's "current active order" tiebreak bucket -- TODO: the real chain
    // (entry->activeChildEntry->attached_entity interpreted as a pointer to an
    // unidentified record, reading a short at +0x10) isn't recovered yet; treated as 0
    // (no scaling correction) pending a dedicated class-recovery pass.
    int leftBucket = 0;
    int rightBucket = 0;

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

    int leftWeight = (leftBucket + 10) * leftEntry->CalculateMapOrderEntryAverageChildRatingX10();
    int rightWeight =
        (rightBucket + 10) * rightEntry->CalculateMapOrderEntryAverageChildRatingX10();
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
    int bump = loserStart * 5 + candidateTier;
    int winnerCount = CountMapOrderChildren(winner->childOrderList);
    if (winnerCount > 0) {
      for (TMapOrderChildLinkNode* node = winner->childOrderList; node != nullptr;
           node = node->next) {
        node->object_ptr->AdjustMapOrderNodeStatCapped499(
            static_cast<short>((bump * 3) / winnerCount));
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
