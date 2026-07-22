#include "game/TOcean.h"
#include "game/TNavyMgr.h"
#include "game/TMapMgr.h"
#include "game/TSimMgr.h"

#include <cstdlib>
#include <cstring>
#include <new>

#include "game/mfc.h"
#include "game/GameAssert.h"
#include "game/ui_invalidation_guard.h"
#include "game/TCity.h"
#include "game/TGlobalMapState.h"
#include "game/TZone.h"
#include "game/TPortZone.h"
#include "game/TGreatPower.h"
#include "game/global_data_tables.h"
#include "game/TMapUberPicture.h"
#include "game/UiRuntimeContext.h"
#include "game/TStream.h"
#include "game/TShip.h"
#include "game/navy_order.h"
#include "game/TTaskForce.h"

namespace {
// Retain TOcean::`vftable' in the link until save/load paths virtual-dispatch through
// g_pActiveMapOrderContext (currently only non-virtual methods are referenced).
TOcean g_anchorTOceanInstance;
} // namespace

void NotifyMapUberPictureTileMarker(short tileIndex) {
  if (g_pUiRuntimeContext != 0 && g_pUiRuntimeContext->mapUberPictureF0 != 0) {
    g_pUiRuntimeContext->mapUberPictureF0->InvalidateTile(static_cast<short>(tileIndex));
  }
}

// FUNCTION: IMPERIALISM 0x0055fc40
void TZone::HandleKeyDown(int key_id) {
  short sVarSlotId;
  short sVarActiveSlot;
  TShip* pvNode;
  int nSlotsRemaining;
  bool bSlotIsActive;
  unsigned int uSlotIndex;
  unsigned int uSlotCountLocal;
  Province** piSlotEntry;
  Province** slotTable = secondaryNeighbors.Data();
  unsigned int slotCount = static_cast<unsigned int>(secondaryNeighbors.GetSize());

  if ((nationKeyMask10 & (1U << ((unsigned char)key_id & 0x1f))) == 0) {
    nationKeyMask10 =
        static_cast<unsigned short>(nationKeyMask10 | (1U << ((unsigned char)key_id & 0x1f)));
    sVarSlotId = g_pSimMgr->GetActiveNationId();

    if ((nationKeyMask10 & (1U << ((unsigned char)sVarSlotId & 0x1f))) == 0) {
      uSlotCountLocal = slotCount;
      uSlotIndex = 0;
      if (uSlotCountLocal != 0) {
        do {
          if (uSlotIndex < uSlotCountLocal) {
            piSlotEntry = slotTable + static_cast<int>(uSlotIndex);
          } else {
            piSlotEntry = 0;
          }
          if ((*piSlotEntry)->ownerNationCode00 == static_cast<char>(sVarSlotId)) {
            goto LAB_0055fcae;
          }
          uSlotIndex = uSlotIndex + 1;
        } while (uSlotIndex < uSlotCountLocal);
      }
      bSlotIsActive = false;
    } else {
    LAB_0055fcae:
      bSlotIsActive = true;
    }

    if (bSlotIsActive) {
      if (sVarSlotId == static_cast<short>(key_id)) {
        SetMapOrderUiFlag(1);
        key_id = sVarSlotId + 1;
        nSlotsRemaining = 6;
        do {
          if ((nationKeyMask10 & (1U << ((unsigned char)(key_id % 7) & 0x1f))) != 0) {
            sVarSlotId = GetActiveNationSlotTile();
            SetMapTileStateByteAndNotifyObserver(sVarSlotId,
                                                 key_id % 7 + kMapTileActionStateNationOrderFirst);
            g_pGlobalMapState->terrainStateTable[sVarSlotId].tileActionOrdinal1a = -1;
          }
          key_id = key_id + 1;
          nSlotsRemaining = nSlotsRemaining - 1;
        } while (nSlotsRemaining != 0);
      } else {
        sVarSlotId = GetActiveNationSlotTile();
        SetMapTileStateByteAndNotifyObserver(sVarSlotId, kMapTileActionStateNationOrderFirst);
        g_pGlobalMapState->terrainStateTable[sVarSlotId].tileActionOrdinal1a = -1;
      }
    }
  }

  sVarActiveSlot = g_pSimMgr->GetActiveNationId();
  if (sVarActiveSlot == -1) {
    sVarActiveSlot = g_pSimMgr->GetActiveNationId();
  }

  if ((nationKeyMask10 & (1U << ((unsigned char)sVarActiveSlot & 0x1f))) != 0) {
    for (pvNode = TShip::GetFirst(); pvNode != 0; pvNode = pvNode->next) {
      if (((pvNode->location == this) && (pvNode->nation == sVarActiveSlot)) &&
          (pvNode->taskForce == 0)) {
        SetMapOrderUiFlag(1);
        return;
      }
    }
  }
  SetMapOrderUiFlag(0);
}
// SYNTHETIC: IMPERIALISM 0x00562100
// TOcean::CreateObject

// SYNTHETIC: IMPERIALISM 0x00562140
// TOcean::`scalar deleting destructor'

TOcean::~TOcean() {}

// SYNTHETIC: IMPERIALISM 0x00562190
// TOcean::GetRuntimeClass

IMPLEMENT_DYNCREATE(TOcean, TObject)

// Slot 0x07 (Free): releases navy orders, map-action caches/zones, province-name state,
// and reseeds the map status PRNG. The address was briefly mis-modeled as non-virtual
// after a bad symbols.csv row
// (65c7e4|TPortZone::vftable, a stale duplicate of TPortZone's real vtable at
// 0x65c758) made TOcean's orig vtable boundary look 3 slots short; the row is
// deleted and this is confirmed a real override slot (raw memory at 0x65c7e4
// reads TOcean::Free, followed by inherited TObject::ShallowClone/ShallowFree).
// FUNCTION: IMPERIALISM 0x005621e0
void TOcean::Free() {
  if (g_pNavyOrderManager != 0) {
    g_pNavyOrderManager->ScuttleEverything();
  }
  if (g_pMapActionContextDistanceCache != 0) {
    delete[] static_cast<char*>(g_pMapActionContextDistanceCache);
    g_pMapActionContextDistanceCache = 0;
    g_nMapActionContextDistanceCacheSizedFor = -1;
    g_nMapActionContextCount = 0;
  }

  for (int i = 0; i < nationCount; ++i) {
    TZone* zone = &contextArray[i];
    if (g_pMapActionContextListHead == zone) {
      g_pMapActionContextListHead = zone->prev18;
    }
    if (zone->prev18 != 0) {
      zone->prev18->next1c = zone->next1c;
    }
    if (zone->next1c != 0) {
      zone->next1c->prev18 = zone->prev18;
    }
    zone->next1c = 0;
    zone->prev18 = 0;
  }
  delete[] contextArray;

  for (;;) {
    TZone* portZoneProbe = g_pMapActionContextListHead;
    while (portZoneProbe != 0 && portZoneProbe->IsKindOf(RUNTIME_CLASS(TPortZone)) == 0) {
      portZoneProbe = portZoneProbe->prev18;
    }
    if (portZoneProbe == 0) {
      break;
    }

    TZone* portZone = g_pMapActionContextListHead;
    while (portZone != 0 && portZone->IsKindOf(RUNTIME_CLASS(TPortZone)) == 0) {
      portZone = portZone->prev18;
    }
    portZone->Free();
  }

  delete[] routeSegments;
  delete this;
}

// FUNCTION: IMPERIALISM 0x00562340
void TOcean::ReadFrom(TStream* stream) {
  if (g_pMapActionContextDistanceCache != 0) {
    delete[] static_cast<char*>(g_pMapActionContextDistanceCache);
    g_pMapActionContextDistanceCache = 0;
    g_nMapActionContextCount = -1;
  }

  TObject::ReadFrom(stream);
  EnsureSelectedTaskForceForOrderOwnerAndRefresh(0);

  int i;
  for (i = 0; i < nationCount; ++i) {
    TZone* zone = &contextArray[i];
    if (g_pMapActionContextListHead == zone) {
      g_pMapActionContextListHead = zone->prev18;
    }
    if (zone->prev18 != 0) {
      zone->prev18->next1c = zone->next1c;
    }
    if (zone->next1c != 0) {
      zone->next1c->prev18 = zone->prev18;
    }
    zone->next1c = 0;
    zone->prev18 = 0;
  }
  delete[] contextArray;

  for (;;) {
    TZone* portZoneProbe = g_pMapActionContextListHead;
    while (portZoneProbe != 0 && portZoneProbe->IsKindOf(RUNTIME_CLASS(TPortZone)) == 0) {
      portZoneProbe = portZoneProbe->prev18;
    }
    if (portZoneProbe == 0) {
      break;
    }

    TZone* portZone = g_pMapActionContextListHead;
    while (portZone != 0 && portZone->IsKindOf(RUNTIME_CLASS(TPortZone)) == 0) {
      portZone = portZone->prev18;
    }
    portZone->Free();
  }

  stream->ReadBytes(&nationCount, 2);
  contextArray = new TZone[nationCount];
  if (contextArray == 0) {
    GAME_FAIL_NIL_POINTER();
  }
  for (i = 0; i < nationCount; ++i) {
    contextArray[i].ReadFrom(stream);
  }

  short portZoneCount;
  stream->ReadBytes(&portZoneCount, 2);
  while (portZoneCount != 0) {
    TPortZone* portZone = new TPortZone;
    portZone->ReadFrom(stream);
    --portZoneCount;
  }

  stream->ReadBytes(&routeNodeCount, 2);
  delete[] routeSegments;
  routeSegments = new CRect[routeNodeCount];
  if (routeSegments == 0) {
    GAME_FAIL_NIL_POINTER();
  }
  for (i = 0; i < routeNodeCount; ++i) {
    stream->ReadBytes(&routeSegments[i].top, 4);
    stream->ReadBytes(&routeSegments[i].left, 4);
    stream->ReadBytes(&routeSegments[i].bottom, 4);
    stream->ReadBytes(&routeSegments[i].right, 4);
  }

  if (g_nSaveFormatVersion < 0xd) {
    for (TZone* zone = g_pMapActionContextListHead; zone != 0; zone = zone->prev18) {
      if (zone->primaryNeighbors.Data() != 0) {
        void* oldEntries = zone->primaryNeighbors.Data();
        zone->primaryNeighbors.Data() = 0;
        zone->primaryNeighbors.Capacity() = 0;
        zone->primaryNeighbors.Count() = 0;
        free(oldEntries);
      }
      if (zone->secondaryNeighbors.Data() != 0) {
        void* oldEntries = zone->secondaryNeighbors.Data();
        zone->secondaryNeighbors.Data() = 0;
        zone->secondaryNeighbors.Capacity() = 0;
        zone->secondaryNeighbors.Count() = 0;
        free(oldEntries);
      }
    }
  }
  RefreshPortZoneNeighborContextLinksAndFallbacks();
}

// FUNCTION: IMPERIALISM 0x005628f0
void TOcean::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
  stream->WriteBytesSlot78(&nationCount, 2);
  int i;
  for (i = 0; i < nationCount; ++i) {
    contextArray[i].WriteTo(stream);
  }

  short portZoneCount = 0;
  TZone* portZone = g_pMapActionContextListHead;
  while (portZone != 0 && portZone->IsKindOf(RUNTIME_CLASS(TPortZone)) == 0) {
    portZone = portZone->prev18;
  }
  while (portZone != 0) {
    ++portZoneCount;
    portZone = portZone->prev18;
    while (portZone != 0 && portZone->IsKindOf(RUNTIME_CLASS(TPortZone)) == 0) {
      portZone = portZone->prev18;
    }
  }
  stream->WriteBytesSlot78(&portZoneCount, 2);

  portZone = g_pMapActionContextListHead;
  while (portZone != 0 && portZone->IsKindOf(RUNTIME_CLASS(TPortZone)) == 0) {
    portZone = portZone->prev18;
  }
  TZone* oldestPortZone = portZone;
  while (oldestPortZone != 0) {
    TZone* previousPortZone = oldestPortZone->prev18;
    while (previousPortZone != 0 && previousPortZone->IsKindOf(RUNTIME_CLASS(TPortZone)) == 0) {
      previousPortZone = previousPortZone->prev18;
    }
    if (previousPortZone == 0) {
      break;
    }
    oldestPortZone = previousPortZone;
  }
  portZone = oldestPortZone;
  while (portZone != 0) {
    portZone->WriteTo(stream);
    portZone = portZone->next1c;
    while (portZone != 0 && portZone->IsKindOf(RUNTIME_CLASS(TPortZone)) == 0) {
      portZone = portZone->next1c;
    }
  }

  stream->WriteBytesSlot78(&routeNodeCount, 2);
  for (i = 0; i < routeNodeCount; ++i) {
    stream->WriteBytesSlot78(&routeSegments[i].top, 4);
    stream->WriteBytesSlot78(&routeSegments[i].left, 4);
    stream->WriteBytesSlot78(&routeSegments[i].bottom, 4);
    stream->WriteBytesSlot78(&routeSegments[i].right, 4);
  }
}

// One relaxation sweep of the ground-cost wavefront: for every still-unset tile (cost 0),
// mark it reached (-1) when any hex neighbor is off-map or has a different owner nation,
// otherwise pull in the cheapest positive neighbor cost as -(1+cost). A
// final pass flips the tentative negative costs positive. Returns the number of tiles
// changed this sweep (0 => converged).
// FUNCTION: IMPERIALISM 0x00562AF0
int RelaxMapTileCostFieldByNeighborTerrain(short* costField) {
  int changedCount = 0;
  int tileIndex = 0;
  short* pCost = costField;
  do {
    if (*pCost == 0) {
      for (int direction = 0; direction < 6; direction++) {
        short neighbor = TMapMgr::StepHexTileIndexByDirectionWithWrapRules(
            static_cast<short>(tileIndex), static_cast<short>(direction));
        short cur = *pCost;
        TTerrainStateRecordView* tiles = g_pGlobalMapState->terrainStateTable;
        if (cur == 0 && (neighbor == -1 ||
                         tiles[neighbor].ownerNationTag04 != tiles[tileIndex].ownerNationTag04)) {
          *pCost = -1;
          changedCount++;
        } else {
          short neighborCost = costField[neighbor];
          if (neighborCost > 0 && (cur == 0 || neighborCost < -cur)) {
            *pCost = static_cast<short>(-1 - neighborCost);
            changedCount++;
          }
        }
      }
    }
    tileIndex++;
    pCost++;
    if (tileIndex > 0x194f) {
      short* clear = costField;
      for (int i = 0x1950; i != 0; i--) {
        if (*clear < 0) {
          *clear = static_cast<short>(-*clear);
        }
        clear++;
      }
      return changedCount;
    }
  } while (true);
}

// FUNCTION: IMPERIALISM 0x00562c00
int SelectBestSeedTileForNationFromCostField(short* costField, short nationTag) {
  int bestTile = -1;
  int bestScore = -1;
  short equalBestCount = 0;

  for (int tileIndex = 0; static_cast<short>(tileIndex) < 0x1878; ++tileIndex) {
    TTerrainStateRecordView* tile = &g_pGlobalMapState->terrainStateTable[tileIndex];
    if (static_cast<short>(tile->ownerNationTag04) != nationTag) {
      continue;
    }

    int score = costField[tileIndex] * 12;
    for (int direction = 0; direction < 6; ++direction) {
      short neighbor = TMapMgr::StepHexTileIndexByDirectionWithWrapRules(tileIndex, direction);
      if (neighbor != -1 && g_pGlobalMapState->terrainStateTable[neighbor].ownerNationTag04 ==
                                tile->ownerNationTag04) {
        score += costField[neighbor] * 2;
        if (direction == 4 || direction == 1) {
          score += costField[neighbor];
        }
      }
    }

    if (bestTile == -1 || bestScore < score) {
      bestTile = tileIndex;
      bestScore = score;
      equalBestCount = 1;
    } else if (score == bestScore) {
      ++equalBestCount;
      if (rand() % equalBestCount == 0 || bestTile < 0xd8) {
        bestTile = tileIndex;
        bestScore = score;
      }
    } else if (bestTile < 0xd8) {
      bestTile = tileIndex;
      bestScore = score;
    }
  }

  return bestTile;
}

void SetMapTileStateByteAndNotifyObserver(int tileIndex, int stateByte) {
  g_pGlobalMapState->SetMapTileStateByteAndNotifyObserver(tileIndex, stateByte);
}

// FUNCTION: IMPERIALISM 0x00562d90
void TOcean::InitializeMapActionContextsForNationCountUsingCostField(int nationCountArg) {
  TZone* contextBase;
  int* costField;
  int relaxPassCount;
  int nationIndex;

  nationCount = static_cast<short>(nationCountArg);
  delete[] contextArray;
  contextBase = new TZone[static_cast<short>(nationCountArg)];
  contextArray = contextBase;
  if (contextBase == 0) {
    GAME_FAIL_NIL_POINTER();
  }
  costField = new int[0xca8];
  {
    int* clearCursor = costField;
    for (int clearIndex = 0xca8; clearIndex != 0; clearIndex = clearIndex - 1) {
      *clearCursor = 0;
      clearCursor = clearCursor + 1;
    }
  }
  relaxPassCount = RelaxMapTileCostFieldByNeighborTerrain(reinterpret_cast<short*>(costField));
  while (relaxPassCount != 0) {
    relaxPassCount = RelaxMapTileCostFieldByNeighborTerrain(reinterpret_cast<short*>(costField));
  }
  nationIndex = 0;
  if (0 < static_cast<short>(nationCountArg)) {
    do {
      int seedTile = SelectBestSeedTileForNationFromCostField(
          reinterpret_cast<short*>(costField), static_cast<short>(nationIndex + 0x17));
      contextArray[nationIndex].SetMapActionContextTargetTileAndRefreshMarkers(nationIndex + 0x17,
                                                                               seedTile);
      nationIndex = nationIndex + 1;
    } while (nationIndex < static_cast<short>(nationCountArg));
  }
  delete[] costField;
}

// FUNCTION: IMPERIALISM 0x00562f20
void TOcean::RefreshMapActionContextNationOverlaysAndOrderRanks() {
  // 1) Clear every map-action context's per-nation key mask.
  for (TZone* maskZone = g_pMapActionContextListHead; maskZone != 0; maskZone = maskZone->prev18) {
    maskZone->nationKeyMask10 = 0;
  }

  // 2) Re-seed the masks from the primary navy order list: each ship flags its zone
  // with its owner nation's bit.
  for (TShip* shipNode = TShip::GetFirst(); shipNode != 0; shipNode = shipNode->next) {
    TZone* orderZone = shipNode->location;
    orderZone->nationKeyMask10 = static_cast<unsigned short>(
        orderZone->nationKeyMask10 | (1 << static_cast<unsigned char>(shipNode->nation)));
  }

  // 3) Reset overlay tile states across the whole map: nation-overlay states (7..0xd)
  // clear to -1, linked-zone overlay states (0xe..0x15) flip to their negated value.
  for (short overlayTile = 0; overlayTile < 0x1950; ++overlayTile) {
    short overlayState = static_cast<signed char>(
        g_pGlobalMapState->terrainStateTable[overlayTile].tileActionState16);
    unsigned char isNationOverlay = (overlayState >= kMapTileActionStateNationOrderFirst &&
                                     overlayState <= kMapTileActionStateNationOrderLast);
    if (isNationOverlay != 0) {
      SetMapTileStateByteAndNotifyObserver(overlayTile, kMapTileActionStateNone);
    } else {
      unsigned char isLinkedZoneOverlay = (overlayState >= kMapTileActionStateLinkedZoneFirst &&
                                           overlayState <= kMapTileActionStateLinkedZoneLast);
      if (isLinkedZoneOverlay != 0) {
        SetMapTileStateByteAndNotifyObserver(overlayTile, -overlayState);
      }
    }
  }

  // 4) For every context flagged for the active nation (mask bit or secondary-neighbor
  // city match), refresh the order-UI flag and repaint the other six nations' slot
  // markers.
  short activeNationId = g_pSimMgr->GetActiveNationId();
  if (g_pMapActionContextListHead != 0) {
    unsigned char activeNationBit = static_cast<unsigned char>(1 << activeNationId);
    for (TZone* ctxZone = g_pMapActionContextListHead; ctxZone != 0; ctxZone = ctxZone->prev18) {
      unsigned char nationFlagged = (ctxZone->nationKeyMask10 & activeNationBit) != 0 ||
                                    ctxZone->HasSecondaryNeighborWithNationTag(activeNationId) != 0;
      if (nationFlagged != 0) {
        ctxZone->SetMapOrderUiFlag(
            ctxZone->CanDisplayMapOrderEntryInCurrentContext(g_pSimMgr->GetActiveNationId(), 1));
        int slotCursor = activeNationId + 1;
        int slotsRemaining = 6;
        do {
          int slotWrapped = slotCursor % 7;
          if ((ctxZone->nationKeyMask10 & static_cast<unsigned char>(1 << slotWrapped)) != 0) {
            short slotTile = ctxZone->GetActiveNationSlotTile();
            SetMapTileStateByteAndNotifyObserver(slotTile,
                                                 slotWrapped + kMapTileActionStateNationOrderFirst);
            g_pGlobalMapState->terrainStateTable[slotTile].tileActionOrdinal1a = -1;
          }
          ++slotCursor;
          --slotsRemaining;
        } while (slotsRemaining != 0);
      }
    }
  }

  // 5) Order ranks: for every other nation's type-5 (task-force) order entry anchored on
  // an active-nation-owned city, mark that nation's overlay on the anchor context's best
  // coastal tile and store the entry's within-nation order rank in the tile's +0x1a word.
  for (TTaskForce* rankEntry = g_pNavyOrderManager->orderQueueHead; rankEntry != 0;
       rankEntry = rankEntry->nextForce) {
    if (rankEntry->nation == g_pSimMgr->GetActiveNationId()) {
      continue;
    }
    unsigned char isTaskForceEntry = (rankEntry->shipOrders == 5);
    if (isTaskForceEntry == 0) {
      continue;
    }
    int cityIndex = GetProvinceIndex(rankEntry->target.asProvince);
    if (static_cast<short>(g_pGlobalMapState->cityScoreTable[cityIndex].ownerNationCode00) !=
        g_pSimMgr->GetActiveNationId()) {
      continue;
    }
    // location is the anchoring map-action context TZone*; target.asProvince is the
    // kind-5 city record used by the coastal-tile heuristic.
    short coastalTile = rankEntry->location->FindBestCoastalTileForContextAndCityStateByHeuristic(
        rankEntry->target.asProvince);
    if (coastalTile == -1) {
      continue;
    }
    SetMapTileStateByteAndNotifyObserver(coastalTile,
                                         rankEntry->nation + kMapTileActionStateNationOrderFirst);
    g_pGlobalMapState->terrainStateTable[coastalTile].tileActionOrdinal1a =
        static_cast<short>(rankEntry->GetNationalIndex());
  }
}

// FUNCTION: IMPERIALISM 0x00563300
TZone* TOcean::GetMapActionContextEntryByNationCodeOffset17(short nationCode) {
  return &contextArray[nationCode - 0x17];
}

// FUNCTION: IMPERIALISM 0x005633b0
TZone* TOcean::GetLinkedZoneForSeaTile(short seaTileIndex) {
  TTerrainStateRecordView& terrainRecord = g_pGlobalMapState->terrainStateTable[seaTileIndex];
  signed char terrainClass = static_cast<signed char>(terrainRecord.tileActionState16);
  if (terrainClass == kMapTileActionStateAnchor || terrainClass == kMapTileActionStateDockedFleet) {
    return TZone::FindPortZoneByTile(seaTileIndex);
  }
  signed char nationCode = terrainRecord.ownerNationTag04;
  if (nationCode < 0x17) {
    return 0;
  }
  return &contextArray[static_cast<short>(nationCode) - 0x17];
}

// Walks the g_pMapActionContextListHead chain (via prev18) for the first TPortZone
// whose selected/coastal tile id matches the city's currently-selected order tile.
// FUNCTION: IMPERIALISM 0x005634a0
TZone* TOcean::FindPortZoneBySelectedTile(TCity* city) {
  short selectedTileId = city->SelectedOrderTileId();
  TZone* node = g_pMapActionContextListHead;
  while (node != 0 && node->IsKindOf(RUNTIME_CLASS(TPortZone)) == 0) {
    node = node->prev18;
  }
  for (;;) {
    TPortZone* portZone = static_cast<TPortZone*>(node);
    if (portZone == 0) {
      return 0;
    }
    if (static_cast<short>(portZone->tileOrTerrainId0c) == selectedTileId) {
      return portZone;
    }
    if (portZone->activeTileIndex20 == selectedTileId) {
      return portZone;
    }
    if (portZone->portTileIndex48 == selectedTileId) {
      break;
    }
    node = portZone->prev18;
    while (node != 0 && node->IsKindOf(RUNTIME_CLASS(TPortZone)) == 0) {
      node = node->prev18;
    }
  }
  return node;
}

// FUNCTION: IMPERIALISM 0x00563540
TZone* TOcean::FindFirstPortZoneContextByNation(short nationSlot) {
  TZone* esi = static_cast<TZone*>(g_pMapActionContextListHead);
  if (esi != 0) {
    do {
      if (esi->IsKindOf(RUNTIME_CLASS(TPortZone)) != 0) {
        break;
      }
      esi = esi->prev18;
    } while (esi != 0);
  }

  TZone* eax = esi;
  if (eax == 0) {
    return 0;
  }

  do {
    short tileIndex = static_cast<TPortZone*>(eax)->portTileIndex48;
    short ownerTag =
        static_cast<short>(g_pGlobalMapState->terrainStateTable[tileIndex].ownerNationTag04);
    if (ownerTag == nationSlot) {
      return eax;
    }

    esi = eax->prev18;
    if (esi != 0) {
      do {
        if (esi->IsKindOf(RUNTIME_CLASS(TPortZone)) != 0) {
          break;
        }
        esi = esi->prev18;
      } while (esi != 0);
    }
    eax = esi;
  } while (eax != 0);

  return 0;
}

// FUNCTION: IMPERIALISM 0x005635e0
void TOcean::EnsurePortZoneForTile(short nTileIndex) {
  if (g_pGlobalMapState == 0) {
    return;
  }
  TTerrainStateRecordView* terrainTable = g_pGlobalMapState->terrainStateTable;
  int tileIndex = static_cast<int>(nTileIndex);
  if ((terrainTable[tileIndex].activeFlags1c & 1) == 0) {
    return;
  }
  signed char nationSeed = terrainTable[tileIndex].ownerNationTag04;

  TZone* existingZone = TZone::GetFirstPortZone();
  while (existingZone != 0 && static_cast<short>(existingZone->tileOrTerrainId0c) != nTileIndex &&
         existingZone->activeTileIndex20 != nTileIndex &&
         static_cast<TPortZone*>(existingZone)->portTileIndex48 != nTileIndex) {
    existingZone = existingZone->GetNextPortZone();
  }
  if (existingZone != 0) {
    return;
  }

  TPortZone* portZone = new TPortZone();
  if (portZone != 0) {
    portZone->portTileIndex48 = nTileIndex;
  }
  if (portZone == 0) {
    FailNilPointerWithAssert(s_SourcePathUOcean_006984CC, 0x96a);
  }

  portZone->SetMapActionContextTargetTileAndRefreshMarkers(static_cast<int>(nationSeed), -1);
  portZone->tileOrTerrainId0c = tileIndex;
  portZone->GenerateZoneStatusCodeIfUnset();
  portZone->GenerateMapActionContextDisplayNameAndHeadline(0, 0);

  short bestSeaTile = -1;
  for (int i = 0; i < 6; ++i) {
    short direction = static_cast<short>((tileIndex + i) % 6);
    short candidateTile = TMapMgr::StepHexTileIndexByDirectionWithWrapRules(nTileIndex, direction);
    if (candidateTile == -1) {
      continue;
    }
    if (terrainTable[candidateTile].GetTerrainKind() != kStrategicTerrainWater) {
      continue;
    }
    bool allNeighborsQualify = true;
    for (int j = 0; j < 6; ++j) {
      short neighborTile = TMapMgr::GetNeighborTileID(candidateTile, static_cast<short>(j));
      if (neighborTile == -1) {
        continue;
      }
      signed char neighborNation = terrainTable[neighborTile].ownerNationTag04;
      if (neighborNation < 0x17 && neighborNation != nationSeed) {
        allNeighborsQualify = false;
        break;
      }
    }
    if (allNeighborsQualify) {
      bestSeaTile = candidateTile;
      break;
    }
  }
  if (bestSeaTile == -1) {
    bestSeaTile = TraceTerrainFlowToNearestSeaTile(nTileIndex);
  }

  TZone* linkedContext;
  signed char seaTileClass = terrainTable[bestSeaTile].tileActionState16;
  if (seaTileClass == kMapTileActionStateAnchor || seaTileClass == kMapTileActionStateDockedFleet) {
    linkedContext = TZone::GetFirstPortZone();
    while (linkedContext != 0 &&
           static_cast<short>(linkedContext->tileOrTerrainId0c) != bestSeaTile &&
           linkedContext->activeTileIndex20 != bestSeaTile &&
           static_cast<TPortZone*>(linkedContext)->portTileIndex48 != bestSeaTile) {
      linkedContext = linkedContext->GetNextPortZone();
    }
  } else {
    signed char seaTileOwner = terrainTable[bestSeaTile].ownerNationTag04;
    if (seaTileOwner < 0x17) {
      linkedContext = 0;
    } else {
      linkedContext =
          g_pActiveMapOrderContext->GetMapActionContextEntryByNationCodeOffset17(seaTileOwner);
    }
  }

  if (linkedContext != 0) {
    int entryIndex = 0;
    int primarySize = portZone->primaryNeighbors.GetSize();
    bool alreadyLinked = false;
    if (primarySize != 0) {
      for (; entryIndex < primarySize; ++entryIndex) {
        if (portZone->primaryNeighbors.GetAt(entryIndex) == linkedContext) {
          alreadyLinked = true;
          break;
        }
      }
    }
    if (!alreadyLinked) {
      portZone->primaryNeighbors.Add(linkedContext);
      linkedContext->primaryNeighbors.Add(portZone);
    }
  }

  SetMapTileStateByteAndNotifyObserver(static_cast<int>(bestSeaTile), kMapTileActionStateAnchor);
  portZone->tileOrTerrainId0c = static_cast<int>(bestSeaTile);
  portZone->activeTileIndex20 = portZone->FindNearestActiveSeaContextTileFromOffset216();
}

// FUNCTION: IMPERIALISM 0x00564240
void TOcean::RemovePortZoneByTile(short nTileIndex) {
  TZone* zone = g_pMapActionContextListHead;
  while (zone != 0 && zone->IsKindOf(RUNTIME_CLASS(TPortZone)) == 0) {
    zone = zone->prev18;
  }
  while (zone != 0) {
    if (static_cast<short>(zone->tileOrTerrainId0c) == nTileIndex ||
        zone->activeTileIndex20 == nTileIndex ||
        static_cast<TPortZone*>(zone)->portTileIndex48 == nTileIndex) {
      zone->Free();
      return;
    }
    zone = zone->prev18;
    while (zone != 0 && zone->IsKindOf(RUNTIME_CLASS(TPortZone)) == 0) {
      zone = zone->prev18;
    }
  }
}

// bd 1uj.16: TTaskForce::OrderEvade / OrderSailTowards's
// final notification step (0x5642e0). Only runs when the entry belongs to the active
// nation. It re-marks the entry's map tile (TTaskForce::UpdateNavyOrderMapMarkerByOrder-
// Type), lights the entry's TZone map-order UI flag iff the active nation still has a
// pending navy-order node targeting that zone, notifies the map picture's subview of the
// tile, and clears this manager's cached selected task force if it pointed at the entry.
// FUNCTION: IMPERIALISM 0x005642e0
void TOcean::FinalizeQueuedMapOrderEntry(TTaskForce* entry) {
  // entry->nation (+0x1c) holds this entry's owner-nation slot here.
  if (g_pSimMgr->GetActiveNationId() != entry->nation) {
    return;
  }
  entry->CreateIngot();

  // location (+0x18) is the entry's owning map-order zone (see the TZone casts in
  // TNavyMgr/TToolBarCluster); slot 0x58 is TZone::SetMapOrderUiFlag.
  TZone* zone = entry->location;
  short nation = g_pSimMgr->GetActiveNationId();
  if (nation == -1) {
    nation = g_pSimMgr->GetActiveNationId();
  }
  int hasPendingNode = 0;
  if ((zone->nationKeyMask10 & static_cast<unsigned char>(1 << (nation & 0x1f))) != 0) {
    for (TShip* node = TShip::GetFirst(); node != nullptr; node = node->next) {
      if (node->location == zone && node->nation == nation && node->taskForce == nullptr) {
        hasPendingNode = 1;
        break;
      }
    }
  }
  zone->SetMapOrderUiFlag(hasPendingNode);

  // ingotTileIndex (+0x30) doubles as the entry's active map-tile notify index; 0xffff
  // means "no tile". Mac CodeWarrior identifies mapUberPictureF0 slot 0x1e8 as
  // NoticeTile.
  short tileNotifyIndex = entry->ingotTileIndex;
  if (tileNotifyIndex != -1 && g_pUiRuntimeContext->mapUberPictureF0 != nullptr) {
    g_pUiRuntimeContext->mapUberPictureF0->NoticeTile(tileNotifyIndex);
  }

  if (selectedTaskForce14 == entry) {
    selectedTaskForce14 = nullptr;
  }
}

// Mac oracle: TOcean::ForgetForce(TTaskForce*).
// FUNCTION: IMPERIALISM 0x00564400
void TOcean::ForgetForce(TTaskForce* entry) {
  if (this == 0) {
    return;
  }
  if (selectedTaskForce14 == entry) {
    selectedTaskForce14 = 0;
  }
  short nation = g_pSimMgr->GetActiveNationId();
  if (entry->nation != nation) {
    return;
  }

  entry->DestroyIngot();
  TZone* zone = entry->location;
  if (zone == 0) {
    return;
  }
  if (nation == -1) {
    nation = g_pSimMgr->GetActiveNationId();
  }

  int hasUnassignedShip = 0;
  if ((zone->nationKeyMask10 & static_cast<unsigned char>(1 << nation)) != 0) {
    for (TShip* ship = TShip::GetFirst(); ship != 0; ship = ship->next) {
      if (ship->location == zone && ship->nation == nation && ship->taskForce == 0) {
        hasUnassignedShip = 1;
        break;
      }
    }
  }
  zone->SetMapOrderUiFlag(hasUnassignedShip);
}

// FUNCTION: IMPERIALISM 0x00564530
int TOcean::ComputeGlobalMapActionContextNodeValueAverage() {
  int sum = 0;
  int count = 0;

  for (TZone* zone = g_pMapActionContextListHead; zone != 0; zone = zone->prev18) {
    sum += zone->ComputeMapActionContextNodeValueAverage();
    ++count;
  }

  return sum / count;
}

// FUNCTION: IMPERIALISM 0x00564570
TZone* TOcean::FindMapActionContextContainingNodeByIndex(int cityRecordIndex) {
  Province* target = &g_pGlobalMapState->cityScoreTable[cityRecordIndex];
  for (TZone* zone = g_pMapActionContextListHead; zone != 0; zone = zone->prev18) {
    if (zone->secondaryNeighbors.ContainsEntry(target)) {
      return zone;
    }
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x00564600
TTaskForce* TOcean::EnsureSelectedTaskForceForOrderOwnerAndRefresh(TZone* pMapOrderContextZone) {
  // If a different context zone is now selected, drop the cached task force's per-nation
  // order nodes; and if the new context is null, free and forget the cached task force.
  if (selectedTaskForce14 != nullptr && selectedTaskForce14->location != pMapOrderContextZone) {
    selectedTaskForce14->RegainVirginity(g_pSimMgr->GetActiveNationId(), pMapOrderContextZone);
    if (pMapOrderContextZone == nullptr) {
      TTaskForce* previous = selectedTaskForce14;
      selectedTaskForce14 = nullptr;
      previous->Free();
    }
  }
  if (selectedTaskForce14 == nullptr) {
    if (pMapOrderContextZone != nullptr) {
      selectedTaskForce14 = pMapOrderContextZone->CreateTaskForceFromNavyOrdersForNationIfEligible(
          g_pSimMgr->GetActiveNationId());
      return selectedTaskForce14;
    }
  } else if (pMapOrderContextZone != nullptr) {
    selectedTaskForce14->MaxOut(0);
  }
  return selectedTaskForce14;
}

// FUNCTION: IMPERIALISM 0x005979f0
TTaskForce* GetActiveMapOrderEntry() {
  return g_pActiveMapOrderContext->selectedTaskForce14;
}
