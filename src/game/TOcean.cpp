#include "game/TOcean.h"
#include "game/TNavyMgr.h"
#include "game/TMapMgr.h"
#include "game/TSimMgr.h"

#include <cstring>
#include <new>

#include "game/mfc.h"
#include "game/mfc.h"
#include "game/GameAssert.h"
#include "game/ui_invalidation_guard.h"
#include "game/mfc.h"
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

undefined4 SelectBestSeedTileForNationFromCostField(void);

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

void SetMapTileStateByteAndNotifyObserver(int tileIndex, int stateByte) {
  g_pGlobalMapState->SetMapTileStateByteAndNotifyObserver(tileIndex, stateByte);
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
  TGlobalMapCityScoreRecord** piSlotEntry;
  TGlobalMapCityScoreRecord** slotTable = secondaryNeighbors.Data();
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
            SetMapTileStateByteAndNotifyObserver(sVarSlotId, key_id % 7 + 7);
            *reinterpret_cast<unsigned short*>(
                reinterpret_cast<char*>(&g_pGlobalMapState->terrainStateTable[sVarSlotId]) + 0x1a) =
                0xffff;
          }
          key_id = key_id + 1;
          nSlotsRemaining = nSlotsRemaining - 1;
        } while (nSlotsRemaining != 0);
      } else {
        sVarSlotId = GetActiveNationSlotTile();
        SetMapTileStateByteAndNotifyObserver(sVarSlotId, 7);
        *reinterpret_cast<unsigned short*>(
            reinterpret_cast<char*>(&g_pGlobalMapState->terrainStateTable[sVarSlotId]) + 0x1a) =
            0xffff;
      }
    }
  }

  sVarActiveSlot = g_pSimMgr->GetActiveNationId();
  if (sVarActiveSlot == -1) {
    sVarActiveSlot = g_pSimMgr->GetActiveNationId();
  }

  if ((nationKeyMask10 & (1U << ((unsigned char)sVarActiveSlot & 0x1f))) != 0) {
    for (pvNode = GetNavyPrimaryOrderListHead(); pvNode != 0; pvNode = pvNode->nextOlder24) {
      if (((pvNode->field08 == this) && (pvNode->ownerNationSlot14 == sVarActiveSlot)) &&
          (pvNode->ownerOrderEntry0c == 0)) {
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

// Slot 0x07 (Free). Ghidra: DispatchNationPendingActionEventCodes (264 bytes) —
// real body is a follow-up port; stub keeps the vtable slot owned/paired. The
// address was briefly mis-modeled as non-virtual after a bad symbols.csv row
// (65c7e4|TPortZone::vftable, a stale duplicate of TPortZone's real vtable at
// 0x65c758) made TOcean's orig vtable boundary look 3 slots short; the row is
// deleted and this is confirmed a real override slot (raw memory at 0x65c7e4
// reads TOcean::Free, followed by inherited TObject::ShallowClone/ShallowFree).
// FUNCTION: IMPERIALISM 0x005621e0
void TOcean::Free() {}

// FUNCTION: IMPERIALISM 0x00562340
void TOcean::ReadFrom(TStream* stream) {
  (void)stream;
}

// FUNCTION: IMPERIALISM 0x005628f0
void TOcean::WriteTo(TStream* stream) {
  (void)stream;
}

// One relaxation sweep of the ground-cost wavefront: for every still-unset tile (cost 0),
// mark it reached (-1) when any hex neighbor is off-map or has a different owner-nation
// terrain class, otherwise pull in the cheapest positive neighbor cost as -(1+cost). A
// final pass flips the tentative negative costs positive. Returns the number of tiles
// changed this sweep (0 => converged).
// FUNCTION: IMPERIALISM 0x00562AF0
int RelaxMapTileCostFieldByNeighborTerrain(short* costField) {
  int changedCount = 0;
  int tileIndex = 0;
  int tileByteOffset = 0;
  short* pCost = costField;
  do {
    if (*pCost == 0) {
      for (int direction = 0; direction < 6; direction++) {
        short neighbor = TMapMgr::StepHexTileIndexByDirectionWithWrapRules(
            static_cast<short>(tileIndex), static_cast<short>(direction));
        short cur = *pCost;
        char* tiles = reinterpret_cast<char*>(g_pGlobalMapState->terrainStateTable);
        if (cur == 0 &&
            (neighbor == -1 || tiles[4 + neighbor * 0x24] != tiles[tileByteOffset + 4])) {
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
    tileByteOffset += 0x24;
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

// FUNCTION: IMPERIALISM 0x00562d90
void TOcean::InitializeMapActionContextsForNationCountUsingCostField(int nationCountArg) {
  TZone* contextBase;
  int* costField;
  int relaxPassCount;
  int nationIndex;

  nationCount = static_cast<short>(nationCountArg);
  if (contextArray != 0) {
    reinterpret_cast<void(__fastcall*)(TZone*, int, int)>(*reinterpret_cast<int*>(contextArray) +
                                                          4)(contextArray, 0, 3);
  }
  contextBase = new TZone[static_cast<int>(static_cast<short>(nationCountArg))];
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
  if (0 < static_cast<int>(static_cast<short>(nationCountArg))) {
    do {
      reinterpret_cast<int(__cdecl*)(int*, int)>(SelectBestSeedTileForNationFromCostField)(
          costField, nationIndex + 0x17);
      contextArray[nationIndex].SetMapActionContextTargetTileAndRefreshMarkers(nationIndex + 0x17,
                                                                               0xffff);
      nationIndex = nationIndex + 1;
    } while (nationIndex < static_cast<int>(static_cast<short>(nationCountArg)));
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
  for (TShip* shipNode = GetNavyPrimaryOrderListHead(); shipNode != 0;
       shipNode = shipNode->nextOlder24) {
    TZone* orderZone = shipNode->field08;
    orderZone->nationKeyMask10 =
        static_cast<unsigned short>(orderZone->nationKeyMask10 |
                                    (1 << static_cast<unsigned char>(shipNode->ownerNationSlot14)));
  }

  // 3) Reset overlay tile states across the whole map: nation-overlay states (7..0xd)
  // clear to -1, linked-zone overlay states (0xe..0x15) flip to their negated value.
  for (short overlayTile = 0; overlayTile < 0x1950; ++overlayTile) {
    short overlayState = static_cast<signed char>(
        g_pGlobalMapState->terrainStateTable[overlayTile].tileActionClass16);
    unsigned char isNationOverlay = (overlayState >= 7 && overlayState <= 0xd);
    if (isNationOverlay != 0) {
      SetMapTileStateByteAndNotifyObserver(overlayTile, -1);
    } else {
      unsigned char isLinkedZoneOverlay = (overlayState >= 0xe && overlayState < 0x16);
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
            SetMapTileStateByteAndNotifyObserver(slotTile, slotWrapped + 7);
            *reinterpret_cast<unsigned short*>(
                reinterpret_cast<char*>(&g_pGlobalMapState->terrainStateTable[slotTile]) + 0x1a) =
                0xffff;
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
  for (TTaskForce* rankEntry = g_pNavyOrderManager->orderListHead04; rankEntry != 0;
       rankEntry = rankEntry->queue_next) {
    if (rankEntry->required_count == g_pSimMgr->GetActiveNationId()) {
      continue;
    }
    unsigned char isTaskForceEntry = (rankEntry->attachment == 5);
    if (isTaskForceEntry == 0) {
      continue;
    }
    int cityIndex = GetCityIndexFromCityStatePointer(rankEntry->owner.asCityTarget);
    if (static_cast<short>(g_pGlobalMapState->cityScoreTable[cityIndex].ownerNationCode00) !=
        g_pSimMgr->GetActiveNationId()) {
      continue;
    }
    // contextAnchor is the anchoring map-action context TZone*; owner.raw is the kind-5
    // city-target record passed through as the heuristic's opaque second argument.
    short coastalTile =
        rankEntry->contextAnchor->FindBestCoastalTileForContextAndCityStateByHeuristic(
            rankEntry->owner.raw);
    if (coastalTile == -1) {
      continue;
    }
    SetMapTileStateByteAndNotifyObserver(coastalTile, rankEntry->required_count + 7);
    *reinterpret_cast<unsigned short*>(
        reinterpret_cast<char*>(&g_pGlobalMapState->terrainStateTable[coastalTile]) + 0x1a) =
        static_cast<unsigned short>(rankEntry->GetNavyOrderRankWithinNationBucket());
  }
}

// FUNCTION: IMPERIALISM 0x00563300
TZone* TOcean::GetMapActionContextEntryByNationCodeOffset17(short nationCode) {
  return &contextArray[nationCode - 0x17];
}

// FUNCTION: IMPERIALISM 0x005633b0
TZone* TOcean::GetLinkedZoneForSeaTile(short seaTileIndex) {
  TTerrainStateRecordView& terrainRecord = g_pGlobalMapState->terrainStateTable[seaTileIndex];
  signed char terrainClass = static_cast<signed char>(terrainRecord.tileActionClass16);
  if (terrainClass == 3 || terrainClass == 0x0e) {
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
    if (terrainTable[candidateTile].terrainType00 != 5) {
      continue;
    }
    bool allNeighborsQualify = true;
    for (int j = 0; j < 6; ++j) {
      short neighborTile =
          TMapMgr::GetWrappedHexNeighborTileIndexByDirection(candidateTile, static_cast<short>(j));
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
  signed char seaTileClass = terrainTable[bestSeaTile].tileActionClass16;
  if (seaTileClass == 3 || seaTileClass == 0xe) {
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
      portZone->primaryNeighbors.GetOrAppendUnique(linkedContext);
      linkedContext->primaryNeighbors.GetOrAppendUnique(portZone);
    }
  }

  SetMapTileStateByteAndNotifyObserver(static_cast<int>(bestSeaTile), 3);
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

// bd 1uj.16: TTaskForce::SetMapOrderType9AndQueue / PromoteMapOrderChainAndQueue's
// final notification step (0x5642e0). Only runs when the entry belongs to the active
// nation. It re-marks the entry's map tile (TTaskForce::UpdateNavyOrderMapMarkerByOrder-
// Type), lights the entry's TZone map-order UI flag iff the active nation still has a
// pending navy-order node targeting that zone, notifies the map picture's subview of the
// tile, and clears this manager's cached selected task force if it pointed at the entry.
// FUNCTION: IMPERIALISM 0x005642e0
void TOcean::FinalizeQueuedMapOrderEntry(TTaskForce* entry) {
  // entry->required_count (+0x1c) holds this entry's owner-nation slot here.
  if (g_pSimMgr->GetActiveNationId() != entry->required_count) {
    return;
  }
  entry->UpdateNavyOrderMapMarkerByOrderType();

  // contextAnchor (+0x18) is the entry's owning map-order zone (see the TZone casts in
  // TNavyMgr/TToolBarCluster); slot 0x58 is TZone::SetMapOrderUiFlag.
  TZone* zone = entry->contextAnchor;
  short nation = g_pSimMgr->GetActiveNationId();
  if (nation == -1) {
    nation = g_pSimMgr->GetActiveNationId();
  }
  int hasPendingNode = 0;
  if ((zone->nationKeyMask10 & static_cast<unsigned char>(1 << (nation & 0x1f))) != 0) {
    for (TShip* node = GetNavyPrimaryOrderListHead(); node != nullptr; node = node->nextOlder24) {
      if (node->field08 == zone && node->ownerNationSlot14 == nation &&
          node->ownerOrderEntry0c == nullptr) {
        hasPendingNode = 1;
        break;
      }
    }
  }
  zone->SetMapOrderUiFlag(hasPendingNode);

  // tiebreak_strength (+0x30) doubles as the entry's active map-tile notify index; 0xffff
  // means "no tile". Mac CodeWarrior identifies mapUberPictureF0 slot 0x1e8 as
  // NoticeTile.
  short tileNotifyIndex = entry->tiebreak_strength;
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
  if (entry->required_count != nation) {
    return;
  }

  entry->ClearNavyOrderMapMarker();
  TZone* zone = entry->contextAnchor;
  if (zone == 0) {
    return;
  }
  if (nation == -1) {
    nation = g_pSimMgr->GetActiveNationId();
  }

  int hasUnassignedShip = 0;
  if ((zone->nationKeyMask10 & static_cast<unsigned char>(1 << nation)) != 0) {
    for (TShip* ship = GetNavyPrimaryOrderListHead(); ship != 0; ship = ship->nextOlder24) {
      if (ship->field08 == zone && ship->ownerNationSlot14 == nation &&
          ship->ownerOrderEntry0c == 0) {
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
  TGlobalMapCityScoreRecord* target = &g_pGlobalMapState->cityScoreTable[cityRecordIndex];
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
  if (selectedTaskForce14 != nullptr &&
      selectedTaskForce14->contextAnchor != pMapOrderContextZone) {
    selectedTaskForce14->RemoveTaskForceOrderNodesByNationAndClearSelectionState(
        g_pSimMgr->GetActiveNationId(), pMapOrderContextZone);
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
    selectedTaskForce14->RefreshTaskForceSelectionFlagsForCurrentNationOrders(0);
  }
  return selectedTaskForce14;
}

// FUNCTION: IMPERIALISM 0x005979f0
TTaskForce* GetActiveMapOrderEntry() {
  return g_pActiveMapOrderContext->selectedTaskForce14;
}
