#include "game/TOcean.h"
#include "game/TNavyMgr.h"
#include "game/TMapMgr.h"
#include "game/TSimMgr.h"

#include <cstring>
#include <new>

#include "game/mfc.h"
#include "game/mfc.h"
#include "game/GameAssert.h"
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
#include "game/TTaskForce.h"

undefined4 SelectBestSeedTileForNationFromCostField(void);

namespace {
// Retain TOcean::`vftable' in the link until save/load paths virtual-dispatch through
// g_pActiveMapOrderContext (currently only non-virtual methods are referenced).
TOcean g_anchorTOceanInstance;
} // namespace

// FUNCTION: IMPERIALISM 0x00515e00
void NotifyMapUberPictureTileMarker(short tileIndex) {
  if (g_pUiRuntimeContext != 0 && g_pUiRuntimeContext->mapUberPictureF0 != 0) {
    g_pUiRuntimeContext->mapUberPictureF0->InvalidateTileMarkerChain(static_cast<short>(tileIndex));
  }
}

void SetMapTileStateByteAndNotifyObserver(int tileIndex, int stateByte) {
  g_pGlobalMapState->terrainStateTable[static_cast<short>(tileIndex)].tileActionClass16 =
      static_cast<unsigned char>(stateByte);
  NotifyMapUberPictureTileMarker(tileIndex);
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
  int* piSlotEntry;
  int** slotTable = reinterpret_cast<int**>(secondaryNeighbors.Data());
  unsigned int slotCount = static_cast<unsigned int>(secondaryNeighbors.GetSize());

  if ((field10 & (1U << ((unsigned char)key_id & 0x1f))) == 0) {
    field10 = static_cast<unsigned short>(field10 | (1U << ((unsigned char)key_id & 0x1f)));
    sVarSlotId = g_pSimMgr->GetActiveNationId();

    if ((field10 & (1U << ((unsigned char)sVarSlotId & 0x1f))) == 0) {
      uSlotCountLocal = slotCount;
      uSlotIndex = 0;
      if (uSlotCountLocal != 0) {
        do {
          if (uSlotIndex < uSlotCountLocal) {
            piSlotEntry = reinterpret_cast<int*>(slotTable) + static_cast<int>(uSlotIndex);
          } else {
            piSlotEntry = 0;
          }
          if (*reinterpret_cast<char*>(*piSlotEntry) == static_cast<char>(sVarSlotId)) {
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
          if ((field10 & (1U << ((unsigned char)(key_id % 7) & 0x1f))) != 0) {
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

  if ((field10 & (1U << ((unsigned char)sVarActiveSlot & 0x1f))) != 0) {
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

// No standalone address: the original ctor is small enough that MSVC500 inlined it
// directly at its one call site (TGameSetupPicture::HandleEvent's 'rand'-cheat path,
// 0x575bb0-0x575bd9) rather than emitting a separate TOcean::TOcean symbol.
TOcean::TOcean()
    : TObject(), nationCount(0), contextArray(0), routeNodeCount(0), routeNodeBuffer(0) {
  // Only selectedTaskForce14 (+0x14) is zeroed by the original ctor; the rest of the
  // still-unrecovered pad18 region is left uninitialized there too.
  selectedTaskForce14 = 0;
}

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
    maskZone->field10 = 0;
  }

  // 2) Re-seed the masks from the primary navy order list: each ship flags its zone
  // with its owner nation's bit.
  for (TShip* shipNode = GetNavyPrimaryOrderListHead(); shipNode != 0;
       shipNode = shipNode->nextOlder24) {
    TZone* orderZone = shipNode->field08;
    orderZone->field10 = static_cast<unsigned short>(
        orderZone->field10 | (1 << static_cast<unsigned char>(shipNode->ownerNationSlot14)));
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
      unsigned char nationFlagged = (ctxZone->field10 & activeNationBit) != 0 ||
                                    ctxZone->HasSecondaryNeighborWithNationTag(activeNationId) != 0;
      if (nationFlagged != 0) {
        ctxZone->SetMapOrderUiFlag(
            ctxZone->CanDisplayMapOrderEntryInCurrentContext(g_pSimMgr->GetActiveNationId(), 1));
        int slotCursor = activeNationId + 1;
        int slotsRemaining = 6;
        do {
          int slotWrapped = slotCursor % 7;
          if ((ctxZone->field10 & static_cast<unsigned char>(1 << slotWrapped)) != 0) {
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
    int cityIndex = GetCityIndexFromCityStatePointer(
        reinterpret_cast<TGlobalMapCityScoreRecord*>(rankEntry->owner), 0);
    if (static_cast<short>(g_pGlobalMapState->cityScoreTable[cityIndex].ownerNationCode00) !=
        g_pSimMgr->GetActiveNationId()) {
      continue;
    }
    // contextAnchor's pointee varies by producer (see TTaskForce.h); this entry kind
    // stores the anchoring map-action context TZone*.
    short coastalTile = reinterpret_cast<TZone*>(rankEntry->contextAnchor)
                            ->FindBestCoastalTileForContextAndCityStateByHeuristic(
                                reinterpret_cast<int>(rankEntry->owner));
    if (coastalTile == -1) {
      continue;
    }
    SetMapTileStateByteAndNotifyObserver(coastalTile, rankEntry->required_count + 7);
    *reinterpret_cast<unsigned short*>(
        reinterpret_cast<char*>(&g_pGlobalMapState->terrainStateTable[coastalTile]) + 0x1a) =
        static_cast<unsigned short>(rankEntry->GetNavyOrderRankWithinNationBucket());
  }
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
  return GetMapActionContextEntryByNationCodeOffset17(static_cast<short>(nationCode));
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
    if (static_cast<short>(portZone->field0c) == selectedTileId) {
      return portZone;
    }
    if (portZone->field20 == selectedTileId) {
      return portZone;
    }
    if (static_cast<short>(portZone->field48) == selectedTileId) {
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
    short tileIndex = static_cast<short>(static_cast<TPortZone*>(eax)->field48);
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

// FUNCTION: IMPERIALISM 0x00564530
int ComputeGlobalMapActionContextNodeValueAverage(void) {
  int sum = 0;
  int count = 0;

  for (TZone* zone = g_pMapActionContextListHead; zone != 0; zone = zone->prev18) {
    TGreatPower* nationState = g_apNationStates[zone->field12];
    sum += static_cast<int>(nationState->ComputeMapActionContextNodeValueAverage());
    ++count;
  }

  return sum / count;
}

// FUNCTION: IMPERIALISM 0x00564600
TTaskForce* TOcean::EnsureSelectedTaskForceForOrderOwnerAndRefresh(TZone* pMapOrderContextZone) {
  // If a different context zone is now selected, drop the cached task force's per-nation
  // order nodes; and if the new context is null, free and forget the cached task force.
  if (selectedTaskForce14 != nullptr &&
      selectedTaskForce14->contextAnchor != reinterpret_cast<int>(pMapOrderContextZone)) {
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

// bd 1uj.16: TTaskForce::SetMapOrderType9AndQueue / PromoteMapOrderChainAndQueue's
// final notification step (0x5642e0). Genuinely large (per-nation IsKindOf-gated
// view/menu refresh over g_apNationStates[entry->required_count] and a TZone
// SetMapOrderUiFlag dispatch) and several hops away from those two targets'
// core receiver-recovery ask; left as a documented placeholder rather than a
// guessed body. NOT claimed with a // FUNCTION: marker -- see bd 1uj.16
// follow-up notes.
void TOcean::FinalizeQueuedMapOrderEntry(TTaskForce* entry) {
  (void)entry;
}

// FUNCTION: IMPERIALISM 0x005979f0
TTaskForce* GetActiveMapOrderEntry() {
  return g_pActiveMapOrderContext->selectedTaskForce14;
}
