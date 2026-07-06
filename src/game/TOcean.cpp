#include "game/TOcean.h"
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

extern "C" {
extern CRuntimeClass PTR_s_TOcean_0065c630;
}

undefined4 RelaxMapTileCostFieldByNeighborTerrain(void);
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
  g_pGlobalMapState->terrainStateTable[static_cast<short>(tileIndex)].pad16 =
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
          (pvNode->field0c == 0)) {
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
  // Only the first dword of this still-unrecovered padding region is zeroed by the
  // original ctor; the rest of pad14 is left uninitialized there too.
  memset(pad14, 0, sizeof(int));
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

// FUNCTION: IMPERIALISM 0x00562d90
void TOcean::InitializeMapActionContextsForNationCountUsingCostField(int nationCountArg) {
  TZone* contextBase;
  int* costField;
  int relaxPassCount;
  int nationIndex;
  int contextStride;

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
  relaxPassCount =
      reinterpret_cast<int(__cdecl*)(int*)>(RelaxMapTileCostFieldByNeighborTerrain)(costField);
  while (relaxPassCount != 0) {
    relaxPassCount =
        reinterpret_cast<int(__cdecl*)(int*)>(RelaxMapTileCostFieldByNeighborTerrain)(costField);
  }
  nationIndex = 0;
  if (0 < static_cast<int>(static_cast<short>(nationCountArg))) {
    contextStride = 0;
    do {
      reinterpret_cast<int(__cdecl*)(int*, int)>(SelectBestSeedTileForNationFromCostField)(
          costField, nationIndex + 0x17);
      reinterpret_cast<TZone*>(reinterpret_cast<char*>(contextArray) + contextStride)
          ->SetMapActionContextTargetTileAndRefreshMarkers(nationIndex + 0x17, 0xffff);
      nationIndex = nationIndex + 1;
      contextStride = contextStride + 0x48;
    } while (nationIndex < static_cast<int>(static_cast<short>(nationCountArg)));
  }
  delete[] costField;
}

// FUNCTION: IMPERIALISM 0x00563300
TZone* TOcean::GetMapActionContextEntryByNationCodeOffset17(short nationCode) {
  return reinterpret_cast<TZone*>(reinterpret_cast<char*>(this->contextArray) +
                                  (static_cast<int>(nationCode) - 0x17) * 0x48);
}

TZone* TOcean::GetLinkedZoneForSeaTile(short seaTileIndex) {
  TTerrainStateRecordView& terrainRecord = g_pGlobalMapState->terrainStateTable[seaTileIndex];
  signed char terrainClass = static_cast<signed char>(terrainRecord.pad16);
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
    if (node == 0) {
      return 0;
    }
    if (static_cast<short>(node->field0c) == selectedTileId) {
      return node;
    }
    if (node->field20 == selectedTileId) {
      return node;
    }
    if (static_cast<short>(static_cast<TPortZone*>(node)->field48) == selectedTileId) {
      break;
    }
    node = node->prev18;
    while (node != 0 && node->IsKindOf(RUNTIME_CLASS(TPortZone)) == 0) {
      node = node->prev18;
    }
  }
  return node;
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
TTaskForce* TOcean::EnsureSelectedTaskForceForOrderOwnerAndRefresh(TTaskForce* pMapOrderEntry) {
  // TODO: port body @ 0x564600 (245 bytes; frees/caches a task force into an as-yet
  // unexposed TOcean field around +0x14; not yet ported).
  (void)pMapOrderEntry;
  return nullptr;
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
