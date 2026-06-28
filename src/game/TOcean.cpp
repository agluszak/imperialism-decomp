#include "game/TOcean.h"

#include <new>

#include "game/mfc.h"
#include "game/mfc.h"
#include "game/GameAssert.h"
#include "game/mfc.h"
#include "game/TCity.h"
#include "game/TGlobalMapState.h"
#include "game/TZone.h"
#include "game/TGreatPower.h"
#include "game/diplomacy_globals.h"
#include "game/TMapUberPicture.h"
#include "game/UiRuntimeContext.h"
#include "game/TStream.h"
#include "game/TShip.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

extern "C" {
extern char g_pClassDescTPortZone;
extern CRuntimeClass PTR_s_TOcean_0065c630;
}

undefined4 RelaxMapTileCostFieldByNeighborTerrain(void);
undefined4 SelectBestSeedTileForNationFromCostField(void);

namespace {

// Map-action chain node: CObject-derived, next pointer at +0x18; TPortZone nodes
// carry the tile-id shorts checked at +0x0c/+0x20/+0x48.
struct MapActionNodeView : public CObject {
  unsigned char pad04[0x0c - 0x04];
  short tileId0c;
  unsigned char pad0e[0x18 - 0x0e];
  MapActionNodeView* next18;
  unsigned char pad1c[0x20 - 0x1c];
  short tileId20;
  unsigned char pad22[0x48 - 0x22];
  short tileId48;
};

} // namespace

namespace {
// Retain TOcean::`vftable' in the link until save/load paths virtual-dispatch through
// g_pActiveMapOrderContext (currently only non-virtual methods are referenced).
TOcean g_anchorTOceanInstance;
} // namespace

// FUNCTION: IMPERIALISM 0x00515e00
void NotifyMapUberPictureTileMarker(short tileIndex) {
  if (g_pUiRuntimeContext != 0 && g_pUiRuntimeContext->mapUberPictureF0 != 0) {
    g_pUiRuntimeContext->mapUberPictureF0->InvalidateTileMarkerChain(
        static_cast<short>(tileIndex));
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
  void* pvNode;
  int nSlotsRemaining;
  bool bSlotIsActive;
  unsigned int uSlotIndex;
  unsigned int uSlotCountLocal;
  int* piSlotEntry;
  int** slotTable = reinterpret_cast<int**>(secondaryNeighbors.Data());
  unsigned int slotCount = static_cast<unsigned int>(secondaryNeighbors.GetSize());

  if ((field10 & (1U << ((unsigned char)key_id & 0x1f))) == 0) {
    field10 = static_cast<unsigned short>(field10 | (1U << ((unsigned char)key_id & 0x1f)));
    sVarSlotId = g_pUiRuntimeContext->GetActiveNationId();

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
            *reinterpret_cast<unsigned short*>(reinterpret_cast<char*>(
                &g_pGlobalMapState->terrainStateTable[sVarSlotId]) + 0x1a) = 0xffff;
          }
          key_id = key_id + 1;
          nSlotsRemaining = nSlotsRemaining - 1;
        } while (nSlotsRemaining != 0);
      } else {
        sVarSlotId = GetActiveNationSlotTile();
        SetMapTileStateByteAndNotifyObserver(sVarSlotId, 7);
        *reinterpret_cast<unsigned short*>(reinterpret_cast<char*>(
            &g_pGlobalMapState->terrainStateTable[sVarSlotId]) + 0x1a) = 0xffff;
      }
    }
  }

  sVarActiveSlot = g_pUiRuntimeContext->GetActiveNationId();
  if (sVarActiveSlot == -1) {
    sVarActiveSlot = g_pUiRuntimeContext->GetActiveNationId();
  }

  if ((field10 & (1U << ((unsigned char)sVarActiveSlot & 0x1f))) != 0) {
    for (pvNode = GetNavyPrimaryOrderListHead(); pvNode != 0;
         pvNode = *reinterpret_cast<void**>(reinterpret_cast<char*>(pvNode) + 0x24)) {
      if (((*reinterpret_cast<void**>(reinterpret_cast<char*>(pvNode) + 8) == this) &&
           (*reinterpret_cast<short*>(reinterpret_cast<char*>(pvNode) + 0x14) == sVarActiveSlot)) &&
          (*reinterpret_cast<int*>(reinterpret_cast<char*>(pvNode) + 0xc) == 0)) {
        SetMapOrderUiFlag(1);
        return;
      }
    }
  }
  SetMapOrderUiFlag(0);
}

// SYNTHETIC: IMPERIALISM 0x00562140
// TOcean::`scalar deleting destructor'

TOcean::~TOcean() {}
IMPLEMENT_DYNCREATE(TOcean, TObject)

TOcean::TOcean() {}

// Slot 0x07 (Free). Ghidra: DispatchNationPendingActionEventCodes (264 bytes) —
// real body is a follow-up port; stub keeps the vtable slot owned/paired. This
// address was previously mis-owned by TPortZone (its "vtable" 0x65c7e4 aliases
// TOcean's tail).
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

// FUNCTION: IMPERIALISM 0x005634a0
void* TOcean::FindPortZoneBySelectedTile(TCity* city) {
  short selectedTileId;
  if (city->selectedOrderB0 == 0) {
    selectedTileId = 1;
  } else {
    selectedTileId =
        *reinterpret_cast<short*>(reinterpret_cast<char*>(city->selectedOrderB0) + 0x14);
  }
  MapActionNodeView* node = reinterpret_cast<MapActionNodeView*>(g_pMapActionContextListHead);
  while (node != 0 &&
         node->IsKindOf(reinterpret_cast<const CRuntimeClass*>(&g_pClassDescTPortZone)) == 0) {
    node = node->next18;
  }
  for (;;) {
    if (node == 0) {
      return 0;
    }
    if (node->tileId0c == selectedTileId) {
      return node;
    }
    if (node->tileId20 == selectedTileId) {
      return node;
    }
    if (node->tileId48 == selectedTileId) {
      break;
    }
    node = node->next18;
    while (node != 0 &&
           node->IsKindOf(reinterpret_cast<const CRuntimeClass*>(&g_pClassDescTPortZone)) == 0) {
      node = node->next18;
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
