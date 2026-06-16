#include "game/TMapOrderContext.h"

#include "game/mfc.h"
#include "game/mfc.h"
#include "game/GameAssert.h"
#include "game/mfc.h"
#include "game/TCity.h"
#include "game/TGlobalMapState.h"
#include "game/TZone.h"
#include "game/TGreatPower.h"
#include "game/diplomacy_globals.h"
#include "game/UiRuntimeContext.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

extern "C" {
extern char g_pClassDescTPortZone;
}

int AllocateWithFallbackHandler(undefined4 size_bytes);
undefined4 CallCallbackRepeatedly(void);
undefined4 thunk_RelaxMapTileCostFieldByNeighborTerrain(void);
undefined4 thunk_SelectBestSeedTileForNationFromCostField(void);
undefined4 thunk_GetNavyPrimaryOrderListHead(void);

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

// FUNCTION: IMPERIALISM 0x00515e00
void SetMapTileStateByteAndNotifyObserver(int tileIndex, int stateByte) {
  char* tileArrayBase = reinterpret_cast<char*>(
      *reinterpret_cast<int*>(reinterpret_cast<char*>(g_pGlobalMapState) + 0xc));
  tileArrayBase[0x16 + static_cast<short>(tileIndex) * 0x24] = static_cast<char>(stateByte);
  if (g_pUiRuntimeContext != 0) {
    void** observerSlot =
        reinterpret_cast<void**>(reinterpret_cast<char*>(g_pUiRuntimeContext) + 0xf0);
    if (*observerSlot != 0) {
      reinterpret_cast<void(__fastcall*)(void*, int)>(*reinterpret_cast<int*>(
          *reinterpret_cast<int*>(*observerSlot) + 0x1d8))(*observerSlot, tileIndex);
    }
  }
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
  int** slotTable = reinterpret_cast<int**>(field38);
  unsigned int slotCount = static_cast<unsigned int>(field40);

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
            *reinterpret_cast<unsigned short*>(
                *reinterpret_cast<int*>(reinterpret_cast<char*>(g_pGlobalMapState) + 0xc) + 0x1a +
                sVarSlotId * 0x24) = 0xffff;
          }
          key_id = key_id + 1;
          nSlotsRemaining = nSlotsRemaining - 1;
        } while (nSlotsRemaining != 0);
      } else {
        sVarSlotId = GetActiveNationSlotTile();
        SetMapTileStateByteAndNotifyObserver(sVarSlotId, 7);
        *reinterpret_cast<unsigned short*>(
            *reinterpret_cast<int*>(reinterpret_cast<char*>(g_pGlobalMapState) + 0xc) + 0x1a +
            sVarSlotId * 0x24) = 0xffff;
      }
    }
  }

  sVarActiveSlot = g_pUiRuntimeContext->GetActiveNationId();
  if (sVarActiveSlot == -1) {
    sVarActiveSlot = g_pUiRuntimeContext->GetActiveNationId();
  }

  if ((field10 & (1U << ((unsigned char)sVarActiveSlot & 0x1f))) != 0) {
    for (pvNode = reinterpret_cast<void*>(thunk_GetNavyPrimaryOrderListHead()); pvNode != 0;
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

// FUNCTION: IMPERIALISM 0x00562d90
void TMapOrderContext::InitializeMapActionContextsForNationCountUsingCostField(int nationCountArg) {
  int* countHeader;
  TMapNationActionContext* contextBase;
  undefined4* costField;
  int relaxPassCount;
  int nationIndex;
  int contextStride;

  nationCount = static_cast<short>(nationCountArg);
  if (contextArray != 0) {
    reinterpret_cast<void(__fastcall*)(TMapNationActionContext*, int, int)>(
        *reinterpret_cast<int*>(contextArray) + 4)(contextArray, 0, 3);
  }
  countHeader = reinterpret_cast<int*>(AllocateWithFallbackHandler(
      static_cast<undefined4>(static_cast<int>(static_cast<short>(nationCountArg)) * 0x48 + 4)));
  if (countHeader == 0) {
    contextBase = 0;
  } else {
    contextBase = reinterpret_cast<TMapNationActionContext*>(countHeader + 1);
    *countHeader = static_cast<int>(static_cast<short>(nationCountArg));
    reinterpret_cast<void(__stdcall*)(int, int, int, int, int)>(CallCallbackRepeatedly)(
        reinterpret_cast<int>(contextBase), 0x48,
        static_cast<int>(static_cast<short>(nationCountArg)), 0x0040405c, 0x00407775);
  }
  contextArray = contextBase;
  if (contextBase == 0) {
    GAME_FAIL_NIL_POINTER();
  }
  costField = reinterpret_cast<undefined4*>(AllocateWithFallbackHandler(0xca8 * 4));
  {
    undefined4* clearCursor = costField;
    for (int clearIndex = 0xca8; clearIndex != 0; clearIndex = clearIndex - 1) {
      *clearCursor = 0;
      clearCursor = clearCursor + 1;
    }
  }
  relaxPassCount = reinterpret_cast<int(__cdecl*)(int)>(
      thunk_RelaxMapTileCostFieldByNeighborTerrain)(reinterpret_cast<int>(costField));
  while (relaxPassCount != 0) {
    relaxPassCount = reinterpret_cast<int(__cdecl*)(int)>(
        thunk_RelaxMapTileCostFieldByNeighborTerrain)(reinterpret_cast<int>(costField));
  }
  nationIndex = 0;
  if (0 < static_cast<int>(static_cast<short>(nationCountArg))) {
    contextStride = 0;
    do {
      reinterpret_cast<void(__cdecl*)(int, int)>(thunk_SelectBestSeedTileForNationFromCostField)(
          reinterpret_cast<int>(costField), nationIndex + 0x17);
      reinterpret_cast<TZone*>(reinterpret_cast<char*>(contextArray) + contextStride)
          ->SetMapActionContextTargetTileAndRefreshMarkers(nationIndex + 0x17, 0xffff);
      nationIndex = nationIndex + 1;
      contextStride = contextStride + 0x48;
    } while (nationIndex < static_cast<int>(static_cast<short>(nationCountArg)));
  }
  FreeHeapBufferIfNotNull(reinterpret_cast<undefined4>(costField));
}

// FUNCTION: IMPERIALISM 0x005634a0
void* TMapOrderContext::FindPortZoneBySelectedTile(TCity* city) {
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
