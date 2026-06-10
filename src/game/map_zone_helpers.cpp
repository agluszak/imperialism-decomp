#include "game/TZone.h"
#include "game/TGlobalMapState.h"
#include "game/CObject.h"
#include "game/CRuntimeClass.h"

extern "C" void* g_pMapActionContextListHead;
extern "C" char g_pClassDescTPortZone;

static int ZoneIsPortKind(TZone* node) {
  return reinterpret_cast<CObject*>(node)->IsKindOf(
      reinterpret_cast<const CRuntimeClass*>(&g_pClassDescTPortZone));
}

// FUNCTION: IMPERIALISM 0x00563540
#pragma optimize("y", on)
TZone* FindFirstPortZoneContextByNation(short nationSlot) {
  TZone* esi = static_cast<TZone*>(g_pMapActionContextListHead);
  if (esi != 0) {
    do {
      if (ZoneIsPortKind(esi) != 0) {
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
    int tileIndex = static_cast<int>(static_cast<short>(eax->field48));
    tileIndex = tileIndex + tileIndex * 8;
    char* terrainTable = reinterpret_cast<char*>(g_pGlobalMapState->terrainStateTable);
    short ownerTag = static_cast<short>(
        static_cast<signed char>(terrainTable[tileIndex * 4 + 3]));
    if (ownerTag == nationSlot) {
      return eax;
    }

    esi = eax->prev18;
    if (esi != 0) {
      do {
        if (ZoneIsPortKind(esi) != 0) {
          break;
        }
        esi = esi->prev18;
      } while (esi != 0);
    }
    eax = esi;
  } while (eax != 0);

  return 0;
}
#pragma optimize("", on)
