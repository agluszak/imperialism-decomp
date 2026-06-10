#include "game/CObject.h"
#include "game/CRuntimeClass.h"
#include "game/TGlobalMapState.h"
#include "game/TMapOrderContext.h"
#include "game/TZone.h"

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

extern "C" {
extern void* g_pMapActionContextListHead;
extern void* g_pActiveMapOrderContext;
extern char g_pClassDescTPortZone;
}

undefined4 thunk_StepHexTileIndexByDirectionWithWrapRules(void);
undefined4 GetNextPortZone(void);

namespace {

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

// FUNCTION: IMPERIALISM 0x0055ff70
int ScoreCoastalTileForContextAndCityStateAffinity(int tileIndex, int contextZone, int contextCityState) {
  char* mapTileBase =
      reinterpret_cast<char*>(*reinterpret_cast<int*>(reinterpret_cast<char*>(g_pGlobalMapState) + 0xc));
  char* tileRecord = mapTileBase + static_cast<short>(tileIndex) * 0x24;
  if (tileRecord[0] != static_cast<char>(0x05)) {
    return 0;
  }
  if (tileRecord[0x16] != static_cast<char>(-1)) {
    return 0;
  }
  short nationId = static_cast<short>(tileRecord[4]);
  int zoneRecord = 0;
  if (nationId >= 0x17) {
    zoneRecord = reinterpret_cast<int>(static_cast<TMapOrderContext*>(g_pActiveMapOrderContext)->contextArray) +
                 (nationId - 0x17) * 0x48;
  }
  if (zoneRecord != contextZone) {
    return 0x3e8;
  }

  int score = 0x1388;
  int neighborDir = 0;
  do {
    short neighborTile = reinterpret_cast<short(__cdecl*)(int, int)>(thunk_StepHexTileIndexByDirectionWithWrapRules)(
        tileIndex, neighborDir);
    if (neighborTile != -1) {
      char* neighborRecord = mapTileBase + neighborTile * 0x24;
      if (neighborRecord[0] == static_cast<char>(0x05)) {
        short neighborSubtype = static_cast<short>(neighborRecord[0x16]);
        if ((neighborSubtype == 3) || (neighborSubtype == 0x0e)) {
          MapActionNodeView* portZone = static_cast<MapActionNodeView*>(g_pMapActionContextListHead);
          while (portZone != 0 &&
                 portZone->IsKindOf(reinterpret_cast<const CRuntimeClass*>(&g_pClassDescTPortZone)) == 0) {
            portZone = portZone->next18;
          }
          while (portZone != 0) {
            if ((portZone->tileId0c == neighborTile) || (portZone->tileId20 == neighborTile) ||
                (portZone->tileId48 == neighborTile)) {
              break;
            }
            portZone = static_cast<MapActionNodeView*>(
                reinterpret_cast<void*(__fastcall*)(void*)>(GetNextPortZone)(portZone));
          }
          int portZoneRecord = reinterpret_cast<int>(portZone);
          if (portZoneRecord != contextZone) {
            score = score - 1;
          }
        } else {
          short cityStateLink = *reinterpret_cast<short*>(neighborRecord + 0x14);
          int cityStateRecord = 0;
          if (cityStateLink != -1) {
            cityStateRecord = *reinterpret_cast<int*>(reinterpret_cast<char*>(g_pGlobalMapState) + 0x10) +
                              cityStateLink * 0xa8;
          }
          if (cityStateRecord == contextCityState) {
            score = score + 0x64;
          } else {
            score = score - 0xa;
          }
        }
      }
    }
    neighborDir = neighborDir + 1;
  } while (neighborDir < 6);

  return score;
}
