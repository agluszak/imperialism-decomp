#include "game/TMapOrderContext.h"

#include "game/CObject.h"
#include "game/CRuntimeClass.h"
#include "game/TCity.h"

extern "C" {
extern void* g_pMapActionContextListHead; // 0x6a3fc8
}

// GLOBAL: IMPERIALISM 0x0065c618
extern "C" char g_pClassDescTPortZone = 0;

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

// FUNCTION: IMPERIALISM 0x005634a0
#pragma optimize("y", on)
void* TMapOrderContext::FindPortZoneBySelectedTile(TCity* relationManager) {
  short selectedTileId;
  if (relationManager->selectedOrderB0 == 0) {
    selectedTileId = 1;
  } else {
    selectedTileId = *reinterpret_cast<short*>(
        reinterpret_cast<char*>(relationManager->selectedOrderB0) + 0x14);
  }
  MapActionNodeView* node = static_cast<MapActionNodeView*>(g_pMapActionContextListHead);
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
#pragma optimize("", on)
