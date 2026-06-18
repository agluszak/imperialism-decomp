#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/TObject.h"
#include "game/TZone.h"

class TCity;

// TOcean map-order runtime singleton (g_pActiveMapOrderContext @ 0x6a3fbc).
// Ghidra historically labeled this InputState for container-level methods.
// Vtable 0x0065c7c8 is a stub installed at allocation; the full zone family
// uses TZone vtable 0x0065c6d8 on constructed nodes.
// VTABLE: IMPERIALISM 0x0065c7c8
class TOcean : public TObject {
public:
  short nationCount;                     // +0x04
  TMapNationActionContext* contextArray; // +0x08
  short field0c;                         // +0x0c
  char pad0e[2];                         // +0x0e
  unsigned short keyMask;                // +0x10
  char pad12[0x26];                      // +0x12 .. +0x37
  int* slotTable;                        // +0x38
  unsigned int slotCount;                // +0x40
  char pad44[0x14];                      // +0x44 .. +0x57 (allocation size TBD)

  void InitializeMapActionContextsForNationCountUsingCostField(int nationCountArg);

  // 0x005634a0 — walks g_pMapActionContextListHead for TPortZone tile-id match.
  void* FindPortZoneBySelectedTile(TCity* city);
};

void SetMapTileStateByteAndNotifyObserver(int tileIndex, int stateByte);
int ComputeGlobalMapActionContextNodeValueAverage(void);

// GLOBAL: IMPERIALISM 0x006a3fbc
extern TOcean* g_pActiveMapOrderContext;

// === BEGIN GENERATED (TOcean) — refreshed by `just gen-class TOcean`; do not hand-edit ===
// clang-format off
// vtable @ 0x0065c7c8 (7 slots), object size 0x18, base TObject
//   slot 0x00  byte 0x00  0x00562190  new       GetTOceanClassNamePointer
//   slot 0x01  byte 0x04  0x00562140  new       DestroyTPortZoneManager
//   slot 0x02  byte 0x08  0x00485e90  new       GetTTaskClassNamePointer
//   slot 0x03  byte 0x0c  0x00412bf0  new       ConstructTTaskBaseState
//   slot 0x04  byte 0x10  0x00412c10  new       GetTEventHandlerClassNamePointer
//   slot 0x05  byte 0x14  0x005628f0  new       SerializeMapActionContextRuntimeState
//   slot 0x06  byte 0x18  0x00562340  new       DeserializeMapActionContextRuntimeState
// object size 0x18 (RTTI) unverified against the header layout;
// set curated.layout.size_verified to emit a sizeof static_assert.
// clang-format on
// === END GENERATED (TOcean) ===
