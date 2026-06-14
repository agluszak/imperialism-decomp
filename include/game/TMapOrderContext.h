#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/TZone.h"

class TCity;

// Map-order runtime singleton (g_pActiveMapOrderContext @ 0x6a3fbc).
// Ghidra historically labeled this InputState for container-level methods.
// Vtable 0x0065c7c8 is a stub installed at allocation; the full zone family
// uses TZone vtable 0x0065c6d8 on constructed nodes.
// VTABLE: IMPERIALISM 0x0065c7c8
class TMapOrderContext {
public:
  short nationCount;           // +0x04
  TMapNationActionContext* contextArray; // +0x08
  short field0c;               // +0x0c
  char pad0e[2];             // +0x0e
  unsigned short keyMask;      // +0x10
  char pad12[0x26];          // +0x12 .. +0x37
  int* slotTable;              // +0x38
  unsigned int slotCount;      // +0x40
  char pad44[0x14];          // +0x44 .. +0x57 (allocation size TBD)

  void InitializeMapActionContextsForNationCountUsingCostField(int nationCountArg);

  // 0x005634a0 — walks g_pMapActionContextListHead for TPortZone tile-id match.
  void* FindPortZoneBySelectedTile(TCity* city);
};

void SetMapTileStateByteAndNotifyObserver(int tileIndex, int stateByte);
int ComputeGlobalMapActionContextNodeValueAverage(void);
