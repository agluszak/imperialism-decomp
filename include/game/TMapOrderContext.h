#pragma once

// Map-order runtime context singleton (g_pActiveMapOrderContext @ 0x6a3fbc). Only the
// port-zone lookup is recovered so far; the call sites dispatch it as a thiscall
// method on the context even though the body never reads `this`.
class TMapOrderContext {
public:
  // 0x005634a0 — walks the map-action node chain (g_pMapActionContextListHead) for
  // TPortZone nodes whose tile-id fields match the relation manager's selected order
  // tile (or tile 1 when no order is selected).
  void* FindPortZoneBySelectedTile(class TRelationManager* relationManager);
};
