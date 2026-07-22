// TOcean::AllocateRouteNodeStateBufferByCount (0x0052e7b0) -- a UOcean.h helper that resizes
// the map-order singleton's route-node buffer to hold `count` 0x10-byte route records. Kept in
// its own translation unit (UMapper/UOcean route cluster) alongside the route rebuild pass.

#include "game/TOcean.h"

#include "decomp_types.h"
#include "game/global_data_tables.h"
#include "game/mfc.h"
#include "game/ui_invalidation_guard.h"

// FUNCTION: IMPERIALISM 0x0052e7b0
void TOcean::AllocateRouteNodeStateBufferByCount(short count) {
  routeNodeCount = count;
  delete[] routeSegments;
  routeSegments = new CRect[count];
  if (routeSegments == nullptr) {
    routeSegments = nullptr;
  }
  if (routeSegments == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag("D:\\Ambit\\Cross\\UOcean.h", 0x1e7);
  }
}

// FUNCTION: IMPERIALISM 0x00563330
TZone* TOcean::GetMapActionContextEntryByIndex(short index) {
  return contextArray + index;
}
