#pragma once

#include "decomp_types.h"
#include "game/ClipStateRegion.h"
#include "game/global_data_tables.h"

struct QuickDrawSurfaceGuard {
  ClipStateRegionWrapper* surfaceWrapper;
  QuickDrawSurfaceGuard();
  ~QuickDrawSurfaceGuard();
};
