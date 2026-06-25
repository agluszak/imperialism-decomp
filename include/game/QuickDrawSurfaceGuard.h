#pragma once

#include "decomp_types.h"
#include "game/ClipStateRegion.h"

extern void* g_pReusableQuickDrawSurfaceListHead;

struct QuickDrawSurfaceGuard {
  ClipStateRegionWrapper* surfaceWrapper;
  QuickDrawSurfaceGuard();
  ~QuickDrawSurfaceGuard();
};
