#pragma once

#include "decomp_types.h"

extern void* g_pReusableQuickDrawSurfaceListHead;

struct QuickDrawSurfaceGuard {
  int surfaceWrapper;
  QuickDrawSurfaceGuard();
  ~QuickDrawSurfaceGuard();
};
