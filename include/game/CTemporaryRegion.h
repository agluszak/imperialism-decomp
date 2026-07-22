#pragma once

#include "decomp_types.h"
#include "game/quickdraw_regions.h"

// Mac-oracle class (CW symbols: CTemporaryRegion ctor/dtor/Cleanup): a stack-scoped
// QuickDraw region handle with a one-slot reuse cache (g_pTemporaryRegionCache) so
// per-paint users don't churn NewRgn/DisposeRgn. Paint paths GetClip into it and
// SetClip from it around scoped drawing.
struct CTemporaryRegion {
  RgnHandle tempRgn;
  CTemporaryRegion();  // 0x00497320
  ~CTemporaryRegion(); // 0x00497390
};
