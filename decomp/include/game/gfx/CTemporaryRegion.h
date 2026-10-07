#pragma once

#include "decomp_types.h"
#include "game/gfx/quickdraw_regions.h"

struct CTemporaryRegion {
  RgnHandle tempRgn;
  CTemporaryRegion();
  ~CTemporaryRegion();
};
