#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/mfc.h"

struct ClipStateRegionInner {
  char prefix[0x10];
  int attachRegistered;
  CBrush brush;
};

ASSERT_SIZE(ClipStateRegionInner, 0x1c);

struct ClipStateRegionWrapper {
  ClipStateRegionInner* inner;
};

ClipStateRegionWrapper* CreateClipStateRegionWrapperObject(void);
undefined4 DestroyClipStateRegionWrapperObject(ClipStateRegionWrapper* wrapperObject);
int IntersectRectWrapper(RECT* src1, RECT* src2, RECT* dst);
