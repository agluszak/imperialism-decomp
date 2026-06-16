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

undefined4 CreateClipStateRegionWrapperObject(void);
undefined4 DestroyClipStateRegionWrapperObject(int* wrapperObject);
