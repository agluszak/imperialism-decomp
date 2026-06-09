#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/CClientDC.h"
#include "game/TView.h"

struct ScopedMapQuickDrawContext {
  CClientDC clientDc;
  TView* renderTarget;

  explicit ScopedMapQuickDrawContext(void* renderTarget);
  ~ScopedMapQuickDrawContext();

  int* IntersectClipRectOnPrimaryAndSecondaryDc(int* clipRect);
};

ASSERT_SIZE(ScopedMapQuickDrawContext, 0x18);

typedef ScopedMapQuickDrawContext ScopedMapQuickDrawContextGuard;
