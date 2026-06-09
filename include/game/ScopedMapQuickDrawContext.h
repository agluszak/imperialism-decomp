#pragma once

#include "decomp_types.h"

struct ScopedMapQuickDrawContext {
  int storage[6];

  explicit ScopedMapQuickDrawContext(void* renderTarget);
  ~ScopedMapQuickDrawContext();
};

typedef ScopedMapQuickDrawContext ScopedMapQuickDrawContextGuard;
