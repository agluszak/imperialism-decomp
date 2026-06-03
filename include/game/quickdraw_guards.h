#pragma once

// QuickDraw scoped guards (stack RAII objects modeled so MSVC reproduces the
// original C++ EH frames that wrap QuickDraw drawing bodies) plus the fill-color
// helper. Extracted from ui_widget_shared.h.

#include "decomp_types.h"

// Reusable QuickDraw clip-surface guard. The constructor reuses a cached surface
// wrapper (global free-list head) or allocates a new one; the destructor caches
// this surface if none is cached, otherwise frees it. Modeled as a stack RAII
// object so MSVC reproduces the original C++ EH frame that wraps QuickDraw
// drawing bodies. ctor: 0x00497320, dtor: 0x00497390 (defined in trade_screen.cpp).
struct QuickDrawSurfaceGuard {
  int surfaceWrapper;
  QuickDrawSurfaceGuard();
  ~QuickDrawSurfaceGuard();
};

undefined4 thunk_ConstructScopedMapQuickDrawContext(void);
undefined4 thunk_DestroyScopedMapQuickDrawContext(void);

// Scoped map QuickDraw context guard. This is a separate RAII family from
// QuickDrawSurfaceGuard and appears in animation/render wrappers.
struct ScopedMapQuickDrawContextGuard {
  int storage[6];

  explicit ScopedMapQuickDrawContextGuard(void* renderTarget) {
    reinterpret_cast<void(__fastcall*)(ScopedMapQuickDrawContextGuard*, int, int)>(
        thunk_ConstructScopedMapQuickDrawContext)(this, 0, reinterpret_cast<int>(renderTarget));
  }

  ~ScopedMapQuickDrawContextGuard() {
    reinterpret_cast<void(__cdecl*)()>(thunk_DestroyScopedMapQuickDrawContext)();
  }
};

void __cdecl SetQuickDrawFillColor(int fillColor);
