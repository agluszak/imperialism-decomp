#pragma once

#include "decomp_types.h"
#include "game/win_rect.h"

// Nested blit target at parent+0x4 (astruct_18 / Ghidra). Passed as the first two
// operands to BlitRectWithOptionalTransparency.
struct TQuickDrawBlitSurface {
  int field00;
  int hdcOrBitmapHandle; // +0x4
};

// Runtime QuickDraw surface context (primary / active / transient). The blit subobject
// at +0x4 is what callers historically reached via `context + 4`.
struct TQuickDrawSurfaceContext {
  int field00;
  TQuickDrawBlitSurface blitSurface; // +0x4
  char pad08[4];
  RECT clipRect; // +0x0c
  char pad1c[4];
  int flipDescriptor; // +0x20
  char pad24[4];
  int quickDrawColor; // +0x28
  int transparentBlitColor; // +0x2c

  TQuickDrawBlitSurface* GetBlitSurface() { return &blitSurface; }
  const TQuickDrawBlitSurface* GetBlitSurface() const { return &blitSurface; }
};

// GLOBAL: IMPERIALISM 0x006a1d60
extern TQuickDrawSurfaceContext* g_pActiveQuickDrawSurfaceContext;
// GLOBAL: IMPERIALISM 0x006a30a8
extern TQuickDrawSurfaceContext* g_pPrimaryRenderSurfaceContext;

undefined4 BlitRectWithOptionalTransparency(void);

static __inline void BlitQuickDrawSurfaces(TQuickDrawBlitSurface* srcSurface,
                                           TQuickDrawBlitSurface* dstSurface, RECT* srcRect,
                                           RECT* dstRect, unsigned char blitFlags) {
  reinterpret_cast<void(__cdecl*)(void*, void*, RECT*, RECT*, int, int)>(
      reinterpret_cast<void(*)()>(BlitRectWithOptionalTransparency))(srcSurface, dstSurface, srcRect, dstRect, (int)blitFlags, 0);
}
