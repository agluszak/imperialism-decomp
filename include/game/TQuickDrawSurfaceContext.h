#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/mfc.h"

class CDib;

// Nested blit target at parent+0x4 (astruct_18 / Ghidra). Passed as the first two
// operands to BlitRectWithOptionalTransparency. Original init (0x495eb0) stores the
// DIB-section bits pointer and the dword-aligned 8bpp row stride ((biWidth + 3) & ~3).
struct TQuickDrawBlitSurface {
  void* pixelBits; // +0x0
  short stride;    // +0x4
  short pad06;
};
ASSERT_SIZE(TQuickDrawBlitSurface, 0x8);

// Runtime QuickDraw surface context (primary / active / transient). The blit subobject
// at +0x4 is what callers historically reached via `context + 4`.
struct TQuickDrawSurfaceContext {
  int field00;
  TQuickDrawBlitSurface blitSurface; // +0x4
  RECT clipRect;                     // +0x0c
  short field1c;                     // +0x1c
  short pad1e;
  CDib* surfaceDib;         // +0x20 — backing CDib (0x495eb0 stores node->dib here)
  void* surfaceObject;      // +0x24
  int quickDrawColor;       // +0x28
  int transparentBlitColor; // +0x2c

  TQuickDrawBlitSurface* GetBlitSurface() {
    return &blitSurface;
  }
  const TQuickDrawBlitSurface* GetBlitSurface() const {
    return &blitSurface;
  }
};
ASSERT_SIZE(TQuickDrawSurfaceContext, 0x30);

struct TBitmapSurfaceNode {
  void* pixelBits;
  short stride;
  short field06;
  int field08;
  int field0c;
  int field10;
  int field14;
  int field18;
  CDib* dib;
};
ASSERT_SIZE(TBitmapSurfaceNode, 0x20);

struct TBitmapSurfaceContextDescriptor : public TQuickDrawSurfaceContext {
  const char* debugSourcePath; // +0x30

  void Reset();
  bool InitializeSurfaceNode(int width, int height, int bitDepth);
  void ReleaseSurfaceNode();

  TBitmapSurfaceNode** GetSurfaceNodeSlot() const {
    return static_cast<TBitmapSurfaceNode**>(surfaceObject);
  }

  void SetSurfaceNodeSlot(TBitmapSurfaceNode** slot) {
    surfaceObject = slot;
  }

  TBitmapSurfaceNode* GetSurfaceNode() const {
    TBitmapSurfaceNode** slot = GetSurfaceNodeSlot();
    return slot != 0 ? *slot : 0;
  }
};
ASSERT_SIZE(TBitmapSurfaceContextDescriptor, 0x34);

// Address markers: src/game/global_data_tables.cpp.

// Core QuickDraw surface blitter (memory-to-memory row copy, with an 0x24-flagged
// transparent-color-skip variant; a GDI/CDC-based path handles the real-screen
// sentinel surface or a caller-supplied clip region). renderCtx's real type isn't
// recovered; every current caller passes null. 0x00496d40
void __stdcall BlitRectWithOptionalTransparency(TQuickDrawBlitSurface* srcSurface,
                                                TQuickDrawBlitSurface* dstSurface, RECT* srcRect,
                                                RECT* dstRect, unsigned char blitFlags,
                                                void* renderCtx);

static __inline void BlitQuickDrawSurfaces(TQuickDrawBlitSurface* srcSurface,
                                           TQuickDrawBlitSurface* dstSurface, RECT* srcRect,
                                           RECT* dstRect, unsigned char blitFlags) {
  BlitRectWithOptionalTransparency(srcSurface, dstSurface, srcRect, dstRect, blitFlags, 0);
}
