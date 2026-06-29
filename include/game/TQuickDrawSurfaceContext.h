#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/mfc.h"

class CDib;

// Nested blit target at parent+0x4 (astruct_18 / Ghidra). Passed as the first two
// operands to BlitRectWithOptionalTransparency.
struct TQuickDrawBlitSurface {
  int field00;
  int hdcOrBitmapHandle; // +0x4
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
  int flipDescriptor;       // +0x20
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

undefined4 BlitRectWithOptionalTransparency(void);

static __inline void BlitQuickDrawSurfaces(TQuickDrawBlitSurface* srcSurface,
                                           TQuickDrawBlitSurface* dstSurface, RECT* srcRect,
                                           RECT* dstRect, unsigned char blitFlags) {
  reinterpret_cast<void(__cdecl*)(void*, void*, RECT*, RECT*, int, int)>(
      reinterpret_cast<void (*)()>(BlitRectWithOptionalTransparency))(
      srcSurface, dstSurface, srcRect, dstRect, (int)blitFlags, 0);
}
