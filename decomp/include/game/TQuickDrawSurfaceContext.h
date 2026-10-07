#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/mfc.h"
#include "game/gfx/quickdraw_regions.h"

class CDib;

struct TQuickDrawBlitSurface {
  unsigned char* pixelBits; // 8-bpp indexed pixels
  short stride;
  short pad06;
  RECT clipRect;
  short field18;
  short pad1a;
  CDib* surfaceDib;
  void* surfaceObject;
  COLORREF foregroundColor; // current QuickDraw/GDI foreground color
  COLORREF backgroundColor; // current background / transparent-pixel color
};
ASSERT_SIZE(TQuickDrawBlitSurface, 0x2c);

struct TQuickDrawSurfaceContext {
  int field00;
  TQuickDrawBlitSurface blitSurface;

  ~TQuickDrawSurfaceContext();

  TQuickDrawBlitSurface* GetBlitSurface() {
    return &blitSurface;
  }
  const TQuickDrawBlitSurface* GetBlitSurface() const {
    return &blitSurface;
  }
};
ASSERT_SIZE(TQuickDrawSurfaceContext, 0x30);

void DisposeGWorld(TQuickDrawSurfaceContext* surface);

struct TBitmapSurfaceNode {
  unsigned char* pixelBits;
  short stride;
  short pad06;
  CRect bounds;
  short bitDepth;
  short pad1a; // +0x1a alignment filler before `dib`
  CDib* dib;
  TBitmapSurfaceNode();
  TBitmapSurfaceNode(int width, int height, int bitDepth);
};
ASSERT_SIZE(TBitmapSurfaceNode, 0x20);

struct TBitmapSurfaceContextDescriptor : public TQuickDrawSurfaceContext {
  const char* debugSourcePath;

  TBitmapSurfaceContextDescriptor();
  bool InitializeSurfaceNode(int width, int height, int bitDepth);

  TBitmapSurfaceNode** GetPixMapHandle() const {
    return static_cast<TBitmapSurfaceNode**>(blitSurface.surfaceObject);
  }

  void SetPixMapHandle(TBitmapSurfaceNode** slot) {
    blitSurface.surfaceObject = slot;
  }

  TBitmapSurfaceNode* GetPixMap() const {
    TBitmapSurfaceNode** slot = GetPixMapHandle();
    return slot != 0 ? *slot : 0;
  }
};
ASSERT_SIZE(TBitmapSurfaceContextDescriptor, 0x34);

void __cdecl BlitRectWithOptionalTransparency(TQuickDrawBlitSurface* srcSurface,
                                              TQuickDrawBlitSurface* dstSurface, RECT* srcRect,
                                              RECT* dstRect, unsigned char blitFlags,
                                              RgnHandle clipRegion = 0);
