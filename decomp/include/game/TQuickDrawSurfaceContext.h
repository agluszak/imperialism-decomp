#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/mfc.h"
#include "game/gfx/quickdraw_regions.h"

class CDib;

struct TQuickDrawBlitSurface {
  unsigned char* pixelBits; // +0x00 — 8-bpp indexed pixels
  short stride;             // +0x04
  short pad06;              // +0x06
  RECT clipRect;            // +0x08
  short field18;            // +0x18
  short pad1a;              // +0x1a
  CDib* surfaceDib;         // +0x1c
  void* surfaceObject;      // +0x20
  COLORREF foregroundColor; // +0x24 -- current QuickDraw/GDI foreground color
  COLORREF backgroundColor; // +0x28 -- current background / transparent-pixel color
};
ASSERT_SIZE(TQuickDrawBlitSurface, 0x2c);

struct TQuickDrawSurfaceContext {
  int field00;
  TQuickDrawBlitSurface blitSurface; // +0x4

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
  CRect bounds;                                            // +0x08
  short bitDepth;                                          // +0x18
  short pad1a;                                             // +0x1a alignment filler before `dib`
  CDib* dib;                                               // +0x1c
  TBitmapSurfaceNode();                                    // 0x00495cc0
  TBitmapSurfaceNode(int width, int height, int bitDepth); // 0x00495d00
};
ASSERT_SIZE(TBitmapSurfaceNode, 0x20);

struct TBitmapSurfaceContextDescriptor : public TQuickDrawSurfaceContext {
  const char* debugSourcePath; // +0x30

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
