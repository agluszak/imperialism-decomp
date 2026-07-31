#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/mfc.h"
#include "game/gfx/quickdraw_regions.h"

class CDib;

// Surface body at TQuickDrawSurfaceContext+0x4 (astruct_17/astruct_18 in Ghidra).
// BlitRectWithOptionalTransparency receives a pointer to this subobject and reads both
// its leading pixel buffer/stride and its backing CDib at +0x1c. Original init
// (0x495eb0) stores the DIB-section bits pointer and the dword-aligned 8bpp row stride
// ((biWidth + 3) & ~3).
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

// Runtime QuickDraw surface context (primary / active / transient). The blit subobject
// at +0x4 is what callers historically reached via `context + 4`.
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
  // pad06: alignment filler after `stride`, matching the sibling TQuickDrawBlitSurface's
  // pad06 at the same {pixelBits, stride, pad} layout (see above); never written by the
  // constructor (0x00495d00).
  short pad06;
  // The constructors treat +0x08..+0x17 as one rectangle: the default overload builds an
  // empty CRect, while the allocating overload sets {0,0,width,height} from the CDib.
  CRect bounds; // +0x08
  // bitDepth18: the constructor (0x00495d00) stores the low 16 bits of its third argument
  // (the bit-depth passed to `new CDib(width, height, bitDepth)`) here via a 16-bit write
  // `MOV word ptr [ESI+0x18], BX` -- so this is a `short`, not the DIB-derived height. The
  // legacy name "requestedHeight18" was wrong: BX holds arg3 (bitDepth), not the height. No
  // observed read site.
  short bitDepth18;                                        // +0x18
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

// Address markers: src/game/global_data_tables.cpp.

// Core QuickDraw surface blitter (memory-to-memory row copy, with an 0x24-flagged
// transparent-color-skip variant; a GDI/CDC-based path handles the real-screen
// sentinel surface or a caller-supplied QuickDraw region). 0x00496d40
void __cdecl BlitRectWithOptionalTransparency(TQuickDrawBlitSurface* srcSurface,
                                              TQuickDrawBlitSurface* dstSurface, RECT* srcRect,
                                              RECT* dstRect, unsigned char blitFlags,
                                              RgnHandle clipRegion);

static __inline void BlitQuickDrawSurfaces(TQuickDrawBlitSurface* srcSurface,
                                           TQuickDrawBlitSurface* dstSurface, RECT* srcRect,
                                           RECT* dstRect, unsigned char blitFlags) {
  BlitRectWithOptionalTransparency(srcSurface, dstSurface, srcRect, dstRect, blitFlags, 0);
}
