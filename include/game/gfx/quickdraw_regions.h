#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/mfc.h"

// Windows reimplementation of the Mac QuickDraw region API (original TU:
// D:\Ambit\QuickDraw.cpp — the debug path baked into this cluster). The Mac
// `Region` record is emulated with an embedded MFC CRgn; `RgnHandle` keeps the
// Mac Region** handle shape (call sites re-dereference the handle on every
// access, exactly like the original Toolbox contract).

struct TBitmapSurfaceNode;

struct Region {
  RECT rgnBBox;         // +0x00 bounding box, refreshed via ::GetRgnBox
  int attachRegistered; // +0x10 BOOL result of CRgn::Attach in the ctor / RectRgn
  CRgn rgn;             // +0x14 the real GDI region (m_hObject at +0x18)

  Region();                  // 0x004954a0
  ~Region();                 // 0x00495520
  void RefreshBoundingBox(); // 0x004955f0
};
ASSERT_SIZE(Region, 0x1c);

typedef Region** RgnHandle;

// Mac QuickDraw API surface (names follow Inside Macintosh; QD prefix only where
// a Win32 name collides).
void InitializeCityBuildingControlRegions_Impl(RgnHandle region, int x, int y); // 0x00497b30
RgnHandle NewRgn(void);                                                         // 0x00495820
RgnHandle DisposeRgn(RgnHandle rgn);                                            // 0x00495610
void RectRgn(RgnHandle rgn, RECT* rect);                                        // 0x004958e0
void GetClip(RgnHandle rgn);                                                    // 0x00495920
void SetClip(RgnHandle rgn);                                                    // 0x00495a30
void ClipRect(RECT* rect);                                                      // 0x00495a80
void UnionRgn(RgnHandle srcA, RgnHandle srcB, RgnHandle dst);                   // 0x004977a0
void SetEmptyRgn(RgnHandle rgn);                                                // 0x00497810
void QDFrameRgn(RgnHandle rgn);                                                 // 0x00497860
// Combine two clip regions into dst (empty/copy/RGN_DIFF cases) and refresh its box. 0x00497540
void CombineClipRegionsWithEmptyHandling(RgnHandle srcA, RgnHandle srcB, RgnHandle dst);
// Fill the region with a solid foreground-color brush (CBrush(COLORREF) form). 0x00497940
void FillClipRegionWithForegroundBrush(RgnHandle rgn);
// Fill the region's interior with the current QuickDraw foreground color. 0x00497a10
void QDPaintRgn(RgnHandle rgn);
// Intersect the clip region with `rect` (RGN_AND) and refresh its bounding box. 0x00498070
void IntersectClipRegionWithRectAndUpdateBounds(RgnHandle clipRgn, RECT* rect);
void SetRectRgn(RgnHandle rgn, short left, short top, short right,
                short bottom);              // 0x00498be0
void CopyRgn(RgnHandle src, RgnHandle dst); // 0x00497bb0
void OpenRgn(void);                         // 0x00497f60
void CloseRgn(RgnHandle dst);               // 0x00497f90
void QDFrameRect(RECT* rect);               // 0x00498180 (Win32 ::FrameRect collides)
unsigned char EmptyRgn(RgnHandle rgn);      // 0x00498aa0
int PtInRgn(CPoint* point, RgnHandle rgn);  // 0x00495650
// QuickDraw MapPt: rescale a point from srcRect's space into dstRect's, per axis.
void MapPt(int* point, RECT* srcRect, RECT* dstRect); // 0x004956e0
// Byte-identical unfolded second copy kept by the retail image.
void MapPtSecondCopy(int* point, RECT* srcRect, RECT* dstRect); // 0x00495780
int SectRect(RECT* src1, RECT* src2, RECT* dst);                // 0x00498bb0
int BitMapToRegion(RgnHandle rgn, TBitmapSurfaceNode* surface); // 0x00497ef0
void DisposeTemporaryRegionCache(void);                         // 0x004974f0

// 0x498b10: copies rect to a local and returns IsRectEmpty of the copy.
int ProbeRectEmptyAfterCopyToLocal(RECT* rect);
