#pragma once

#include "compat.h"
#include "decomp_types.h"
#include "game/mfc.h"

// Windows reimplementation of the Mac QuickDraw region API: Region wraps an MFC CRgn and
// RgnHandle keeps the Mac Region** shape.

struct TBitmapSurfaceNode;

struct Region {
  RECT rgnBBox;         // +0x00 bounding box, refreshed via ::GetRgnBox
  int attachRegistered; // +0x10 BOOL result of CRgn::Attach in the ctor / RectRgn
  CRgn rgn;             // +0x14 the real GDI region (m_hObject at +0x18)

  Region();
  ~Region();
  BOOL ReplaceWithRect(const RECT* rect);
  void RefreshBoundingBox();
};
ASSERT_SIZE(Region, 0x1c);

typedef Region** RgnHandle;

void OffsetRgn(RgnHandle region, int horizontalOffset, int verticalOffset);
void RefreshRgnBoundingBox(RgnHandle region);
RgnHandle NewRgn(void);
RgnHandle DisposeRgn(RgnHandle rgn);
void RectRgn(RgnHandle rgn, RECT* rect);
void GetClip(RgnHandle rgn);
void SetClip(RgnHandle rgn);
void ClipRect(RECT* rect);
void UnionRgn(RgnHandle srcA, RgnHandle srcB, RgnHandle dst);
void SetEmptyRgn(RgnHandle rgn);
void QDFrameRgn(RgnHandle rgn);
// Combine two clip regions into dst (empty/copy/RGN_DIFF cases) and refresh its box
void CombineClipRegionsWithEmptyHandling(RgnHandle srcA, RgnHandle srcB, RgnHandle dst);
// Fill the region with a solid foreground-color brush (CBrush(COLORREF) form)
void FillClipRegionWithForegroundBrush(RgnHandle rgn);
// Fill the region's interior with the current QuickDraw foreground color
void QDPaintRgn(RgnHandle rgn);
// Intersect the clip region with `rect` (RGN_AND) and refresh its bounding box
void ClipRegionToRect(RgnHandle clipRgn, RECT* rect);
void SetRectRgn(RgnHandle rgn, short left, short top, short right, short bottom);
bool EqualRgn(RgnHandle first, RgnHandle second);
void CopyRgn(RgnHandle src, RgnHandle dst);
void SectRgn(RgnHandle srcA, RgnHandle srcB, RgnHandle dst);
void OpenRgn(void);
void CloseRgn(RgnHandle dst);
void QDFrameRect(RECT* rect); // 0x00498180 (Win32 ::FrameRect collides)
void QDFrameOval(RECT* rect);
void QDPaintOval(RECT* rect);
unsigned char EmptyRgn(RgnHandle rgn);
int PtInRgn(CPoint* point, RgnHandle rgn);
// QuickDraw MapPt: rescale a point from srcRect's space into dstRect's, per axis.
void MapPt(int* point, RECT* srcRect, RECT* dstRect);
// Byte-identical unfolded second copy kept by the retail image.
void MapPtSecondCopy(int* point, RECT* srcRect, RECT* dstRect);
int SectRect(RECT* src1, RECT* src2, RECT* dst);
int BitMapToRegion(RgnHandle rgn, TBitmapSurfaceNode* surface);
void DisposeTemporaryRegionCache(void);

int ProbeRectEmptyAfterCopyToLocal(RECT* rect);
