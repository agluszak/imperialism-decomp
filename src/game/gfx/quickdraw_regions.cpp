// Windows reimplementation of the Mac QuickDraw region API (original TU:
// D:\Ambit\QuickDraw.cpp). See quickdraw_regions.h for the Region/RgnHandle model.

#include "game/gfx/quickdraw_regions.h"

#include "game/gfx/CDib.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/globals/prelude.h"
#include "game/globals/gfx_globals.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/quickdraw_rendering.h"

// FUNCTION: IMPERIALISM 0x004954a0
Region::Region() : attachRegistered(0) {
  attachRegistered = rgn.Attach(::CreateRectRgn(0, 0, 0, 0));
}

// FUNCTION: IMPERIALISM 0x00495520
Region::~Region() {
  if (attachRegistered) {
    rgn.DeleteObject();
  }
}

// FUNCTION: IMPERIALISM 0x004955f0
void Region::RefreshBoundingBox() {
  ::GetRgnBox(static_cast<HRGN>(rgn.m_hObject), &rgnBBox);
}

// FUNCTION: IMPERIALISM 0x00495610
RgnHandle DisposeRgn(RgnHandle rgn) {
  if (rgn != 0) {
    delete *rgn;
  }
  delete rgn;
  return 0;
}

// PtInRgn: EmptyRgn's test spelled out inline, then Win32 PtInRegion.
// FUNCTION: IMPERIALISM 0x00495650
int PtInRgn(CPoint* point, RgnHandle rgn) {
  unsigned char empty = 1;
  if (rgn != 0) {
    Region* region = *rgn;
    if (static_cast<HRGN>(region->rgn) != 0) {
      ::GetRgnBox(static_cast<HRGN>(region->rgn.m_hObject), &region->rgnBBox);
      RECT box;
      ::CopyRect(&box, &region->rgnBBox);
      empty = static_cast<unsigned char>(::IsRectEmpty(&box));
    }
  }
  if (empty) {
    return 0;
  }
  return ::PtInRegion(static_cast<HRGN>((*rgn)->rgn.m_hObject), point->x, point->y);
}

// QuickDraw MapPt: rescale a point from `srcRect`'s coordinate space into `dstRect`'s,
// independently on each axis. The original copies each rect into a local before reading
// its extent (and swaps which local holds which rect between the two axes); that shape is
// kept so the two CopyRect pairs line up with the original.
// FUNCTION: IMPERIALISM 0x004956e0
void MapPt(int* point, RECT* srcRect, RECT* dstRect) {
  RECT scratchA;
  RECT scratchB;
  ::CopyRect(&scratchA, dstRect);
  ::CopyRect(&scratchB, srcRect);
  point[0] = ((scratchA.right - scratchA.left) * point[0]) / (scratchB.right - scratchB.left);
  ::CopyRect(&scratchB, dstRect);
  ::CopyRect(&scratchA, srcRect);
  point[1] = ((scratchB.bottom - scratchB.top) * point[1]) / (scratchA.bottom - scratchA.top);
}

// Byte-identical second copy of MapPt that the linker did not fold (the retail image keeps
// both). Same contract as MapPt above.
// FUNCTION: IMPERIALISM 0x00495780
void MapPtSecondCopy(int* point, RECT* srcRect, RECT* dstRect) {
  RECT scratchA;
  RECT scratchB;
  ::CopyRect(&scratchA, dstRect);
  ::CopyRect(&scratchB, srcRect);
  point[0] = ((scratchA.right - scratchA.left) * point[0]) / (scratchB.right - scratchB.left);
  ::CopyRect(&scratchB, dstRect);
  ::CopyRect(&scratchA, srcRect);
  point[1] = ((scratchB.bottom - scratchB.top) * point[1]) / (scratchA.bottom - scratchA.top);
}

// FUNCTION: IMPERIALISM 0x00495820
RgnHandle NewRgn(void) {
  RgnHandle handle = new Region*;
  Region* region = new Region();
  *handle = region;
  return handle;
}

// FUNCTION: IMPERIALISM 0x004958e0
void RectRgn(RgnHandle rgn, RECT* rect) {
  Region* region = *rgn;
  if (region->attachRegistered) {
    region->rgn.DeleteObject();
  }
  region->attachRegistered = region->rgn.Attach(::CreateRectRgnIndirect(rect));
}

// GetClip: read the current clip into the handle — start from the cached global
// clip region, then let the real DC clip (or a CPaintDC's paint rect) win.
// FUNCTION: IMPERIALISM 0x00495920
void GetClip(RgnHandle rgn) {
  // Reads the static-initialized global (0x494040 CRT init sets it) directly; GetSafeHandle
  // on the possibly-null pointer reproduces the original's inline `test/je/[+4]` null-guard.
  ::CombineRgn(static_cast<HRGN>((*rgn)->rgn.m_hObject),
               static_cast<HRGN>(g_pGlobalClipRegionHandleObject->GetSafeHandle()), 0, RGN_COPY);
  CDC* dc = g_pQuickDrawMemoryDc;
  if (dc == 0) {
    dc = g_pScopedMapQuickDrawDcHandleObject;
  }
  if (::GetClipRgn(dc->GetSafeHdc(), static_cast<HRGN>((*rgn)->rgn)) == -1) {
    dc = g_pQuickDrawMemoryDc;
    if (dc == 0) {
      dc = g_pScopedMapQuickDrawDcHandleObject;
    }
    if (dc != 0) {
      if (dc->IsKindOf(RUNTIME_CLASS(CPaintDC))) {
        (*rgn)->rgn.Attach(::CreateRectRgnIndirect(&static_cast<CPaintDC*>(dc)->m_ps.rcPaint));
      } else {
        RECT rect; // left uninitialized in the original too
        (*rgn)->rgn.Attach(::CreateRectRgnIndirect(&rect));
      }
    }
  }
}

// SetClip: copy the handle's region into the cached global clip region. The
// source is read through CRgn::operator HRGN, whose this==NULL check absorbs the
// "nil region" sentinel some callers store in a handle (a Region* placed so that
// &(*rgn)->rgn == NULL).
// FUNCTION: IMPERIALISM 0x00495a30
void SetClip(RgnHandle rgn) {
  // Direct read of the static-initialized global (no null-guard on it, matching the
  // original -- the 0x494040 CRT init guarantees it is set before any SetClip call).
  ::CombineRgn(static_cast<HRGN>(g_pGlobalClipRegionHandleObject->m_hObject),
               static_cast<HRGN>((*rgn)->rgn), 0, RGN_COPY);
}

// ClipRect: vestigial in the Windows port — builds a rect region and immediately
// destroys it (only the UI-active gate survives from the Mac semantics).
// FUNCTION: IMPERIALISM 0x00495a80
void ClipRect(RECT* rect) {
  if (GetMcAppUiActiveFlag()) {
    CRgn rectRegion;
    rectRegion.Attach(::CreateRectRgn(rect->left, rect->top, rect->right, rect->bottom));
    rectRegion.DeleteObject();
  }
}

// FUNCTION: IMPERIALISM 0x004974f0
void DisposeTemporaryRegionCache(void) {
  RgnHandle cache = g_pTemporaryRegionCache;
  if (cache != 0 && *cache != 0) {
    delete *cache;
  }
  delete cache;
  g_pTemporaryRegionCache = 0;
}

// Combine two source clip regions into `dst`: when both are empty `dst` becomes an empty
// region; when exactly one is empty the other is copied (RGN_COPY); when both are non-empty
// they are combined with RGN_DIFF. The bounding box of `dst` is refreshed afterwards. The
// per-region emptiness test (GetRgnBox -> CopyRect -> IsRectEmpty) is inlined at each site, as
// in the original.
// FUNCTION: IMPERIALISM 0x00497540
void CombineClipRegionsWithEmptyHandling(RgnHandle srcA, RgnHandle srcB, RgnHandle dst) {
  RECT boundsScratch;

  char emptyA;
  if (srcA == NULL) {
    emptyA = 1;
  } else {
    Region* ra = *srcA;
    HRGN ha = static_cast<HRGN>(static_cast<HGDIOBJ>(ra->rgn));
    if (ha == NULL) {
      emptyA = 1;
    } else {
      ::GetRgnBox(ha, &ra->rgnBBox);
      ::CopyRect(&boundsScratch, &ra->rgnBBox);
      emptyA = static_cast<char>(::IsRectEmpty(&boundsScratch));
    }
  }

  if (emptyA != 0) {
    char emptyB;
    if (srcB == NULL) {
      emptyB = 1;
    } else {
      Region* rb = *srcB;
      HRGN hb = static_cast<HRGN>(static_cast<HGDIOBJ>(rb->rgn));
      if (hb == NULL) {
        emptyB = 1;
      } else {
        ::GetRgnBox(hb, &rb->rgnBBox);
        ::CopyRect(&boundsScratch, &rb->rgnBBox);
        emptyB = static_cast<char>(::IsRectEmpty(&boundsScratch));
      }
    }
    if (emptyB != 0) {
      (*dst)->rgn.DeleteObject();
      (*dst)->rgn.Attach(::CreateRectRgn(0, 0, 0, 0));
      ::GetRgnBox(static_cast<HRGN>((*dst)->rgn.m_hObject), &(*dst)->rgnBBox);
      return;
    }
  }

  char emptyA2;
  if (srcA == NULL) {
    emptyA2 = 1;
  } else {
    Region* ra = *srcA;
    HRGN ha = static_cast<HRGN>(static_cast<HGDIOBJ>(ra->rgn));
    if (ha == NULL) {
      emptyA2 = 1;
    } else {
      ::GetRgnBox(ha, &ra->rgnBBox);
      ::CopyRect(&boundsScratch, &ra->rgnBBox);
      emptyA2 = static_cast<char>(::IsRectEmpty(&boundsScratch));
    }
  }

  HRGN hrgnSrc1;
  HRGN hrgnSrc2;
  HRGN hrgnDst;
  int mode;
  if (emptyA2 == 0) {
    char emptyB2;
    if (srcB == NULL) {
      emptyB2 = 1;
    } else {
      Region* rb = *srcB;
      HRGN hb = static_cast<HRGN>(static_cast<HGDIOBJ>(rb->rgn));
      if (hb == NULL) {
        emptyB2 = 1;
      } else {
        ::GetRgnBox(hb, &rb->rgnBBox);
        ::CopyRect(&boundsScratch, &rb->rgnBBox);
        emptyB2 = static_cast<char>(::IsRectEmpty(&boundsScratch));
      }
    }
    if (emptyB2 == 0) {
      hrgnSrc2 = static_cast<HRGN>(static_cast<HGDIOBJ>((*srcB)->rgn));
      hrgnSrc1 = static_cast<HRGN>(static_cast<HGDIOBJ>((*srcA)->rgn));
      mode = RGN_DIFF;
      hrgnDst = static_cast<HRGN>((*dst)->rgn.m_hObject);
    } else if (static_cast<HGDIOBJ>((*srcA)->rgn) == NULL) {
      mode = RGN_COPY;
      hrgnDst = static_cast<HRGN>((*dst)->rgn.m_hObject);
      hrgnSrc1 = NULL;
      hrgnSrc2 = NULL;
    } else {
      hrgnSrc1 = static_cast<HRGN>((*srcA)->rgn.m_hObject);
      mode = RGN_COPY;
      hrgnSrc2 = NULL;
      hrgnDst = static_cast<HRGN>((*dst)->rgn.m_hObject);
    }
  } else if (static_cast<HGDIOBJ>((*srcB)->rgn) == NULL) {
    hrgnDst = static_cast<HRGN>((*dst)->rgn.m_hObject);
    mode = RGN_COPY;
    hrgnSrc1 = NULL;
    hrgnSrc2 = NULL;
  } else {
    hrgnSrc1 = static_cast<HRGN>((*srcB)->rgn.m_hObject);
    hrgnDst = static_cast<HRGN>((*dst)->rgn.m_hObject);
    mode = RGN_COPY;
    hrgnSrc2 = NULL;
  }

  ::CombineRgn(hrgnDst, hrgnSrc1, hrgnSrc2, mode);
  ::GetRgnBox(static_cast<HRGN>((*dst)->rgn.m_hObject), &(*dst)->rgnBBox);
}

// FUNCTION: IMPERIALISM 0x004977a0
void UnionRgn(RgnHandle srcA, RgnHandle srcB, RgnHandle dst) {
  CRgn* rgnB = &(*srcB)->rgn;
  CRgn* rgnA = &(*srcA)->rgn;
  CRgn* rgnDst = &(*dst)->rgn;
  ::CombineRgn(static_cast<HRGN>(rgnDst->m_hObject), static_cast<HRGN>(*rgnA),
               static_cast<HRGN>(*rgnB), RGN_OR);
  ::GetRgnBox(static_cast<HRGN>((*dst)->rgn.m_hObject), &(*dst)->rgnBBox);
}

// FUNCTION: IMPERIALISM 0x00497810
void SetEmptyRgn(RgnHandle rgn) {
  (*rgn)->rgn.DeleteObject();
  (*rgn)->rgn.Attach(::CreateRectRgn(0, 0, 0, 0));
  ::GetRgnBox(static_cast<HRGN>((*rgn)->rgn.m_hObject), &(*rgn)->rgnBBox);
}

// FUNCTION: IMPERIALISM 0x00497860
void QDFrameRgn(RgnHandle rgn) {
  CBrush brush(g_QuickDrawForegroundColor);
  CDC* dc = g_pQuickDrawMemoryDc;
  if (dc == 0) {
    dc = g_pScopedMapQuickDrawDcHandleObject;
  }
  if (dc != 0) {
    ::FrameRgn(dc->m_hDC, static_cast<HRGN>((*rgn)->rgn.m_hObject), static_cast<HBRUSH>(brush), 1,
               1);
  }
}

// FUNCTION: IMPERIALISM 0x00497940
void FillClipRegionWithForegroundBrush(RgnHandle rgn) {
  CBrush fillBrush(g_QuickDrawForegroundColor);
  CDC* dc =
      g_pQuickDrawMemoryDc != NULL ? g_pQuickDrawMemoryDc : g_pScopedMapQuickDrawDcHandleObject;
  if (dc != NULL) {
    ::FillRgn(dc->m_hDC, static_cast<HRGN>((*rgn)->rgn.m_hObject),
              static_cast<HBRUSH>(fillBrush.m_hObject));
  }
  fillBrush.DeleteObject();
}

// FUNCTION: IMPERIALISM 0x00497a10
void QDPaintRgn(RgnHandle rgn) {
  CBrush fillBrush;
  fillBrush.Attach(::CreateSolidBrush(g_QuickDrawForegroundColor));
  CDC* dc =
      g_pQuickDrawMemoryDc != NULL ? g_pQuickDrawMemoryDc : g_pScopedMapQuickDrawDcHandleObject;
  if (dc != NULL) {
    ::FillRgn(dc->m_hDC, static_cast<HRGN>((*rgn)->rgn.m_hObject),
              static_cast<HBRUSH>(fillBrush.m_hObject));
  }
  fillBrush.DeleteObject();
}

// FUNCTION: IMPERIALISM 0x00497b30
void InitializeCityBuildingControlRegions_Impl(RgnHandle region, int x, int y) {
  (void)x;
  (void)y;
  ::GetRgnBox(static_cast<HRGN>((*region)->rgn), &(*region)->rgnBBox);
}

// FUNCTION: IMPERIALISM 0x00497bb0
void CopyRgn(RgnHandle src, RgnHandle dst) {
  CRgn* srcRgn = &(*src)->rgn;
  CRgn* dstRgn = &(*dst)->rgn;
  ::CombineRgn(static_cast<HRGN>(dstRgn->m_hObject), static_cast<HRGN>(*srcRgn), 0, RGN_COPY);
  ::GetRgnBox(static_cast<HRGN>((*dst)->rgn.m_hObject), &(*dst)->rgnBBox);
}

// Convert the surface's non-transparent pixel area into the region (the Mac
// BitMapToRegion role in this engine's sprite pipeline).
// FUNCTION: IMPERIALISM 0x00497ef0
int BitMapToRegion(RgnHandle rgn, TBitmapSurfaceNode* surface) {
  POINT* polygonPoints = surface->dib->BuildNonTransparentOutlinePolygon(0xffffffff);
  (*rgn)->rgn.DeleteObject();
  HRGN polygonRegion = ::CreatePolygonRgn(polygonPoints + 1, polygonPoints[0].x, WINDING);
  int attached = (*rgn)->rgn.Attach(polygonRegion);
  delete[] polygonPoints;
  return attached;
}

// OpenRgn/CloseRgn: region recording. QDFrameRect XORs framed rects into the
// accumulator while a recording is open; CloseRgn copies it into the handle.
// FUNCTION: IMPERIALISM 0x00497f60
void OpenRgn(void) {
  g_hOpenRgnAccumulator = ::CreateRectRgn(0, 0, 0, 0);
}

// FUNCTION: IMPERIALISM 0x00497f90
void CloseRgn(RgnHandle dst) {
  HRGN accumulated =
      static_cast<HRGN>(CGdiObject::FromHandle(g_hOpenRgnAccumulator)->GetSafeHandle());
  ::CombineRgn(static_cast<HRGN>((*dst)->rgn.m_hObject), accumulated, 0, RGN_COPY);
  ::DeleteObject(g_hOpenRgnAccumulator);
  g_hOpenRgnAccumulator = 0;
}

// FUNCTION: IMPERIALISM 0x00498070
void IntersectClipRegionWithRectAndUpdateBounds(RgnHandle clipRgn, RECT* rect) {
  CRgn rectRegion;
  rectRegion.Attach(::CreateRectRgn(rect->left, rect->top, rect->right, rect->bottom));
  ::CombineRgn(static_cast<HRGN>((*clipRgn)->rgn.m_hObject),
               static_cast<HRGN>(rectRegion.m_hObject),
               static_cast<HRGN>((*clipRgn)->rgn.m_hObject), RGN_AND);
  ::GetRgnBox(static_cast<HRGN>((*clipRgn)->rgn.m_hObject), &(*clipRgn)->rgnBBox);
  rectRegion.DeleteObject();
}

// FUNCTION: IMPERIALISM 0x00498180
void QDFrameRect(RECT* rect) {
  if (g_hOpenRgnAccumulator != 0) {
    CRgn rectRegion;
    rectRegion.Attach(::CreateRectRgnIndirect(rect));
    ::CombineRgn(g_hOpenRgnAccumulator, g_hOpenRgnAccumulator, static_cast<HRGN>(rectRegion),
                 RGN_XOR);
    rectRegion.DeleteObject();
    return;
  }

  CBrush brush(g_QuickDrawForegroundColor);
  RECT frameRect;
  ::CopyRect(&frameRect, rect);
  if (g_pActiveQuickDrawSurfaceContextHead == &g_defaultQuickDrawSurfaceSentinel) {
    ::OffsetRect(&frameRect, g_nQuickDrawOriginX, g_nQuickDrawOriginY);
  }
  CDC* dc = g_pQuickDrawMemoryDc;
  if (dc == 0) {
    dc = g_pScopedMapQuickDrawDcHandleObject;
  }
  ::FrameRect(dc->m_hDC, &frameRect, static_cast<HBRUSH>(brush));
}

// EmptyRgn: true when the handle carries no region or its bounding box is empty.
// FUNCTION: IMPERIALISM 0x00498aa0
unsigned char EmptyRgn(RgnHandle rgn) {
  if (rgn != 0) {
    Region* region = *rgn;
    if (static_cast<HRGN>(region->rgn) != 0) {
      ::GetRgnBox(static_cast<HRGN>(region->rgn.m_hObject), &region->rgnBBox);
      RECT box;
      ::CopyRect(&box, &region->rgnBBox);
      return static_cast<unsigned char>(::IsRectEmpty(&box));
    }
  }
  return 1;
}

// FUNCTION: IMPERIALISM 0x00498b10
int ProbeRectEmptyAfterCopyToLocal(RECT* rect) {
  tagRECT localRect;
  CopyRect(&localRect, rect);
  return IsRectEmpty(&localRect);
}

// Reorder-wrapper over the Win32 IntersectRect, matching the Mac SectRect
// argument order (src1, src2, dst).
// FUNCTION: IMPERIALISM 0x00498bb0
int SectRect(RECT* src1, RECT* src2, RECT* dst) {
  return IntersectRect(dst, src1, src2);
}

// FUNCTION: IMPERIALISM 0x00498be0
void SetRectRgn(RgnHandle rgn, short left, short top, short right, short bottom) {
  (*rgn)->rgn.Attach(::CreateRectRgn(left, top, right, bottom));
}
