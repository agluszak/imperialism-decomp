// Windows reimplementation of the Mac QuickDraw region API (original TU:
// D:\Ambit\QuickDraw.cpp). See quickdraw_regions.h for the Region/RgnHandle model.

#include "game/quickdraw_regions.h"

#include "game/CDib.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/global_data_tables.h"
#include "game/quickdraw_rendering.h"

// FUNCTION: IMPERIALISM 0x00495520
Region::~Region() {
  if (attachRegistered) {
    rgn.DeleteObject();
  }
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
    if ((HRGN)region->rgn != 0) {
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
  if (::GetClipRgn(dc->GetSafeHdc(), (HRGN)(*rgn)->rgn) == -1) {
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
  ::CombineRgn(static_cast<HRGN>(g_pGlobalClipRegionHandleObject->m_hObject), (HRGN)(*rgn)->rgn, 0,
               RGN_COPY);
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

// FUNCTION: IMPERIALISM 0x004977a0
void UnionRgn(RgnHandle srcA, RgnHandle srcB, RgnHandle dst) {
  CRgn* rgnB = &(*srcB)->rgn;
  CRgn* rgnA = &(*srcA)->rgn;
  CRgn* rgnDst = &(*dst)->rgn;
  ::CombineRgn(static_cast<HRGN>(rgnDst->m_hObject), (HRGN)*rgnA, (HRGN)*rgnB, RGN_OR);
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
  CBrush brush(static_cast<COLORREF>(g_Quick_Draw_Color_State_006950FC));
  CDC* dc = g_pQuickDrawMemoryDc;
  if (dc == 0) {
    dc = g_pScopedMapQuickDrawDcHandleObject;
  }
  if (dc != 0) {
    ::FrameRgn(dc->m_hDC, static_cast<HRGN>((*rgn)->rgn.m_hObject), static_cast<HBRUSH>(brush), 1,
               1);
  }
}

// FUNCTION: IMPERIALISM 0x00497bb0
void CopyRgn(RgnHandle src, RgnHandle dst) {
  CRgn* srcRgn = &(*src)->rgn;
  CRgn* dstRgn = &(*dst)->rgn;
  ::CombineRgn(static_cast<HRGN>(dstRgn->m_hObject), (HRGN)*srcRgn, 0, RGN_COPY);
  ::GetRgnBox(static_cast<HRGN>((*dst)->rgn.m_hObject), &(*dst)->rgnBBox);
}

// Convert the surface's non-transparent pixel area into the region (the Mac
// BitMapToRegion role in this engine's sprite pipeline).
// FUNCTION: IMPERIALISM 0x00497ef0
int BitMapToRegion(RgnHandle rgn, TBitmapSurfaceNode* surface) {
  int* polygonPoints = surface->dib->BuildNonTransparentOutlinePolygon(0xffffffff);
  (*rgn)->rgn.DeleteObject();
  // GEOMETRY_RAW_BUFFER: two-int header followed by packed POINT records.
  HRGN polygonRegion =
      ::CreatePolygonRgn(reinterpret_cast<POINT*>(polygonPoints + 2), polygonPoints[0], WINDING);
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

// FUNCTION: IMPERIALISM 0x00498180
void QDFrameRect(RECT* rect) {
  if (g_hOpenRgnAccumulator != 0) {
    CRgn rectRegion;
    rectRegion.Attach(::CreateRectRgnIndirect(rect));
    ::CombineRgn(g_hOpenRgnAccumulator, g_hOpenRgnAccumulator, (HRGN)rectRegion, RGN_XOR);
    rectRegion.DeleteObject();
    return;
  }

  CBrush brush(static_cast<COLORREF>(g_Quick_Draw_Color_State_006950FC));
  RECT frameRect;
  ::CopyRect(&frameRect, rect);
  if (g_pActiveQuickDrawSurfaceContextHead == &g_defaultQuickDrawSurfaceSentinel) {
    ::OffsetRect(&frameRect, g_nQuickDrawOriginX, g_nQuickDrawOriginY);
  }
  CDC* dc = g_pQuickDrawMemoryDc;
  if (dc == 0) {
    dc = g_pScopedMapQuickDrawDcHandleObject;
  }
  ::FrameRect(dc->m_hDC, &frameRect, (HBRUSH)brush);
}

// EmptyRgn: true when the handle carries no region or its bounding box is empty.
// FUNCTION: IMPERIALISM 0x00498aa0
unsigned char EmptyRgn(RgnHandle rgn) {
  if (rgn != 0) {
    Region* region = *rgn;
    if ((HRGN)region->rgn != 0) {
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
