#include "game/ui_core/ScopedMapQuickDrawContext.h"
#include "decomp_types.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/globals/global_types.h"
#include "game/globals/gfx_globals.h"
#include "game/globals/shared_globals.h"

typedef void* hwnd_t;

static __inline int BindScopedMapQuickDrawDcHandleInline(TView* view, CDC* existingDc) {
  g_pScopedMapQuickDrawViewContext = view;
  CDC* dcHandleObject = existingDc;
  if (existingDc == 0) {
    if (view->nativeWindow50 != 0) {
      HDC hdc = GetDC(view->nativeWindow50->m_hWnd);
      // LIBRARY: CDC::FromHandle (0x00612736)
      CDC* cdc = CDC::FromHandle(hdc);
      g_pScopedMapQuickDrawDcHandleObject = cdc;
      return cdc != 0;
    }
    dcHandleObject = 0;
  }
  g_pScopedMapQuickDrawDcHandleObject = dcHandleObject;
  return dcHandleObject != 0;
}

static __inline void ReleaseScopedMapQuickDrawDcHandleInline(TView* view, CDC* existingDc) {
  if (existingDc == 0) {
    ReleaseDC(view->nativeWindow50->m_hWnd, g_pScopedMapQuickDrawDcHandleObject->m_hDC);
  }
  g_pScopedMapQuickDrawDcHandleObject = 0;
  g_pScopedMapQuickDrawViewContext = 0;
}

static __inline void BindScopedMapQuickDrawClientDcInline(TView* view, CDC* clientDc) {
  g_pScopedMapQuickDrawViewContext = view;
  if (clientDc != 0) {
    g_pScopedMapQuickDrawDcHandleObject = clientDc;
  } else if (view->nativeWindow50 != 0) {
    g_pScopedMapQuickDrawDcHandleObject = CDC::FromHandle(GetDC(view->nativeWindow50->m_hWnd));
  } else {
    g_pScopedMapQuickDrawDcHandleObject = 0;
  }
}

// Bind the scoped map QuickDraw DC: record the active view, and select the DC-handle
// object (either the caller-supplied one, or a fresh CDC wrapping the view window's DC).
// FUNCTION: IMPERIALISM 0x004945f0
int BindScopedMapQuickDrawDcHandle(TView* view, CDC* existingDc) {
  return BindScopedMapQuickDrawDcHandleInline(view, existingDc);
}

// FUNCTION: IMPERIALISM 0x00494660
CDC* GetActiveQuickDrawDc() {
  CDC* dc = g_pQuickDrawMemoryDc;
  if (dc == 0) {
    dc = g_pScopedMapQuickDrawDcHandleObject;
  }
  return dc;
}

// FUNCTION: IMPERIALISM 0x00494680
CDib* GetActiveQuickDrawSurfaceDib() {
  TQuickDrawSurfaceContext* head = g_pActiveQuickDrawSurfaceContextHead;
  if (head == &g_defaultQuickDrawSurfaceSentinel) {
    return 0;
  }
  TBitmapSurfaceNode** nodeSlot =
      static_cast<TBitmapSurfaceNode**>(head->blitSurface.surfaceObject);
  return (*nodeSlot)->dib;
}

// Release the scoped map QuickDraw DC: when no caller-supplied handle was bound, return
// the borrowed window DC, then clear the active handle/view globals.
// FUNCTION: IMPERIALISM 0x004946b0
void ReleaseScopedMapQuickDrawDcHandle(TView* view, CDC* existingDc) {
  ReleaseScopedMapQuickDrawDcHandleInline(view, existingDc);
}

// FUNCTION: IMPERIALISM 0x00494700
ScopedMapQuickDrawContext::ScopedMapQuickDrawContext(TView* renderTargetArg)
    : clientDc(renderTargetArg->nativeWindow50), renderTarget(renderTargetArg) {
  renderTarget->PrepareForDrawing();
  CRect clipRect;
  clientDc.IntersectClipRect(renderTarget->GetQDExtent(&clipRect));
  BindScopedMapQuickDrawClientDcInline(renderTarget, &clientDc);
}

// FUNCTION: IMPERIALISM 0x004947e0
ScopedMapQuickDrawContext::ScopedMapQuickDrawContext(TView* renderTargetArg, RECT* clipRect)
    : clientDc(renderTargetArg->nativeWindow50), renderTarget(renderTargetArg) {
  renderTarget->PrepareForDrawing();
  clientDc.IntersectClipRect(clipRect);
  BindScopedMapQuickDrawClientDcInline(renderTarget, &clientDc);
}

// FUNCTION: IMPERIALISM 0x004948b0
ScopedMapQuickDrawContext::~ScopedMapQuickDrawContext() {
  ReleaseScopedMapQuickDrawDcHandleInline(renderTarget, &clientDc);
}
