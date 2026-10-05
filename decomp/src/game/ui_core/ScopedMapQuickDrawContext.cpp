#include "game/ui_core/ScopedMapQuickDrawContext.h"
#include "decomp_types.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/globals/global_types.h"
#include "game/globals/gfx_globals.h"
#include "game/globals/shared_globals.h"

typedef void* hwnd_t;

static int BindScopedMapQuickDrawDcHandleInline(TView* view, CDC* existingDc) {
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

static void ReleaseScopedMapQuickDrawDcHandleInline(TView* view, CDC* existingDc) {
  if (existingDc == 0) {
    ReleaseDC(view->nativeWindow50->m_hWnd, g_pScopedMapQuickDrawDcHandleObject->m_hDC);
  }
  g_pScopedMapQuickDrawDcHandleObject = 0;
  g_pScopedMapQuickDrawViewContext = 0;
}

static void BindScopedMapQuickDrawClientDcInline(TView* view, CDC* clientDc) {
  g_pScopedMapQuickDrawViewContext = view;
  if (clientDc != 0) {
    g_pScopedMapQuickDrawDcHandleObject = clientDc;
  } else if (view->nativeWindow50 != 0) {
    g_pScopedMapQuickDrawDcHandleObject = CDC::FromHandle(GetDC(view->nativeWindow50->m_hWnd));
  } else {
    g_pScopedMapQuickDrawDcHandleObject = 0;
  }
}

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
