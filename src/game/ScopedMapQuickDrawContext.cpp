#include "game/ScopedMapQuickDrawContext.h"
#include "decomp_types.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/global_data_tables.h"

typedef void* hwnd_t;

// Bind the scoped map QuickDraw DC: record the active view, and select the DC-handle
// object (either the caller-supplied one, or a fresh CDC wrapping the view window's DC).
// FUNCTION: IMPERIALISM 0x004945f0
int BindScopedMapQuickDrawDcHandle(TView* view, CDC* existingDc) {
  g_pScopedMapQuickDrawViewContext = view;
  CDC* dcHandleObject = existingDc;
  if (existingDc == 0) {
    if (view->nativeWindow50 != 0) {
      HDC hdc = GetDC(reinterpret_cast<HWND>(view->nativeWindow50->m_hWnd));
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
  TBitmapSurfaceNode** nodeSlot = static_cast<TBitmapSurfaceNode**>(head->surfaceObject);
  return (*nodeSlot)->dib;
}

// Release the scoped map QuickDraw DC: when no caller-supplied handle was bound, return
// the borrowed window DC, then clear the active handle/view globals.
// FUNCTION: IMPERIALISM 0x004946b0
void ReleaseScopedMapQuickDrawDcHandle(TView* view, CDC* existingDc) {
  if (existingDc == 0) {
    HDC boundDc = g_pScopedMapQuickDrawDcHandleObject->m_hAttribDC;
    ReleaseDC(reinterpret_cast<HWND>(view->nativeWindow50->m_hWnd), boundDc);
  }
  g_pScopedMapQuickDrawDcHandleObject = 0;
  g_pScopedMapQuickDrawViewContext = 0;
}

// FUNCTION: IMPERIALISM 0x00494700
ScopedMapQuickDrawContext::ScopedMapQuickDrawContext(TView* renderTargetArg)
    : clientDc(renderTargetArg != 0 ? renderTargetArg->nativeWindow50 : 0),
      renderTarget(renderTargetArg) {
  if (renderTarget != 0) {
    renderTarget->PrepareForDrawing();
    RECT clipRect;
    renderTarget->ApplyBounds(&clipRect, 0);
    clientDc.IntersectClipRect(&clipRect);
  }
  g_pScopedMapQuickDrawViewContext = this->renderTarget;
  if (this != 0) {
    g_pScopedMapQuickDrawDcHandleObject = &clientDc;
  } else {
    TView* viewContext = this->renderTarget;
    if (viewContext->nativeWindow50 == 0) {
      g_pScopedMapQuickDrawDcHandleObject = 0;
    } else {
      // LIBRARY: CDC::FromHandle (0x00612736)
      CDC::FromHandle(GetDC(reinterpret_cast<HWND>(viewContext->nativeWindow50->m_hWnd)));
    }
  }
}

// FUNCTION: IMPERIALISM 0x004947e0
ScopedMapQuickDrawContext::ScopedMapQuickDrawContext(TView* renderTargetArg, RECT* clipRect)
    : clientDc(renderTargetArg->nativeWindow50), renderTarget(renderTargetArg) {
  renderTarget->PrepareForDrawing();
  clientDc.IntersectClipRect(clipRect);
  g_pScopedMapQuickDrawViewContext = renderTarget;
  if (this != 0) {
    g_pScopedMapQuickDrawDcHandleObject = &clientDc;
  } else if (renderTarget->nativeWindow50 == 0) {
    g_pScopedMapQuickDrawDcHandleObject = 0;
  } else {
    // LIBRARY: CDC::FromHandle (0x00612736)
    g_pScopedMapQuickDrawDcHandleObject =
        CDC::FromHandle(GetDC(reinterpret_cast<HWND>(renderTarget->nativeWindow50->m_hWnd)));
  }
}

// FUNCTION: IMPERIALISM 0x004948b0
ScopedMapQuickDrawContext::~ScopedMapQuickDrawContext() {
  if (this == 0) {
    TView* viewContext = this->renderTarget;
    ReleaseDC(reinterpret_cast<HWND>(viewContext->nativeWindow50->m_hWnd),
              g_pScopedMapQuickDrawDcHandleObject->m_hAttribDC);
  }
  g_pScopedMapQuickDrawDcHandleObject = 0;
  g_pScopedMapQuickDrawViewContext = 0;
}

// 0x00612fd8 is CDC::IntersectClipRect(LPCRECT) linked from nafxcw.lib -- it was
// mis-owned here as a guard member because clientDc sits at offset 0, so the real CDC
// method (this = &clientDc) looked like a method on the enclosing guard. It is now a
// LIBRARY entry (library_msvc500_fid.cpp) and callers use clientDc.IntersectClipRect().
