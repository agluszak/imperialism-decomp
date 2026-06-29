#include "game/ScopedMapQuickDrawContext.h"
#include "decomp_types.h"
#include "game/global_data_tables.h"

typedef void* hwnd_t;
typedef void* hdc_t;

undefined4 FromHandle_612736(void);

// Bind the scoped map QuickDraw DC: record the active view, and select the DC-handle
// object (either the caller-supplied one, or a fresh CDC wrapping the view window's DC).
// FUNCTION: IMPERIALISM 0x004945f0
int BindScopedMapQuickDrawDcHandle(void* viewArg, int existingHandle) {
  TView* view = reinterpret_cast<TView*>(viewArg);
  g_pScopedMapQuickDrawViewContext = view;
  void* dcHandleObject = reinterpret_cast<void*>(existingHandle);
  if (existingHandle == 0) {
    if (view->nativeWindow50 != 0) {
      HDC hdc = GetDC(reinterpret_cast<HWND>(view->nativeWindow50->m_hWnd));
      void* cdc = reinterpret_cast<void*(__stdcall*)(HDC)>(FromHandle_612736)(hdc);
      g_pScopedMapQuickDrawDcHandleObject = cdc;
      return cdc != 0;
    }
    dcHandleObject = 0;
  }
  g_pScopedMapQuickDrawDcHandleObject = dcHandleObject;
  return dcHandleObject != 0;
}

// Release the scoped map QuickDraw DC: when no caller-supplied handle was bound, return
// the borrowed window DC, then clear the active handle/view globals.
// FUNCTION: IMPERIALISM 0x004946b0
void ReleaseScopedMapQuickDrawDcHandle(void* viewArg, int existingHandle) {
  TView* view = reinterpret_cast<TView*>(viewArg);
  if (existingHandle == 0) {
    HDC boundDc =
        *reinterpret_cast<HDC*>(reinterpret_cast<char*>(g_pScopedMapQuickDrawDcHandleObject) + 4);
    ReleaseDC(reinterpret_cast<HWND>(view->nativeWindow50->m_hWnd), boundDc);
  }
  g_pScopedMapQuickDrawDcHandleObject = 0;
  g_pScopedMapQuickDrawViewContext = 0;
}

// FUNCTION: IMPERIALISM 0x00494700
ScopedMapQuickDrawContext::ScopedMapQuickDrawContext(void* renderTargetArg)
    : clientDc(renderTargetArg != 0 ? reinterpret_cast<CWnd*>(
                                          reinterpret_cast<TView*>(renderTargetArg)->nativeWindow50)
                                    : 0),
      renderTarget(reinterpret_cast<TView*>(renderTargetArg)) {
  if (renderTarget != 0) {
    renderTarget->Refresh();
    RECT clipRect;
    renderTarget->ApplyBounds(&clipRect, 0);
    IntersectClipRectOnPrimaryAndSecondaryDc(reinterpret_cast<int*>(&clipRect));
  }
  g_pScopedMapQuickDrawViewContext = this->renderTarget;
  if (this != 0) {
    g_pScopedMapQuickDrawDcHandleObject = this;
  } else {
    TView* viewContext = this->renderTarget;
    if (viewContext->nativeWindow50 == 0) {
      g_pScopedMapQuickDrawDcHandleObject = 0;
    } else {
      GetDC(reinterpret_cast<HWND>(viewContext->nativeWindow50->m_hWnd));
      reinterpret_cast<void(__cdecl*)()>(FromHandle_612736)();
    }
  }
}

// FUNCTION: IMPERIALISM 0x004948b0
ScopedMapQuickDrawContext::~ScopedMapQuickDrawContext() {
  if (this == 0) {
    TView* viewContext = this->renderTarget;
    ReleaseDC(reinterpret_cast<HWND>(viewContext->nativeWindow50->m_hWnd),
              reinterpret_cast<HDC>(*reinterpret_cast<hdc_t*>(
                  reinterpret_cast<char*>(g_pScopedMapQuickDrawDcHandleObject) + 4)));
  }
  g_pScopedMapQuickDrawDcHandleObject = 0;
  g_pScopedMapQuickDrawViewContext = 0;
}

// FUNCTION: IMPERIALISM 0x00612fd8
int* ScopedMapQuickDrawContext::IntersectClipRectOnPrimaryAndSecondaryDc(int* clipRect) {
  if (clientDc.m_hDC != clientDc.m_hAttribDC) {
    clipRect = reinterpret_cast<int*>(IntersectClipRect(
        reinterpret_cast<HDC>(clientDc.m_hDC), clipRect[0], clipRect[1], clipRect[2], clipRect[3]));
  }
  if (clientDc.m_hAttribDC != 0) {
    clipRect = reinterpret_cast<int*>(IntersectClipRect(reinterpret_cast<HDC>(clientDc.m_hAttribDC),
                                                        clipRect[0], clipRect[1], clipRect[2],
                                                        clipRect[3]));
  }
  return clipRect;
}
