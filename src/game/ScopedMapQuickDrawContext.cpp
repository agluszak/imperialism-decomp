#include "game/ScopedMapQuickDrawContext.h"
#include "decomp_types.h"

typedef void* hwnd_t;
typedef void* hdc_t;

extern "C" hdc_t __stdcall GetDC(hwnd_t hwnd);
extern "C" int __stdcall ReleaseDC(hwnd_t hwnd, hdc_t hdc);
extern "C" int __stdcall IntersectClipRect(hdc_t hdc, int left, int top, int right, int bottom);
undefined4 FromHandle_612736(void);

extern void* g_pScopedMapQuickDrawDcHandleObject;
extern void* g_pScopedMapQuickDrawViewContext;

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

// GLOBAL: IMPERIALISM 0x6a1d9c
void* g_pScopedMapQuickDrawDcHandleObject = 0;
// GLOBAL: IMPERIALISM 0x6a1dac
void* g_pScopedMapQuickDrawViewContext = 0;

// FUNCTION: IMPERIALISM 0x00494700
ScopedMapQuickDrawContext::ScopedMapQuickDrawContext(void* renderTargetArg)
    : clientDc(renderTargetArg != 0
                   ? reinterpret_cast<void*>(reinterpret_cast<TView*>(renderTargetArg)->nativeWindow50)
                   : 0),
      renderTarget(reinterpret_cast<TView*>(renderTargetArg)) {
  if (renderTarget != 0) {
    renderTarget->Refresh();
    int clipRect[4];
    renderTarget->ApplyBounds(clipRect, 0);
    IntersectClipRectOnPrimaryAndSecondaryDc(clipRect);
  }
  g_pScopedMapQuickDrawViewContext = this->renderTarget;
  if (this != 0) {
    g_pScopedMapQuickDrawDcHandleObject = this;
  } else {
    TView* viewContext = this->renderTarget;
    if (viewContext->nativeWindow50 == 0) {
      g_pScopedMapQuickDrawDcHandleObject = 0;
    } else {
      GetDC(viewContext->nativeWindow50->hwnd);
      reinterpret_cast<void(__cdecl*)()>(FromHandle_612736)();
    }
  }
}

// FUNCTION: IMPERIALISM 0x004948b0
ScopedMapQuickDrawContext::~ScopedMapQuickDrawContext() {
  if (this == 0) {
    TView* viewContext = this->renderTarget;
    ReleaseDC(
        viewContext->nativeWindow50->hwnd,
        *reinterpret_cast<hdc_t*>(reinterpret_cast<char*>(g_pScopedMapQuickDrawDcHandleObject) + 4));
  }
  g_pScopedMapQuickDrawDcHandleObject = 0;
  g_pScopedMapQuickDrawViewContext = 0;
}

// FUNCTION: IMPERIALISM 0x00612fd8
int* ScopedMapQuickDrawContext::IntersectClipRectOnPrimaryAndSecondaryDc(int* clipRect) {
  if (clientDc.m_hDC != clientDc.m_hAttribDC) {
    clipRect = reinterpret_cast<int*>(IntersectClipRect(reinterpret_cast<hdc_t>(clientDc.m_hDC),
                                                        clipRect[0], clipRect[1], clipRect[2],
                                                        clipRect[3]));
  }
  if (clientDc.m_hAttribDC != 0) {
    clipRect = reinterpret_cast<int*>(IntersectClipRect(
        reinterpret_cast<hdc_t>(clientDc.m_hAttribDC), clipRect[0], clipRect[1], clipRect[2],
        clipRect[3]));
  }
  return clipRect;
}
