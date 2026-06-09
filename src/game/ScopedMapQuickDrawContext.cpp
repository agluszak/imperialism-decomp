#include "game/ScopedMapQuickDrawContext.h"
#include "decomp_types.h"

typedef void* hwnd_t;
typedef void* hdc_t;

extern "C" hdc_t __stdcall GetDC(hwnd_t hwnd);
extern "C" int __stdcall ReleaseDC(hwnd_t hwnd, hdc_t hdc);

undefined4 ConstructCClientDCFromViewHandle(void);
undefined4 IntersectClipRectOnPrimaryAndSecondaryDc(void);
undefined4 DestroyCClientDCAndReleaseHandle(void);
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
ScopedMapQuickDrawContext::ScopedMapQuickDrawContext(void* renderTarget) {
  typedef void(__fastcall * ConstructCClientDCFromViewHandleFn)(void* self, int unusedEdx,
                                                                void* parentAt50);
  reinterpret_cast<ConstructCClientDCFromViewHandleFn>(ConstructCClientDCFromViewHandle)(
      this, 0, *reinterpret_cast<void**>(reinterpret_cast<char*>(renderTarget) + 0x50));
  int viewVtable = *reinterpret_cast<int*>(renderTarget);
  *reinterpret_cast<void**>(reinterpret_cast<char*>(this) + 0x14) = renderTarget;
  typedef void(__fastcall * ViewSlotF8Proc)(void* self, int unusedEdx);
  reinterpret_cast<ViewSlotF8Proc>(*reinterpret_cast<int*>(viewVtable + 0xf8))(renderTarget, 0);
  int renderTargetVtable = *reinterpret_cast<int*>(renderTarget);
  char clipRectBuffer[12];
  typedef void(__fastcall * ViewSlot160Proc)(void* self, int unusedEdx, char* buffer);
  reinterpret_cast<ViewSlot160Proc>(*reinterpret_cast<int*>(renderTargetVtable + 0x160))(
      renderTarget, 0, clipRectBuffer);
  reinterpret_cast<void(__cdecl*)(void*)>(IntersectClipRectOnPrimaryAndSecondaryDc)(this);
  g_pScopedMapQuickDrawViewContext = *reinterpret_cast<void**>(reinterpret_cast<char*>(this) + 0x14);
  if (this != 0) {
    g_pScopedMapQuickDrawDcHandleObject = this;
  } else {
    void* viewContext = g_pScopedMapQuickDrawViewContext;
    if (*reinterpret_cast<int*>(reinterpret_cast<char*>(viewContext) + 0x50) == 0) {
      g_pScopedMapQuickDrawDcHandleObject = 0;
    } else {
      GetDC(*reinterpret_cast<hwnd_t*>(*reinterpret_cast<int*>(reinterpret_cast<char*>(viewContext) +
                                                               0x50) +
                                         0x1c));
      reinterpret_cast<void(__cdecl*)()>(FromHandle_612736)();
    }
  }
}

// FUNCTION: IMPERIALISM 0x004948b0
ScopedMapQuickDrawContext::~ScopedMapQuickDrawContext() {
  if (this == 0) {
    void* viewContext = *reinterpret_cast<void**>(reinterpret_cast<char*>(this) + 0x14);
    ReleaseDC(*reinterpret_cast<hwnd_t*>(*reinterpret_cast<int*>(reinterpret_cast<char*>(viewContext) +
                                                                 0x50) +
                                          0x1c),
              *reinterpret_cast<hdc_t*>(reinterpret_cast<char*>(g_pScopedMapQuickDrawDcHandleObject) +
                                        4));
  }
  g_pScopedMapQuickDrawDcHandleObject = 0;
  g_pScopedMapQuickDrawViewContext = 0;
  typedef void(__fastcall * DestroyCClientDCAndReleaseHandleFn)(void* self, int unusedEdx);
  reinterpret_cast<DestroyCClientDCAndReleaseHandleFn>(DestroyCClientDCAndReleaseHandle)(this, 0);
}
