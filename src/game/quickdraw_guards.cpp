#include "decomp_types.h"
#include "game/quickdraw_guards.h"
#include "game/GameAssert.h"

undefined4 thunk_DestructTShipAndFreeIfOwned(void);
undefined4 CreateClipStateRegionWrapperObject(void);
undefined4 WrapperFor_DeleteRegionHandleFromClipState_At00495520(void);
void FreeHeapBufferIfNotNull(undefined4 ptr_value);

const char kQuickDrawCppPath[] = "D:\\Ambit\\QuickDraw.cpp";

// GLOBAL: IMPERIALISM 0x6a1c98
void* g_pReusableQuickDrawSurfaceListHead = 0;

// FUNCTION: IMPERIALISM 0x00497320
QuickDrawSurfaceGuard::QuickDrawSurfaceGuard() {
  // ORIG_CALLCONV: __thiscall
  if (g_pReusableQuickDrawSurfaceListHead != 0) {
    surfaceWrapper = reinterpret_cast<int>(g_pReusableQuickDrawSurfaceListHead);
    g_pReusableQuickDrawSurfaceListHead = 0;
    return;
  }
  surfaceWrapper = (int)CreateClipStateRegionWrapperObject();
  if (surfaceWrapper == 0) {
    GAME_FAIL_NIL_POINTER();
    reinterpret_cast<void(__cdecl*)(const char*, int)>(thunk_DestructTShipAndFreeIfOwned)(
        kQuickDrawCppPath, 0x7f6);
  }
}

// FUNCTION: IMPERIALISM 0x00497390
QuickDrawSurfaceGuard::~QuickDrawSurfaceGuard() {
  // ORIG_CALLCONV: __thiscall
  if (g_pReusableQuickDrawSurfaceListHead != 0) {
    int regionWrapper = surfaceWrapper;
    if (regionWrapper != 0) {
      int regionHandle = *reinterpret_cast<int*>(regionWrapper);
      if (regionHandle != 0) {
        reinterpret_cast<void(__cdecl*)()>(WrapperFor_DeleteRegionHandleFromClipState_At00495520)();
        FreeHeapBufferIfNotNull(regionHandle);
      }
    }
    FreeHeapBufferIfNotNull(regionWrapper);
    surfaceWrapper = 0;
    return;
  }
  g_pReusableQuickDrawSurfaceListHead = reinterpret_cast<void*>(surfaceWrapper);
  surfaceWrapper = 0;
}
