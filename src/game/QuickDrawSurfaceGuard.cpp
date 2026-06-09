#include "game/QuickDrawSurfaceGuard.h"
#include "game/ClipStateRegion.h"
#include "game/GameAssert.h"
#include "game/MfcRuntime.h"

undefined4 thunk_DestructTShipAndFreeIfOwned(void);
undefined4 WrapperFor_DeleteRegionHandleFromClipState_At00495520(void);

const char kQuickDrawCppPath[] = "D:\\Ambit\\QuickDraw.cpp";

// GLOBAL: IMPERIALISM 0x6a1c98
void* g_pReusableQuickDrawSurfaceListHead = 0;

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

// FUNCTION: IMPERIALISM 0x00497320
QuickDrawSurfaceGuard::QuickDrawSurfaceGuard() {
  if (g_pReusableQuickDrawSurfaceListHead != 0) {
    surfaceWrapper = reinterpret_cast<int>(g_pReusableQuickDrawSurfaceListHead);
    g_pReusableQuickDrawSurfaceListHead = 0;
    return;
  }
  surfaceWrapper = CreateClipStateRegionWrapperObject();
  if (surfaceWrapper == 0) {
    GAME_FAIL_NIL_POINTER();
    reinterpret_cast<void(__cdecl*)(const char*, int)>(thunk_DestructTShipAndFreeIfOwned)(
        kQuickDrawCppPath, 0x7f6);
  }
}

// FUNCTION: IMPERIALISM 0x00497390
QuickDrawSurfaceGuard::~QuickDrawSurfaceGuard() {
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
