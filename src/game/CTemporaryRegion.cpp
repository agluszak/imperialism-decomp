#include "game/QuickDrawSurfaceGuard.h"
#include "game/ui_invalidation_guard.h"
#include "game/ClipStateRegion.h"
#include "game/GameAssert.h"
#include "game/mfc.h"
#include "game/global_data_tables.h"

undefined4 WrapperFor_DeleteRegionHandleFromClipState_At00495520(void);

const char kQuickDrawCppPath[] = "D:\\Ambit\\QuickDraw.cpp";

// FUNCTION: IMPERIALISM 0x00497320
QuickDrawSurfaceGuard::QuickDrawSurfaceGuard() {
  if (g_pReusableQuickDrawSurfaceListHead != 0) {
    surfaceWrapper =
        reinterpret_cast<ClipStateRegionWrapper*>(g_pReusableQuickDrawSurfaceListHead);
    g_pReusableQuickDrawSurfaceListHead = 0;
    return;
  }
  surfaceWrapper = CreateClipStateRegionWrapperObject();
  if (surfaceWrapper == 0) {
    GAME_FAIL_NIL_POINTER();
    reinterpret_cast<void(__cdecl*)(const char*, int)>(
        TemporarilyClearAndRestoreUiInvalidationFlag)(kQuickDrawCppPath, 0x7f6);
  }
}

// FUNCTION: IMPERIALISM 0x00497390
QuickDrawSurfaceGuard::~QuickDrawSurfaceGuard() {
  if (g_pReusableQuickDrawSurfaceListHead != 0) {
    ClipStateRegionWrapper* regionWrapper = surfaceWrapper;
    if (regionWrapper != 0) {
      ClipStateRegionInner* regionHandle = regionWrapper->inner;
      if (regionHandle != 0) {
        reinterpret_cast<void(__cdecl*)()>(WrapperFor_DeleteRegionHandleFromClipState_At00495520)();
        delete regionHandle;
        regionWrapper->inner = 0;
      }
    }
    delete regionWrapper;
    surfaceWrapper = 0;
    return;
  }
  g_pReusableQuickDrawSurfaceListHead = surfaceWrapper;
  surfaceWrapper = 0;
}
