#include "game/CTemporaryRegion.h"
#include "game/ui_invalidation_guard.h"
#include "game/quickdraw_regions.h"
#include "game/GameAssert.h"
#include "game/mfc.h"
#include "game/globals/prelude.h"
#include "game/globals/gfx_globals.h"

const char kQuickDrawCppPath[] = "D:\\Ambit\\QuickDraw.cpp";

// FUNCTION: IMPERIALISM 0x00497320
CTemporaryRegion::CTemporaryRegion() {
  if (g_pTemporaryRegionCache != 0) {
    tempRgn = g_pTemporaryRegionCache;
    g_pTemporaryRegionCache = 0;
    return;
  }
  tempRgn = NewRgn();
  if (tempRgn == 0) {
    GAME_FAIL_NIL_POINTER();
    TemporarilyClearAndRestoreUiInvalidationFlag(kQuickDrawCppPath, 0x7f6);
  }
}

// If another temp region already sits in the cache, really dispose ours
// (DisposeRgn spelled out, as in the original); otherwise park the handle for
// the next CTemporaryRegion.
// FUNCTION: IMPERIALISM 0x00497390
CTemporaryRegion::~CTemporaryRegion() {
  if (g_pTemporaryRegionCache != 0) {
    RgnHandle handle = tempRgn;
    if (handle != 0) {
      delete *handle;
    }
    delete handle;
    tempRgn = 0;
    return;
  }
  g_pTemporaryRegionCache = tempRgn;
  tempRgn = 0;
}
