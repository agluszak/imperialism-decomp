#include "game/ui_core/TBitmapResourceLoader.h"

#include "game/gfx/TModuleLibraryCacheTableStateB.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/gfx/ui_invalidation_guard.h"

// FUNCTION: IMPERIALISM 0x00495b70
void TBitmapResourceLoader::EnsureBitmapResourceLoadedAndCopyRectSize() {
  if (bitmapResource == NULL) {
    bitmapResource = g_pModuleLibraryCacheState->LoadBmpResourceByIdCached(bitmapResourceId);
    if (bitmapResource == NULL) {
      bitmapResource =
          g_pModuleLibraryCacheState->BuildIndexedBmpResourceById(bitmapResourceId, 0x42, 0x42, 0);
    }
  }

  CPoint bitmapSize;
  CPoint* copiedSize = bitmapResource->CopyBitmapDimensionsToPoint(&bitmapSize);
  bitmapRect.left = 0;
  bitmapRect.top = 0;
  bitmapRect.right = copiedSize->x;
  bitmapRect.bottom = copiedSize->y;
}

// FUNCTION: IMPERIALISM 0x00495c00
void TBitmapResourceLoader::ReleaseBitmapResource() {
  if (bitmapResource != NULL) {
    g_pModuleLibraryCacheState->ReleaseRecordById(bitmapResourceId);
  }
  bitmapResource = NULL;
}

// Base slot-0x02 stub: reports an assert (D:\Ambit\QuickDraw.h:417) and returns 0. Its
// real semantics are unknown, so the name is provisional -- it was previously borrowed
// from the unrelated free assert/flag function at 0x49d620.
// FUNCTION: IMPERIALISM 0x004a1100
int TBitmapResourceLoader::ReportUnimplementedResourceVirtualSlot02() {
  TemporarilyClearAndRestoreUiInvalidationFlag("D:\\Ambit\\QuickDraw.h", 0x1a1);
  return 0;
}

// FUNCTION: IMPERIALISM 0x004a1130
TBitmapResourceLoader** CreateBitmapResourceLoaderHandle(unsigned short resourceId) {
  TBitmapResourceLoader** handleSlot = new TBitmapResourceLoader*;
  TBitmapResourceLoader* loader = new TBitmapResourceLoader(resourceId);
  *handleSlot = loader;
  return handleSlot;
}
