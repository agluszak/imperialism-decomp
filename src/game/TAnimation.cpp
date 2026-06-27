#include "game/TAnimation.h"
#include "game/TModuleLibraryCacheTableStateB.h"
#include "game/ui_invalidation_guard.h"

// FUNCTION: IMPERIALISM 0x00495b70
void TAnimation::EnsureBitmapResourceLoadedAndCopyRectSize() {
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
void TAnimation::WrapperFor_thunk_DecrementDialogResourceRefCountByShortIdAndCleanup_At00495c00() {
  if (bitmapResource != NULL) {
    g_pModuleLibraryCacheState->ReleaseRecordById(bitmapResourceId);
  }
  bitmapResource = NULL;
}

// SYNTHETIC: IMPERIALISM 0x0049f050
// TAnimation::`scalar deleting destructor'
TAnimation::~TAnimation() {}

// FUNCTION: IMPERIALISM 0x0049f0a0
CRuntimeClass* TAnimation::GetRuntimeClass() const {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0049f140
undefined TAnimation::WrapperFor_InvalidateCityDialogRectRegion_At0049f140() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0049f190
undefined TAnimation::RenderBattleReportInsetWithPaletteShift() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0049f2d0
undefined TAnimation::RenderBattleReportViewSurfaceSpriteWithResourceHandle() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004a1100
undefined TAnimation::WrapperFor_thunk_TemporarilyClearAndRestoreUiInvalidationFlag_At004a1100() {
  return 0;
}
