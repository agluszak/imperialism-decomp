#include "game/TAnimation.h"

#include "game/TModuleLibraryCacheTableStateB.h"
#include "game/ui_invalidation_guard.h"

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

// SYNTHETIC: IMPERIALISM 0x0049f050
// TAnimation::`scalar deleting destructor'
TAnimation::~TAnimation() {}
// SYNTHETIC: IMPERIALISM 0x0049f020
// TAnimation::CreateObject

IMPLEMENT_DYNCREATE(TAnimation, TObject)

TAnimation::TAnimation() {}

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
undefined TBitmapResourceLoader::TemporarilyClearAndRestoreUiInvalidationFlag() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x004a1130
TBitmapResourceLoader** CreateBitmapResourceLoaderHandle(unsigned short resourceId) {
  TBitmapResourceLoader** handleSlot =
      static_cast<TBitmapResourceLoader**>(::operator new(sizeof(TBitmapResourceLoader*)));
  TBitmapResourceLoader* loader = new TBitmapResourceLoader(resourceId);
  *handleSlot = loader;
  return handleSlot;
}
