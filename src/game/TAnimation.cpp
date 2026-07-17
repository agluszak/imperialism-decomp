#include "game/TAnimation.h"

#include "game/TModuleLibraryCacheTableStateB.h"
#include "game/global_data_tables.h"
#include "game/TView.h"
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
// SYNTHETIC: IMPERIALISM 0x0049f020
// TAnimation::CreateObject

// SYNTHETIC: IMPERIALISM 0x0049f050
// TAnimation::`scalar deleting destructor'
TAnimation::~TAnimation() {}

// SYNTHETIC: IMPERIALISM 0x0049f0a0
// TAnimation::GetRuntimeClass

IMPLEMENT_DYNCREATE(TAnimation, TObject)

// FUNCTION: IMPERIALISM 0x0049f0c0
void TAnimation::ConstructTAnimationBaseState(TView* ownerView, RECT* rect, short frameCount,
                                              short param4, int ticksPerFrame, int tag) {
  ownerView04 = ownerView;
  screenRect1C = *rect;
  frameCount0A = frameCount;
  field0C = param4;
  frameIndex08 = 0;
  tickCounter10 = 0;
  ticksPerFrame14 = ticksPerFrame;
  registryTag18 = tag;
}

// Per-tick frame flip: on every ticksPerFrame14-th tick, invalidate the marker rect
// and advance/wrap the frame index (the old WrapperFor_InvalidateCityDialogRectRegion
// name was junk).
// FUNCTION: IMPERIALISM 0x0049f140
undefined TAnimation::AdvanceAnimationTickAndInvalidateOnFrameFlip() {
  tickCounter10 = tickCounter10 + 1;
  if (tickCounter10 == ticksPerFrame14) {
    ownerView04->InvalidateCityDialogRectRegion(&screenRect1C, 1);
    tickCounter10 = 0;
    frameIndex08 = static_cast<short>(frameIndex08 + 1);
    if (frameIndex08 == frameCount0A) {
      frameIndex08 = 0;
    }
  }
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
