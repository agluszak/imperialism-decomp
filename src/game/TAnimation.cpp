#include "game/TAnimation.h"

#include "game/TModuleLibraryCacheTableStateB.h"
#include "game/TAnimator.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/bitmap_descriptor_helpers.h"
#include "game/global_data_tables.h"
#include "game/TView.h"
#include "game/ui_invalidation_guard.h"
#include "game/quickdraw_rendering.h"

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
void TAnimation::Tick() {
  tickCounter10 = tickCounter10 + 1;
  if (tickCounter10 == ticksPerFrame14) {
    ownerView04->InvalidateCityDialogRectRegion(&screenRect1C, 1);
    tickCounter10 = 0;
    frameIndex08 = static_cast<short>(frameIndex08 + 1);
    if (frameIndex08 == frameCount0A) {
      frameIndex08 = 0;
    }
  }
}

// FUNCTION: IMPERIALISM 0x0049f190
void TAnimation::DrawNextFrame(POINT* offset) {
  TQuickDrawSurfaceContext* frameBuffer = g_pUiAnimator->renderSurfaceContext;
  LoadFrameIntoBuffer();

  RECT destination = screenRect1C;
  OffsetRect(&destination, offset->x, offset->y);
  RECT source = {0, 0, destination.right - destination.left, destination.bottom - destination.top};

  UpdatePaletteIndexWithDefaultFallback(0x10);
  if (frameBuffer->blitSurface.surfaceDib != 0) {
    int height = frameBuffer->blitSurface.surfaceDib->m_pInfoHeader->bmiHeader.biHeight;
    if (height < 1) {
      height = -height;
    }
    OffsetRect(&source, 0, (height - source.top) - source.bottom);
  }
  if (g_pActiveQuickDrawSurfaceContext->blitSurface.surfaceDib != 0) {
    int height =
        g_pActiveQuickDrawSurfaceContext->blitSurface.surfaceDib->m_pInfoHeader->bmiHeader.biHeight;
    if (height < 1) {
      height = -height;
    }
    OffsetRect(&destination, 0, (height - destination.top) - destination.bottom);
  }
  BlitRectWithOptionalTransparency(frameBuffer->GetBlitSurface(),
                                   g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &source,
                                   &destination, 0x24, 0);
  UpdatePaletteIndexWithDefaultFallback(0x13);
}

// FUNCTION: IMPERIALISM 0x0049f2d0
void TAnimation::LoadFrameIntoBuffer() {
  TQuickDrawSurfaceContext* savedContext = 0;
  int savedFlags = 0;
  GetGWorld(&savedContext, &savedFlags);

  TBitmapResourceLoader** loaderHandle =
      CreateBitmapResourceLoaderHandle(static_cast<unsigned short>(field0C + frameIndex08));
  QDLoadResource(loaderHandle);
  TBitmapResourceLoader* loader = loaderHandle != 0 ? *loaderHandle : 0;
  if (loader != 0) {
    TQuickDrawSurfaceContext* frameBuffer = g_pUiAnimator->renderSurfaceContext;
    SetGWorld(frameBuffer, savedFlags);
    TBitmapSurfaceNode** pixMap = GetGWorldPixMap(frameBuffer);
    LockPixels(pixMap);

    loader->EnsureBitmapResourceLoadedAndCopyRectSize();
    loader->flags |= 1;
    RECT resourceBounds = loader->bitmapRect;
    ResetQuickDrawStrokeState();
    BlitBitmapResourceLoaderToActiveDc(loaderHandle, &resourceBounds);

    delete loader;
    delete loaderHandle;
    UnlockPixels(pixMap);
    SetGWorld(savedContext, savedFlags);
  }
}

// Base slot-0x02 stub: reports an assert (D:\Ambit\QuickDraw.h:417) and returns 0. Its
// real semantics are unknown, so the name is provisional -- it was previously borrowed
// from the unrelated free assert/flag function at 0x49d620.
// FUNCTION: IMPERIALISM 0x004a1100
undefined4 TBitmapResourceLoader::ReportUnimplementedResourceVirtualSlot02() {
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
