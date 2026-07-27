#include "game/app/TAnimation.h"

#include "game/app/TAnimator.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/ui_core/bitmap_descriptor_helpers.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/quickdraw_rendering.h"

// SYNTHETIC: IMPERIALISM 0x0049f020
// TAnimation::CreateObject

// SYNTHETIC: IMPERIALISM 0x0049f050
// TAnimation::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x0049f080
TAnimation::~TAnimation() {}

// SYNTHETIC: IMPERIALISM 0x0049f0a0
// TAnimation::GetRuntimeClass

IMPLEMENT_DYNCREATE(TAnimation, TObject)

// FUNCTION: IMPERIALISM 0x0049f0c0
void TAnimation::IAnimation(TView* ownerViewArg, RECT* rect, short frameCountArg,
                            short frameResourceBaseIdArg, int ticksPerFrameArg, int tag) {
  ownerView = ownerViewArg;
  screenRect = *rect;
  frameCount = frameCountArg;
  frameResourceBaseId = frameResourceBaseIdArg;
  frameIndex = 0;
  ticksSinceFrameChange = 0;
  ticksPerFrame = ticksPerFrameArg;
  registryTag = tag;
}

// Per-tick frame flip: on every ticksPerFrame-th tick, invalidate the marker rect
// and advance/wrap the frame index (the old WrapperFor_InvalidateCityDialogRectRegion
// name was junk).
// FUNCTION: IMPERIALISM 0x0049f140
void TAnimation::Tick() {
  ticksSinceFrameChange = ticksSinceFrameChange + 1;
  if (ticksSinceFrameChange == ticksPerFrame) {
    ownerView->InvalidateCityDialogRectRegion(&screenRect, 1);
    ticksSinceFrameChange = 0;
    frameIndex = static_cast<short>(frameIndex + 1);
    if (frameIndex == frameCount) {
      frameIndex = 0;
    }
  }
}

// FUNCTION: IMPERIALISM 0x0049f190
void TAnimation::DrawNextFrame(POINT* offset) {
  TQuickDrawSurfaceContext* frameBuffer = g_pUiAnimator->renderSurfaceContext;
  LoadFrameIntoBuffer();

  RECT destination = screenRect;
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

// The original three-slot loader vtable ends at a null dword and has no destructor
// slot; listing 0x0049f2d0 inlines this exact-type non-virtual destructor.
IMPERIALISM_BEGIN_EXACT_TYPE_NON_VIRTUAL_DTOR_DELETE
// FUNCTION: IMPERIALISM 0x0049f2d0
void TAnimation::LoadFrameIntoBuffer() {
  TQuickDrawSurfaceContext* savedContext = 0;
  int savedFlags = 0;
  GetGWorld(&savedContext, &savedFlags);

  TBitmapResourceLoader** loaderHandle = CreateBitmapResourceLoaderHandle(
      static_cast<unsigned short>(frameResourceBaseId + frameIndex));
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
IMPERIALISM_END_EXACT_TYPE_NON_VIRTUAL_DTOR_DELETE
