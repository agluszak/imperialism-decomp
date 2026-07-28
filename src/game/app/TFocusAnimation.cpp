// TFocusAnimation scoped QuickDraw render/tick slice.

#include "game/app/TFocusAnimation.h"

#include "game/ui_core/TView.h"
#include "game/mfc.h"
#include "game/ui_core/TViewMgr.h"
#include "game/quickdraw_guards.h"
#include "game/globals/global_types.h"
#include "game/globals/gfx_globals.h"
#include "game/globals/shared_globals.h"
#include "game/gfx/CDib.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/app/TAnimator.h"

// SYNTHETIC: IMPERIALISM 0x004a0020
// TFocusAnimation::CreateObject

IMPLEMENT_DYNCREATE(TFocusAnimation, TAnimation)
// FUNCTION: IMPERIALISM 0x004a0140
void TFocusAnimation::Tick() {
  ticksSinceFrameChange++;
  if (ticksSinceFrameChange == ticksPerFrame) {
    IdleDraw();
    frameIndex++;
    ticksSinceFrameChange = 0;
    if (frameIndex == frameCount) {
      frameIndex = 0;
    }
  }
}

// FUNCTION: IMPERIALISM 0x004a0190
void TFocusAnimation::IdleDraw() {
  if (enabledFlag != 0) {
    ScopedMapQuickDrawContextGuard quickDrawContext(ownerView);
    ownerView->PrepareForDrawing();
    POINT offset = {0, 0};
    DrawNextFrame(&offset);
    ownerView->PostRender();
  }
}

// FUNCTION: IMPERIALISM 0x004a0250
void TFocusAnimation::DrawNextFrame(POINT* unusedOffset) {
  (void)unusedOffset;
  LoadFrameIntoBuffer();
  ClipAndPaste();
}

// FUNCTION: IMPERIALISM 0x004a0280
void TFocusAnimation::ClipAndPaste() {
  TQuickDrawSurfaceContext* srcContext = g_pUiAnimator->renderSurfaceContext;

  CPoint ownerPoint(screenRect.left, screenRect.top);
  CPoint quickDrawPoint = ownerView->ViewToQDPt(&ownerPoint);

  int width = screenRect.right - screenRect.left;
  int height = screenRect.bottom - screenRect.top;

  RECT destinationRect;
  destinationRect.left = quickDrawPoint.x;
  destinationRect.top = quickDrawPoint.y;
  destinationRect.right = quickDrawPoint.x + width;
  destinationRect.bottom = quickDrawPoint.y + height;

  RECT sourceRect;
  sourceRect.left = 0;
  sourceRect.top = 0;
  sourceRect.right = width;
  sourceRect.bottom = height;

  SetQuickDrawStrokeColor(0xffffff);

  if (g_pActiveQuickDrawSurfaceContext->blitSurface.surfaceDib != 0) {
    if (srcContext != nullptr && srcContext->blitSurface.surfaceDib != 0) {
      int sourceSurfaceHeight =
          srcContext->blitSurface.surfaceDib->m_pInfoHeader->bmiHeader.biHeight;
      if (sourceSurfaceHeight < 1) {
        sourceSurfaceHeight = -sourceSurfaceHeight;
      }
      OffsetRect(&sourceRect, 0, (sourceSurfaceHeight - sourceRect.top) - sourceRect.bottom);
    }

    CDib* activeDib = g_pActiveQuickDrawSurfaceContext->blitSurface.surfaceDib;
    if (activeDib != 0) {
      int destinationSurfaceHeight = activeDib->m_pInfoHeader->bmiHeader.biHeight;
      if (destinationSurfaceHeight < 1) {
        destinationSurfaceHeight = -destinationSurfaceHeight;
      }
      OffsetRect(&destinationRect, 0,
                 (destinationSurfaceHeight - destinationRect.top) - destinationRect.bottom);
    }
  }

  BlitQuickDrawSurfaces(&srcContext->blitSurface, &g_pActiveQuickDrawSurfaceContext->blitSurface,
                        &sourceRect, &destinationRect, 0);
}

// SYNTHETIC: IMPERIALISM 0x004a0050
// TFocusAnimation::`scalar deleting destructor'

// SYNTHETIC: IMPERIALISM 0x004a00a0
// TFocusAnimation::GetRuntimeClass
