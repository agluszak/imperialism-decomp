// TFocusAnimation scoped QuickDraw render/tick slice.

#include "game/app/TFocusAnimation.h"

#include "game/ui_core/TView.h"
#include "game/mfc.h"
#include "game/ui_core/TViewMgr.h"
#include "game/quickdraw_guards.h"
#include "game/globals/prelude.h"
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
  tickCounter10++;
  if (tickCounter10 == ticksPerFrame14) {
    IdleDraw();
    frameIndex08++;
    tickCounter10 = 0;
    if (frameIndex08 == frameCount0A) {
      frameIndex08 = 0;
    }
  }
}

// FUNCTION: IMPERIALISM 0x004a0190
void TFocusAnimation::IdleDraw() {
  if (enabledFlag != 0) {
    ScopedMapQuickDrawContextGuard quickDrawContext(ownerView04);
    ownerView04->PrepareForDrawing();
    POINT offset = {0, 0};
    DrawNextFrame(&offset);
    ownerView04->PostRender();
  }
}

// FUNCTION: IMPERIALISM 0x004a0250
void TFocusAnimation::DrawNextFrame(POINT* offset) {
  LoadFrameIntoBuffer();
  ClipAndPaste();
}

// FUNCTION: IMPERIALISM 0x004a0280
void TFocusAnimation::ClipAndPaste() {
  TQuickDrawSurfaceContext* srcContext = g_pUiAnimator->renderSurfaceContext;

  CPoint pt(screenRect1C.left, screenRect1C.top);
  CPoint transformedPt = ownerView04->ViewToQDPt(&pt);

  int width = screenRect1C.right - screenRect1C.left;
  int height = screenRect1C.bottom - screenRect1C.top;

  RECT local_24;
  local_24.left = transformedPt.x;
  local_24.top = transformedPt.y;
  local_24.right = transformedPt.x + width;
  local_24.bottom = transformedPt.y + height;

  RECT tStack_14;
  tStack_14.left = 0;
  tStack_14.top = 0;
  tStack_14.right = width;
  tStack_14.bottom = height;

  SetQuickDrawStrokeColor(0xffffff);

  if (g_pActiveQuickDrawSurfaceContext->blitSurface.surfaceDib != 0) {
    if (srcContext != nullptr && srcContext->blitSurface.surfaceDib != 0) {
      int heightAnim = srcContext->blitSurface.surfaceDib->m_pInfoHeader->bmiHeader.biHeight;
      if (heightAnim < 1)
        heightAnim = -heightAnim;
      OffsetRect(&tStack_14, 0, (heightAnim - tStack_14.top) - tStack_14.bottom);
    }

    CDib* activeDib = g_pActiveQuickDrawSurfaceContext->blitSurface.surfaceDib;
    if (activeDib != 0) {
      int heightActive = activeDib->m_pInfoHeader->bmiHeader.biHeight;
      if (heightActive < 1)
        heightActive = -heightActive;
      OffsetRect(&local_24, 0, (heightActive - local_24.top) - local_24.bottom);
    }
  }

  BlitQuickDrawSurfaces(&srcContext->blitSurface, &g_pActiveQuickDrawSurfaceContext->blitSurface,
                        &tStack_14, &local_24, 0);
}

// SYNTHETIC: IMPERIALISM 0x004a0050
// TFocusAnimation::`scalar deleting destructor'

// SYNTHETIC: IMPERIALISM 0x004a00a0
// TFocusAnimation::GetRuntimeClass
