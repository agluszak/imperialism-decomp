// TFocusAnimation scoped QuickDraw render/tick slice.

#include "game/TFocusAnimation.h"

#include "game/TView.h"
#include "game/mfc.h"
#include "game/UiRuntimeContext.h"
#include "game/quickdraw_guards.h"
#include "game/ui_widget_thunks.h"
#include "game/global_data_tables.h"
#include "game/CDib.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/quickdraw_rendering.h"
#include "game/TAnimator.h"

IMPLEMENT_DYNCREATE(TFocusAnimation, TAnimation)

TFocusAnimation::TFocusAnimation() : TAnimation(), enabledFlag(1) {}

// FUNCTION: IMPERIALISM 0x004a0140
undefined TFocusAnimation::AdvanceAnimationTickAndInvalidateOnFrameFlip() {
  tickCounter10++;
  if (tickCounter10 == ticksPerFrame14) {
    VTableSlot0D();
    frameIndex08++;
    tickCounter10 = 0;
    if (frameIndex08 == frameCount0A) {
      frameIndex08 = 0;
    }
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x004a0190
void TFocusAnimation::VTableSlot0D() {
  if (enabledFlag != 0) {
    ScopedMapQuickDrawContextGuard quickDrawContext(ownerView04);
    ownerView04->Refresh();
    RenderBattleReportInsetWithPaletteShift();
    ownerView04->PostRenderSlotFC();
  }
}

// FUNCTION: IMPERIALISM 0x004a0250
undefined TFocusAnimation::RenderBattleReportInsetWithPaletteShift() {
  RenderBattleReportViewSurfaceSpriteWithResourceHandle();
  Helper_Uses_BlitRectWithOptionalTransparency_At004a0280();
  return 0;
}

// FUNCTION: IMPERIALISM 0x004a0280
void TFocusAnimation::Helper_Uses_BlitRectWithOptionalTransparency_At004a0280() {
  TQuickDrawSurfaceContext* srcContext =
      *reinterpret_cast<TQuickDrawSurfaceContext**>(g_pUiAnimator + 0x20);

  CPoint pt(screenRect1C.left, screenRect1C.top);
  CPoint transformedPt = ownerView04->TransformPointViaSlot138(&pt);

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

  if (g_pActiveQuickDrawSurfaceContext->surfaceDib != 0) {
    if (srcContext != nullptr && srcContext->surfaceDib != 0) {
      int heightAnim = srcContext->surfaceDib->m_pInfoHeader->bmiHeader.biHeight;
      if (heightAnim < 1)
        heightAnim = -heightAnim;
      OffsetRect(&tStack_14, 0, (heightAnim - tStack_14.top) - tStack_14.bottom);
    }

    CDib* activeDib = g_pActiveQuickDrawSurfaceContext->surfaceDib;
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
