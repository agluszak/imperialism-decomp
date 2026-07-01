// TFocusAnimation scoped QuickDraw render/tick slice.

#include "game/TFocusAnimation.h"

#include "game/TView.h"
#include "game/mfc.h"
#include "game/UiRuntimeContext.h"
#include "game/quickdraw_guards.h"
#include "game/ui_widget_thunks.h"
#include "game/global_data_tables.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/quickdraw_rendering.h"
#include "game/TAnimator.h"

IMPLEMENT_DYNCREATE(TFocusAnimation, TAnimation)

TFocusAnimation::TFocusAnimation() : TAnimation(), enabledFlag(1) {}

// FUNCTION: IMPERIALISM 0x004a0140
undefined TFocusAnimation::WrapperFor_InvalidateCityDialogRectRegion_At0049f140() {
  FrameTick()++;
  if (FrameTick() == FrameTickLimit()) {
    VTableSlot0D();
    Field08()++;
    FrameTick() = 0;
    if (Field08() == Field0a()) {
      Field08() = 0;
    }
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x004a0190
void TFocusAnimation::VTableSlot0D() {
  if (enabledFlag != 0) {
    ScopedMapQuickDrawContextGuard quickDrawContext(reinterpret_cast<void*>(field04));
    reinterpret_cast<TView*>(reinterpret_cast<void*>(field04))->Refresh();
    RenderBattleReportInsetWithPaletteShift();
    reinterpret_cast<TView*>(reinterpret_cast<void*>(field04))->PostRenderSlotFC();
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
  TQuickDrawSurfaceContext* srcContext = *reinterpret_cast<TQuickDrawSurfaceContext**>(g_pUiAnimator + 0x20);

  CPoint pt(SourceLeft(), SourceTop());
  CPoint transformedPt = reinterpret_cast<TView*>(ScopedRenderTarget())->TransformPointViaSlot138(&pt);

  int width = SourceRight() - SourceLeft();
  int height = SourceBottom() - SourceTop();

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

  if (g_pActiveQuickDrawSurfaceContext->flipDescriptor != 0) {
    if (srcContext != nullptr && srcContext->flipDescriptor != 0) {
      int heightAnim = *reinterpret_cast<int*>(*reinterpret_cast<int*>(srcContext->flipDescriptor + 0x10) + 8);
      if (heightAnim < 1) heightAnim = -heightAnim;
      OffsetRect(&tStack_14, 0, (heightAnim - tStack_14.top) - tStack_14.bottom);
    }

    int activeContext = g_pActiveQuickDrawSurfaceContext->flipDescriptor;
    if (activeContext != 0) {
      int heightActive = *reinterpret_cast<int*>(*reinterpret_cast<int*>(activeContext + 0x10) + 8);
      if (heightActive < 1) heightActive = -heightActive;
      OffsetRect(&local_24, 0, (heightActive - local_24.top) - local_24.bottom);
    }
  }

  BlitQuickDrawSurfaces(
      &srcContext->blitSurface,
      &g_pActiveQuickDrawSurfaceContext->blitSurface,
      &tStack_14, &local_24, 0);
}
