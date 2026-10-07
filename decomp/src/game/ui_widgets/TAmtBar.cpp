#include <new>
#include "game/ui_tags_common.h"
#include "game/ui_core/TNumberText.h"
#include "game/ui_core/TWindow.h"

#include "game/globals/global_types.h"
#include "game/globals/gfx_globals.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_widgets_globals.h"
#include "game/ui_widgets/TAmtBar.h"
#include "game/ui_widgets/TAmtBarCluster.h"
#include "game/TQuickDrawSurfaceContext.h"
#include "game/ui_core/TViewMgr.h"
#include "game/quickdraw_guards.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/mfc.h"

// FUNCTION: IMPERIALISM 0x00586e50
short TAmtBar::ApplyMoveClamp(int baseValue, short requestedValue) {
  return baseValue;
}

IMPLEMENT_DYNCREATE(TAmtBar, TView)

// FUNCTION: IMPERIALISM 0x005885f0
TAmtBar::~TAmtBar() {}

// FUNCTION: IMPERIALISM 0x00588610
void TAmtBar::DoPostCreate(int arg) {
  TView::DoPostCreate(arg);
}

// FUNCTION: IMPERIALISM 0x00588630
void TAmtBar::UpdateBarValuesAndRefresh(short valueAt60, short valueAt62) {
  this->rangeOrMaxValue = valueAt60;
  this->stepOrCurrentValue = valueAt62;
  this->RefreshControl();
  this->ForceRedraw();
}

// FUNCTION: IMPERIALISM 0x00588670
void TAmtBar::Draw(RECT* rectBuffer) {
  DrawAmt();
}

// FUNCTION: IMPERIALISM 0x00588690
void TAmtBar::DrawAmt() {
  CTemporaryRegion surface;
  short barRange = rangeOrMaxValue;
  CRect contentBounds;
  CRect frameBounds;
  short controlWidth;
  short controlHeight;
  RECT panelRect;
  RECT contentRect;
  short guideValue = 0;
  short fillOrigin;

  GetClip(surface.tempRgn);

  if (!this->IsActionable() || !this->PrepareForDrawing()) {
    return;
  }

  this->QueryContentBounds(&contentBounds);
  ClipRect(&contentBounds);

  this->QueryBounds(&frameBounds);

  CPoint translatedOrigin(g_nOverlayClipCacheParamX, g_nOverlayClipCacheParamY);
  this->TranslatePointToParentChain4E(&translatedOrigin);

  controlWidth = (short)this->frameWidth;
  controlHeight = (short)this->frameHeight;

  panelRect.left = translatedOrigin.x;
  panelRect.top = translatedOrigin.y;
  panelRect.right = translatedOrigin.x + (int)controlWidth;
  panelRect.bottom = translatedOrigin.y + (int)controlHeight;

  contentRect.left = contentBounds.left;
  contentRect.top = contentBounds.top;
  contentRect.right = contentBounds.right;
  contentRect.bottom = contentBounds.bottom;

  BlitRectWithOptionalTransparency(g_pPrimaryRenderSurfaceContext->GetBlitSurface(),
                                   g_pActiveQuickDrawSurfaceContext->GetBlitSurface(), &panelRect,
                                   &contentRect, 0);

  if (barRange > 0) {
    SetQuickDrawTextOriginWithContextOffset(0, 1);
    g_pViewMgr->SetForeColor(static_cast<short>(auxValueB));
    SetQuickDrawPenSizeAndMarkDirty(1, 7);
    guideValue = stepOrCurrentValue < barRange ? stepOrCurrentValue : barRange;
    DrawCenteredGuideLineOnMapDc((short)(guideValue - 1), 1);
    ResetQuickDrawStrokeState();
  }

  fillOrigin = guideValue > 0 ? (short)(guideValue + 1) : 0;
  SetQuickDrawTextOriginWithContextOffset(fillOrigin, 4);
  SetQuickDrawFillColor(0);
  SetQuickDrawPenSizeAndMarkDirty(1, 1);
  DrawCenteredGuideLineOnMapDc(controlWidth, 4);
  SetQuickDrawTextOriginWithContextOffset(stepOrCurrentValue, 0);
  ResetQuickDrawStrokeState();
  DrawCenteredGuideLineOnMapDc((short)(stepOrCurrentValue - 1), controlHeight);
  SetClip(surface.tempRgn);
}

// FUNCTION: IMPERIALISM 0x00588950
void TAmtBar::DoMouseCommand(CPoint& point, TToolboxEvent* event, CPoint origin) {
  int baseValue;
  if (auxValueA <= 0 ||
      static_cast<int>(frameWidth) / (static_cast<int>(auxValueA) << 1) <= point.x) {
    double ratio = static_cast<double>(point.x) * static_cast<double>(auxValueA) /
                       static_cast<double>(static_cast<int>(frameWidth)) +
                   1.0;
    baseValue = static_cast<int>(ratio);
  } else {
    baseValue = 0;
  }

  short appliedValue = ApplyMoveClamp(baseValue, static_cast<short>(point.x));
  TView* owner = this->ownerContext;
  if ((appliedValue == 0) && point.x != 0) {
    TNumberText* fallbackControl =
        static_cast<TNumberText*>(owner->ResolveControlByTag(kControlTagMove));
    if (fallbackControl == 0) {
      fallbackControl = static_cast<TNumberText*>(owner->ResolveControlByTag(kControlTagSell));
    }
    if (fallbackControl != 0 &&
        static_cast<short>(fallbackControl->UpdateControlCachedIntFromWindowText()) == 0) {
      appliedValue = 1;
    }
  }

  static_cast<TAmtBarCluster*>(owner)->SetMoveAmount(appliedValue);
}
