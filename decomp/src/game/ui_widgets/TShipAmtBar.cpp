#include "game/ui_widgets/TAmtBar.h"
#include "game/ui_core/TWindow.h"
#include "game/ui_widgets/TShipAmtBar.h"
#include "game/city/TShipOrder.h"
#include "game/city/TCity.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_core/TViewMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_widgets_globals.h"
#include "game/quickdraw_guards.h"
#include "game/ui_core/quickdraw_rendering.h"

IMPLEMENT_DYNCREATE(TShipAmtBar, TAmtBar)

// FUNCTION: IMPERIALISM 0x0058ab60
TShipAmtBar::TShipAmtBar() : TAmtBar() {
  rangeOrMaxValue = 0;
  stepOrCurrentValue = 0;
  auxValueA = 0;
  auxValueB = 0;
}

// FUNCTION: IMPERIALISM 0x0058abf0
void TShipAmtBar::DoPostCreate(int arg) {
  TGreatPower* nationState = g_apNationStates[g_pSimMgr->GetPlayerCountry()];
  TCity* province = nationState != 0 ? nationState->GetCityState() : 0;
  selectedMetricRecord = province->shipOrderSlots[0];
  short productionCap = province->productionSummary->strength;
  stepOrCurrentValue = static_cast<short>(frameWidth);
  auxValueA = productionCap;
  auxValueB = 0x3a;
  rangeOrMaxValue = static_cast<short>(0 / static_cast<int>(productionCap));
  TView::DoPostCreate(arg);
}

// FUNCTION: IMPERIALISM 0x0058ac80
void TShipAmtBar::DrawAmt() {
  CTemporaryRegion surface;
  TAmtBar* control = this;
  GetClip(surface.tempRgn);

  if (control != 0 && control->IsActionable()) {
    control->PrepareForDrawing();
    if (control->IsActionable()) {
      CRect boundsRect(0, 0, 0, 0);
      control->GetFrame(&boundsRect);
      ClipRect(&boundsRect);
      control->GetFrame(&boundsRect);
      CPoint translatedOrigin(g_nOverlayClipCacheParamX, g_nOverlayClipCacheParamY);
      control->TranslatePointToParentChain4E(&translatedOrigin);

      if (rangeOrMaxValue > 0) {
        SetQuickDrawTextOriginWithContextOffset(0, 1);
        g_pViewMgr->SetForeColor(static_cast<short>(auxValueB));
        SetQuickDrawPenSizeAndMarkDirty(1, 4);
        DrawCenteredGuideLineOnMapDc(static_cast<short>(rangeOrMaxValue - 1), 1);
        ResetQuickDrawStrokeState();
      }

      SetQuickDrawTextOriginWithContextOffset(stepOrCurrentValue, 0);
      SetQuickDrawFillColor(0);
      ResetQuickDrawStrokeState();
      DrawCenteredGuideLineOnMapDc(stepOrCurrentValue, static_cast<short>(frameHeight - 2));

      SetClip(surface.tempRgn);
      TView* owner = control->GetWindow();
      if (owner != 0) {
        owner->ForceRedraw();
      }
    }
  }
}
