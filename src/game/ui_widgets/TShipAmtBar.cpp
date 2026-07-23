#include "game/ui_widgets/TAmtBar.h"
#include "game/ui_core/TWindow.h"
#include "game/ui_widgets/TShipAmtBar.h"
#include "game/city/TShipOrder.h"
#include "game/city/TCity.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_core/TViewMgr.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_widgets_globals.h"
#include "game/quickdraw_guards.h"
#include "game/ui_core/quickdraw_rendering.h"

// SYNTHETIC: IMPERIALISM 0x0058ab40
// TShipAmtBar::GetRuntimeClass

IMPLEMENT_DYNCREATE(TShipAmtBar, TAmtBar)

// SYNTHETIC: IMPERIALISM 0x0058aaa0
// TShipAmtBar::CreateObject

// FUNCTION: IMPERIALISM 0x0058ab60
TShipAmtBar::TShipAmtBar() : TAmtBar() {
  rangeOrMaxValue = 0;
  stepOrCurrentValue = 0;
  auxValueA = 0;
  auxValueB = 0;
}

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x0058aba0
// TShipAmtBar::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x0058abf0
void TShipAmtBar::DoPostCreate(int arg) {
  TGreatPower* nationState = GetActiveNationState();
  TCity* province = nationState != 0 ? nationState->GetCityState() : 0;
  selectedMetricRecord = province->shipOrderSlots[0];
  short productionCap = province->productionSummary1d8->strength;
  stepOrCurrentValue = (short)this->frameWidth34;
  auxValueA = productionCap;
  auxValueB = 0x3a;
  rangeOrMaxValue = (short)(0 / (int)productionCap);
  TView::DoPostCreate(arg);
}

// FUNCTION: IMPERIALISM 0x0058ac80
void TShipAmtBar::RenderPrimarySurfaceOverlayPanelWithClipCache() {
  CTemporaryRegion surface;
  TAmtBar* control = this;
  GetClip(surface.tempRgn);

  if (control != 0 && control->IsActionable() != 0) {
    control->PrepareForDrawing();
    if (control->IsActionable() != 0) {
      CRect boundsRect(0, 0, 0, 0);
      control->QueryBounds(&boundsRect);
      ClipRect(&boundsRect);
      control->QueryBounds(&boundsRect);
      CPoint translatedOrigin(g_nOverlayClipCacheParamX, g_nOverlayClipCacheParamY);
      control->TranslatePointToParentChain4E(&translatedOrigin);

      if (rangeOrMaxValue > 0) {
        SetQuickDrawTextOriginWithContextOffset(0, 1);
        g_pUiRuntimeContext->ApplyLegendSplitSlot34(auxValueB);
        SetQuickDrawPenSizeAndMarkDirty(1, 4);
        DrawCenteredGuideLineOnMapDc((short)(rangeOrMaxValue - 1), 1);
        ResetQuickDrawStrokeState();
      }

      SetQuickDrawTextOriginWithContextOffset(stepOrCurrentValue, 0);
      SetQuickDrawFillColor(0);
      ResetQuickDrawStrokeState();
      DrawCenteredGuideLineOnMapDc(stepOrCurrentValue, (short)(frameHeight38 - 2));

      SetClip(surface.tempRgn);
      TView* owner = control->GetWindow();
      if (owner != 0) {
        owner->ForceRedraw();
      }
    }
  }
}
