#include "game/ui_widgets/TIndustryCluster.h"
#include "game/ui_core/TWindow.h"
#include "game/ui_core/TView.h"
#include "game/ui_widgets/TRailCluster.h"
#include "game/ui_widgets/TShipyardCluster.h"
#include "game/ui_widgets/TTradeCluster.h"

#include "game/ui_widgets/TAmtBar.h"
#include "game/ui_widgets/TIndustryAmtBar.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_widgets_globals.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/city/TItemOrder.h"
#include "game/ui_core/TViewMgr.h"
#include "game/quickdraw_guards.h"
#include "game/mfc.h"
#include <new>
#include "game/nation/TGreatPower.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/city/TCity.h"
#include "game/ui_core/quickdraw_rendering.h"

IMPLEMENT_DYNCREATE(TIndustryAmtBar, TAmtBar)

// FUNCTION: IMPERIALISM 0x005891d0
TIndustryAmtBar::TIndustryAmtBar() : TAmtBar(), selectedMetricRecord(0) {}

// Destructors are compiler-generated (implicit) from real inheritance.

// FUNCTION: IMPERIALISM 0x00589260
void TIndustryAmtBar::DoPostCreate(int arg) {
  // ORIG_CALLCONV: __thiscall
  TGreatPower* nationState = g_apNationStates[g_pSimMgr->GetPlayerCountry()];
  TCity* province = nationState != 0 ? nationState->GetCityState() : 0;
  short summaryTagIndex = 0;
  int mappedTag = g_pTradeSummarySelectionMap[summaryTagIndex];
  int summaryTag = this->ownerContext->controlTag;
  while (mappedTag != summaryTag) {
    summaryTagIndex = (short)(summaryTagIndex + 1);
    mappedTag = g_pTradeSummarySelectionMap[summaryTagIndex];
  }

  selectedMetricRecord = province->orderSlots[summaryTagIndex];
  // `productionSlot` only exists on TItemOrder-sized (0x54-byte) objects. This
  // downcast is safe here: the summary-tag scan above bounds summaryTagIndex
  // to the 23-entry g_pTradeSummarySelectionMap table (0x696108), so tagIndex
  // never reaches the TTrainingOrder slots (0x17/0x18, object size 0x4c) that
  // share this band — see g_pTradeSummarySelectionMap's doc comment in
  // global_data_tables.cpp.
  int productionValue = nationState->GetCityState()->GetBuildingType(
      static_cast<TItemOrder*>(selectedMetricRecord)->productionSlot);

  short stepValue = selectedMetricRecord->MaxOrder();
  short productionCap = (short)productionValue;
  int rangeRaw = this->frameWidth;
  stepOrCurrentValue = (short)((stepValue * rangeRaw) / productionCap);

  auxValueA = productionCap;
  auxValueB = 0x3a;
  rangeOrMaxValue = (short)((selectedMetricRecord->quantity * rangeRaw) / productionCap);

  TView::DoPostCreate(arg);
}

// FUNCTION: IMPERIALISM 0x00589340
void TIndustryAmtBar::DrawAmt() {
  CTemporaryRegion surface;
  TAmtBar* control = this;
  GetClip(surface.tempRgn);

  if (control != 0 && control->IsActionable()) {
    control->PrepareForDrawing();
    if (control->IsActionable()) {
      CRect boundsRect(0, 0, 0, 0);
      control->QueryBounds(&boundsRect);
      ClipRect(&boundsRect);
      control->QueryBounds(&boundsRect);
      CPoint translatedOrigin(g_nOverlayClipCacheParamX, g_nOverlayClipCacheParamY);
      control->TranslatePointToParentChain4E(&translatedOrigin);

      short styleValueAt60 = control->rangeOrMaxValue;
      if (styleValueAt60 > 0) {
        g_pViewMgr->ApplyLegendSplitSlot34(0);
        SetQuickDrawPenSizeAndMarkDirty(1, 4);
        SetQuickDrawTextOriginWithContextOffset(0, 1);
        DrawCenteredGuideLineOnMapDc((short)(styleValueAt60 - 1), 1);
        ResetQuickDrawStrokeState();
      }

      short overlayOffsetX = control->stepOrCurrentValue;
      short overlayOffsetY = static_cast<short>(control->frameHeight);
      SetQuickDrawTextOriginWithContextOffset(overlayOffsetX, 0);
      SetQuickDrawFillColor(0);
      ResetQuickDrawStrokeState();
      DrawCenteredGuideLineOnMapDc(overlayOffsetX, (short)(overlayOffsetY - 2));

      SetClip(surface.tempRgn);
      TWindow* owner = control->GetWindow();
      if (owner != 0) {
        owner->ForceRedraw();
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x00589540
void TIndustryAmtBar::DrawMax(short selectedValue) {
  CTemporaryRegion surface;
  stepOrCurrentValue = selectedValue;
  GetClip(surface.tempRgn);

  if (IsActionable()) {
    PrepareForDrawing();
    if (IsActionable()) {
      CPoint translatedOrigin(g_nOverlayClipCacheParamX, g_nOverlayClipCacheParamY);
      TranslatePointToParentChain4E(&translatedOrigin);
      RECT invalidRect = {translatedOrigin.x, translatedOrigin.y, translatedOrigin.x + frameWidth,
                          translatedOrigin.y + frameHeight};
      InvalidateCityDialogRectRegion(&invalidRect, 1);
    }
  }
}
