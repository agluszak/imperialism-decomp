#include "game/TIndustryCluster.h"
#include "game/TWindow.h"
#include "game/TView.h"
#include "game/TRailCluster.h"
#include "game/TShipyardCluster.h"
#include "game/TTradeCluster.h"

#include "game/TAmtBar.h"
#include "game/TIndustryAmtBar.h"
#include "game/global_data_tables.h"
#include "game/ui_invalidation_guard.h"
#include "game/TItemOrder.h"
#include "game/UiRuntimeContext.h"
#include "game/quickdraw_guards.h"
#include "game/mfc.h"
#include <new>
#include "game/TGreatPower.h"
#include "game/TCity.h"
#include "game/quickdraw_rendering.h"
#include "game/ui_control_tags.h"


// SYNTHETIC: IMPERIALISM 0x00589110
// TIndustryAmtBar::CreateObject
// SYNTHETIC: IMPERIALISM 0x005891b0
// TIndustryAmtBar::GetRuntimeClass

IMPLEMENT_DYNCREATE(TIndustryAmtBar, TAmtBar)

// FUNCTION: IMPERIALISM 0x005891d0
TIndustryAmtBar::TIndustryAmtBar() : TAmtBar(), selectedMetricRecord(0) {}

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x00589210
// TIndustryAmtBar::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x00589260
void TIndustryAmtBar::DoPostCreate(int arg) {
  // ORIG_CALLCONV: __thiscall
  TGreatPower* nationState = GetActiveNationState();
  TCity* province = nationState != 0 ? nationState->GetCityState() : 0;
  short summaryTagIndex = 0;
  int mappedTag = GetTradeSummarySelectionTagByIndex(summaryTagIndex);
  int summaryTag = *reinterpret_cast<int*>(reinterpret_cast<char*>(this->ownerContext) + 0x1c);
  while (mappedTag != summaryTag) {
    summaryTagIndex = (short)(summaryTagIndex + 1);
    mappedTag = GetTradeSummarySelectionTagByIndex(summaryTagIndex);
  }

  selectedMetricRecord = province->tradeCommodityRecordPtrs[summaryTagIndex];
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
  int rangeRaw = this->frameWidth34;
  stepOrCurrentValue = (short)((stepValue * rangeRaw) / productionCap);

  auxValueA = productionCap;
  auxValueB = 0x3a;
  rangeOrMaxValue = (short)((selectedMetricRecord->quantityField04 * rangeRaw) / productionCap);

  reinterpret_cast<TView*>(this)->TView::DoPostCreate(arg);
}

// FUNCTION: IMPERIALISM 0x00589340
void TIndustryAmtBar::RenderPrimarySurfaceOverlayPanelWithClipCache() {
  CTemporaryRegion surface;
  TAmtBar* control = reinterpret_cast<TAmtBar*>(this);
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

      short styleValueAt60 = *reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x60);
      if (styleValueAt60 > 0) {
        g_pUiRuntimeContext->ApplyLegendSplitSlot34(0);
        SetQuickDrawPenSizeAndMarkDirty(1, 4);
        SetQuickDrawTextOriginWithContextOffset(0, 1);
        DrawCenteredGuideLineOnMapDc((short)(styleValueAt60 - 1), 1);
        ResetQuickDrawStrokeState();
      }

      short overlayOffsetX = *reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x62);
      short overlayOffsetY = *reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x38);
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
void TIndustryAmtBar::RenderQuickDrawOverlayWithHitRegion(short selectedValue) {
  CTemporaryRegion surface;
  stepOrCurrentValue = selectedValue;
  GetClip(surface.tempRgn);

  if (IsActionable() != 0) {
    PrepareForDrawing();
    if (IsActionable() != 0) {
      CPoint translatedOrigin(g_nOverlayClipCacheParamX, g_nOverlayClipCacheParamY);
      TranslatePointToParentChain4E(&translatedOrigin);
      RECT invalidRect = {translatedOrigin.x, translatedOrigin.y, translatedOrigin.x + frameWidth34,
                          translatedOrigin.y + frameHeight38};
      InvalidateCityDialogRectRegion(&invalidRect, 1);
    }
  }
}
