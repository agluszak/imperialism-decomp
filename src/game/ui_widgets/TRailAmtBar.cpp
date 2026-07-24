#include "game/ui_widgets/TIndustryCluster.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_widgets.h"
#include "game/ui_core/TWindow.h"
#include "game/ui_core/TView.h"
#include "game/ui_widgets/TRailCluster.h"
#include "game/ui_widgets/TShipyardCluster.h"
#include "game/ui_widgets/TTradeCluster.h"
#include "game/mfc.h"

#include "game/ui_widgets/TAmtBar.h"
#include "game/ui_widgets/TRailAmtBar.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_widgets_globals.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/city/TProductionOrder.h"
#include "game/city/TCity.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_core/TViewMgr.h"
#include "game/quickdraw_guards.h"
#include <new>

// SYNTHETIC: IMPERIALISM 0x00589ed0
// TRailAmtBar::CreateObject

// SYNTHETIC: IMPERIALISM 0x00589f70
// TRailAmtBar::GetRuntimeClass

// The original descriptor's m_pBaseClass (0x662ff0) points at TAmtBar's CRuntimeClass —
// the retail macro skipped the real C++ base TIndustryAmtBar (both classes are 0x6c with
// the same inlined ctor chain down to TView). Reproduce the retail macro argument.
IMPLEMENT_DYNCREATE(TRailAmtBar, TAmtBar)

// FUNCTION: IMPERIALISM 0x00589f90
TRailAmtBar::TRailAmtBar() : TIndustryAmtBar() {}

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x00589fd0
// TRailAmtBar::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x0058a020
void TRailAmtBar::DoPostCreate(int arg) {
  TGreatPower* nationState = g_apNationStates[g_pSimMgr->GetActiveNationId()];
  TCity* province = nationState != 0 ? nationState->GetCityState() : 0;
  int summaryTag = this->ownerContext->controlTag;

  short recordIndex = 0;
  if ((unsigned int)summaryTag < kControlTagPopv) {
    if (summaryTag == kSummaryTagPopu) {
      recordIndex = 0x3c;
    } else if (summaryTag == kSummaryTagFood) {
      recordIndex = 7;
    }
  } else if ((unsigned int)summaryTag < kControlTagProg) {
    if (summaryTag == kSummaryTagProf) {
      recordIndex = 0x18;
    } else if (summaryTag == kSummaryTagPowe) {
      recordIndex = 0x34;
    }
  } else if (summaryTag == kSummaryTagRail) {
    recordIndex = 0x33;
  } else if (summaryTag == kSummaryTagTrai) {
    recordIndex = 0x17;
  }

  selectedMetricRecord = province->tradeCommodityRecordPtrs[recordIndex];

  short productionOrCapValue = 0;
  if (recordIndex == 0x33 || recordIndex == 7) {
    TPopulationMgr* scenario = province->productionSummary1d8;
    TLaborPool* slots = scenario->productionSlots14;
    productionOrCapValue = (short)(((slots->highSkillCount08 * 2 + slots->mediumSkillCount06) * 2 +
                                    scenario->extraAt1e + slots->lowSkillCount04) /
                                   2);
  } else {
    productionOrCapValue = selectedMetricRecord->MaxOrder();
  }

  if (productionOrCapValue == 0) {
    stepOrCurrentValue = 9999;
  } else {
    short selectedStep = selectedMetricRecord->MaxOrder();
    stepOrCurrentValue =
        (short)(((int)selectedStep * this->frameWidth34) / (int)productionOrCapValue);
  }
  auxValueA = productionOrCapValue;
  if (productionOrCapValue == 0) {
    rangeOrMaxValue = 9999;
  } else {
    rangeOrMaxValue = (short)((this->frameWidth34 * (int)selectedMetricRecord->quantityField04) /
                              (int)productionOrCapValue);
  }
  auxValueB = 0x3a;
  TView::DoPostCreate(arg);
}

// FUNCTION: IMPERIALISM 0x0058a1b0
void TRailAmtBar::RenderPrimarySurfaceOverlayPanelWithClipCache() {
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

      short styleValueAt60 = control->rangeOrMaxValue;
      if (styleValueAt60 > 0) {
        SetQuickDrawTextOriginWithContextOffset(0, 1);
        g_pUiRuntimeContext->ApplyLegendSplitSlot34(0);
        SetQuickDrawPenSizeAndMarkDirty(1, 4);
        DrawCenteredGuideLineOnMapDc((short)(styleValueAt60 - 1), 1);
        ResetQuickDrawStrokeState();
      }

      short overlayOffsetX = control->stepOrCurrentValue;
      short overlayOffsetY = static_cast<short>(control->frameHeight38);
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

// FUNCTION: IMPERIALISM 0x0058a3b0
void TRailAmtBar::RenderQuickDrawOverlayWithHitRegion(short selectedValue) {
  CTemporaryRegion surface;
  stepOrCurrentValue = selectedValue;
  GetClip(surface.tempRgn);

  if (IsActionable() != 0) {
    PrepareForDrawing();
    if (IsActionable() != 0) {
      CPoint translatedOrigin(g_nOverlayClipCacheParamX, g_nOverlayClipCacheParamY);
      TranslatePointToParentChain4E(&translatedOrigin);

      RECT invalidRect;
      invalidRect.left = translatedOrigin.x;
      invalidRect.top = translatedOrigin.y;
      invalidRect.right = translatedOrigin.x + frameWidth34;
      invalidRect.bottom = translatedOrigin.y + frameHeight38;
      InvalidateCityDialogRectRegion(&invalidRect, 1);
    }
  }
}
