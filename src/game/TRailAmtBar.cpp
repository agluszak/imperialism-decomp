#include "game/TIndustryCluster.h"
#include "game/TView.h"
#include "game/TRailCluster.h"
#include "game/TShipyardCluster.h"
#include "game/TTradeCluster.h"
#include "game/mfc.h"

#include "game/TAmtBar.h"
#include "game/TRailAmtBar.h"
#include "game/global_data_tables.h"
#include "game/ui_invalidation_guard.h"
#include "game/quickdraw_rendering.h"
#include "game/ui_control_tags.h"
#include "game/TProductionOrder.h"
#include "game/TCity.h"
#include "game/TGreatPower.h"
#include "game/UiRuntimeContext.h"
#include "game/ui_widget_thunks.h"
#include "game/quickdraw_guards.h"
#include <new>

#include "game/mfc.h"

// FUNCTION: IMPERIALISM 0x00589ed0
TRailAmtBar* __cdecl CreateTRailAmtBarInstance(void) {
  return new TRailAmtBar();
}

// SYNTHETIC: IMPERIALISM 0x00589f70
// TRailAmtBar::GetRuntimeClass

IMPLEMENT_DYNCREATE(TRailAmtBar, TIndustryAmtBar)

// FUNCTION: IMPERIALISM 0x00589f90
TRailAmtBar::TRailAmtBar() : TIndustryAmtBar() {}

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x00589fd0
// TRailAmtBar::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x0058a020
void TRailAmtBar::NoOpUiLifecycleHook(int arg) {
  TGreatPower* nationState = GetActiveNationState();
  TCity* cityState = nationState != 0 ? nationState->GetCityState() : 0;
  int summaryTag = *reinterpret_cast<int*>(reinterpret_cast<char*>(this->ownerContext) + 0x1c);

  short recordIndex = 0;
  if ((unsigned int)summaryTag < 0x706f7076) {
    if (summaryTag == kSummaryTagPopu) {
      recordIndex = 0x3c;
    } else if (summaryTag == kSummaryTagFood) {
      recordIndex = 7;
    }
  } else if ((unsigned int)summaryTag < 0x70726f67) {
    if (summaryTag == kSummaryTagProf) {
      recordIndex = 0x18;
    } else if (summaryTag == kSummaryTagPowe) {
      recordIndex = 0x34;
    }
  } else if (summaryTag == kSummaryTagRail) {
    recordIndex = 0x33;
  } else if (summaryTag == kSummaryTagIart) {
    recordIndex = 0x17;
  }

  selectedMetricRecord = cityState->tradeCommodityRecordPtrs[recordIndex];

  short productionOrCapValue = 0;
  if (recordIndex == 0x33 || recordIndex == 7) {
    TPopulationMgr* scenario = cityState->productionSummary1d8;
    TPopulationMetricBucket* slots = scenario->productionSlots14;
    productionOrCapValue = (short)(((slots->valueAt8 * 2 + slots->valueAt6) * 2 +
                                    scenario->extraAt1e + slots->valueAt4) /
                                   2);
  } else {
    productionOrCapValue = selectedMetricRecord->MaxOrder();
  }

  if (productionOrCapValue == 0) {
    stepOrCurrentValue = 9999;
  } else {
    short selectedStep = selectedMetricRecord->MaxOrder();
    stepOrCurrentValue = (short)(((int)selectedStep * this->field34) / (int)productionOrCapValue);
  }
  auxValueA = productionOrCapValue;
  if (productionOrCapValue == 0) {
    rangeOrMaxValue = 9999;
  } else {
    rangeOrMaxValue = (short)((this->field34 * (int)selectedMetricRecord->quantityField04) /
                              (int)productionOrCapValue);
  }
  auxValueB = 0x3a;
  reinterpret_cast<TView*>(this)->TView::NoOpUiLifecycleHook(arg);
}

// FUNCTION: IMPERIALISM 0x0058a1b0
void TRailAmtBar::RenderPrimarySurfaceOverlayPanelWithClipCache() {
  CTemporaryRegion surface;
  TAmtBar* control = reinterpret_cast<TAmtBar*>(this);
  GetClip(surface.tempRgn);

  if (control != 0 && control->IsActionable() != 0) {
    control->Refresh();
    if (control->IsActionable() != 0) {
      RECT boundsRect = {0, 0, 0, 0};
      control->QueryBounds(&boundsRect);
      ClipRect(&boundsRect);
      control->QueryBounds(&boundsRect);
      control->TranslatePointToParentChain4E();

      short styleValueAt60 = *reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x60);
      if (styleValueAt60 > 0) {
        SetQuickDrawTextOriginWithContextOffset(0, 1);
        g_pUiRuntimeContext->ApplyLegendSplitSlot34(0);
        SetQuickDrawStylePair_1D08_1D0C_AndMarkDirty(1, 4);
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
      TAmtBar* owner = reinterpret_cast<TAmtBar*>(reinterpret_cast<TView*>(control)->OwnerPanel());
      if (owner != 0) {
        owner->InvokeSlot13C();
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x0058a3b0
void __fastcall RenderQuickDrawOverlayWithHitRegion_0058a3b0(TAmtBar* control, int unusedEdx,
                                                             short selectedValue) {
  (void)unusedEdx;
  CTemporaryRegion surface;
  *reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x62) = selectedValue;
  GetClip(surface.tempRgn);

  if (control != 0 && control->IsActionable() != 0) {
    control->Refresh();
    if (control->IsActionable() != 0) {
      RECT boundsRect = {0, 0, 0, 0};
      control->QueryBounds(&boundsRect);
      control->TranslatePointToParentChain4E();

      RECT invalidRect;
      invalidRect.left = boundsRect.left;
      invalidRect.top = boundsRect.top;
      invalidRect.right =
          boundsRect.left + (int)*reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x34);
      invalidRect.bottom =
          boundsRect.top + (int)*reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x38);
      reinterpret_cast<TView*>(control)->InvalidateCityDialogRectRegion(&invalidRect, 1);
    }
  }
}
