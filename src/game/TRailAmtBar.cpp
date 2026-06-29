#include "game/TIndustryCluster.h"
#include "game/TView.h"
#include "game/TRailCluster.h"
#include "game/TShipyardCluster.h"
#include "game/TTradeCluster.h"
#include "game/mfc.h"

#include "game/TAmtBar.h"
#include "game/TRailAmtBar.h"
#include "game/trade_quickdraw.h"
#include "game/TradeCommodityMetricRecord.h"
#include "game/TGreatPower.h"
#include "game/UiRuntimeContext.h"
#include "game/ui_widget_thunks.h"
#include "game/quickdraw_guards.h"
#include <new>

#include "game/mfc.h"

extern "C" {
// GLOBAL: IMPERIALISM 0x00662fe0
CRuntimeClass g_pClassDescTRailAmtBar = {nullptr, 0, 0, nullptr, nullptr};
}

// FUNCTION: IMPERIALISM 0x00589ed0
TRailAmtBar* __cdecl CreateTRailAmtBarInstance(void) {
  return new TRailAmtBar();
}

// FUNCTION: IMPERIALISM 0x00589f70
CRuntimeClass* TRailAmtBar::GetRuntimeClass() const {
  return &g_pClassDescTRailAmtBar;
}

// FUNCTION: IMPERIALISM 0x00589f90
TRailAmtBar::TRailAmtBar() : TIndustryAmtBar() {}

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x00589fd0
// TRailAmtBar::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x0058a020
void TRailAmtBar::NoOpUiLifecycleHook(int arg) {
  TGreatPower* nationState = reinterpret_cast<TGreatPower**>(
      kAddrGlobalNationStates)[g_pUiRuntimeContext->GetActiveNationId()];
  NationCityTradeState* cityState = nationState != 0 ? GetNationTradeCityState(nationState) : 0;
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
    CityTradeScenarioDescriptor* scenario = cityState->scenarioTradeDescriptor;
    CityTradeProductionSlots* slots = scenario->productionSlots;
    productionOrCapValue = (short)(((slots->valueAt8 * 2 + slots->valueAt6) * 2 +
                                    scenario->extraAt1E + slots->valueAt4) /
                                   2);
  } else {
    productionOrCapValue = selectedMetricRecord->QueryStepValue();
  }

  if (productionOrCapValue == 0) {
    stepOrCurrentValue = 9999;
  } else {
    short selectedStep = selectedMetricRecord->QueryStepValue();
    stepOrCurrentValue = (short)(((int)selectedStep * this->field34) / (int)productionOrCapValue);
  }
  auxValueA = productionOrCapValue;
  if (productionOrCapValue == 0) {
    rangeOrMaxValue = 9999;
  } else {
    rangeOrMaxValue = (short)((this->field34 * (int)selectedMetricRecord->controlValue) /
                              (int)productionOrCapValue);
  }
  auxValueB = 0x3a;
  reinterpret_cast<TView*>(this)->TView::NoOpUiLifecycleHook(arg);
}

// FUNCTION: IMPERIALISM 0x0058a1b0
void TRailAmtBar::RenderPrimarySurfaceOverlayPanelWithClipCache() {
  QuickDrawSurfaceGuard surface;
  TAmtBar* control = reinterpret_cast<TAmtBar*>(this);
  ApplyHitRegionToClipState(reinterpret_cast<int*>(surface.surfaceWrapper));

  if (control != 0 && control->IsActionable() != 0) {
    control->Refresh();
    if (control->IsActionable() != 0) {
      RECT boundsRect = {0, 0, 0, 0};
      control->QueryBounds(&boundsRect);
      ApplyRectClipRegion(&boundsRect);
      control->QueryBounds(&boundsRect);
      control->TranslatePointToParentChain4E();

      short styleValueAt60 = *reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x60);
      if (styleValueAt60 > 0) {
        SetQuickDrawTextOrigin(0, 1);
        ApplyQuickDrawStyleFromRuntime(0);
        SetQuickDrawStylePair(1, 4);
        DrawCenteredGuideLine((short)(styleValueAt60 - 1), 1);
        ResetQuickDrawStrokeState();
      }

      short overlayOffsetX = *reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x62);
      short overlayOffsetY = *reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x38);
      SetQuickDrawTextOrigin(overlayOffsetX, 0);
      SetQuickDrawFillColor(0);
      ResetQuickDrawStrokeState();
      DrawCenteredGuideLine(overlayOffsetX, (short)(overlayOffsetY - 2));

      reinterpret_cast<void(__cdecl*)()>(SnapshotHitRegionToClipCache)();
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
  QuickDrawSurfaceGuard surface;
  *reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x62) = selectedValue;
  ApplyHitRegionToClipState(reinterpret_cast<int*>(surface.surfaceWrapper));

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
