#include "game/TRailAmtBar.h"
#include "game/trade_quickdraw.h"
#include "game/TradeCommodityMetricRecord.h"
#include "game/NationState.h"
#include "game/TradeControl.h"
#include "game/UiRuntimeContext.h"
#include "game/ui_widget_thunks.h"
#include "game/quickdraw_guards.h"
#include <new>

// FUNCTION: IMPERIALISM 0x00589ed0
TRailAmtBar* __cdecl CreateTRailAmtBarInstance(void) {
  TRailAmtBar* amountBar = reinterpret_cast<TRailAmtBar*>(AllocateWithFallbackHandler(0x6c));
  if (amountBar != 0) {
    new (amountBar) TRailAmtBar;
  }
  return amountBar;
}

// FUNCTION: IMPERIALISM 0x00589f70
void* __cdecl GetTRailAmtBarClassNamePointer(void) {
  return reinterpret_cast<void*>(kAddrClassDescTRailAmtBar);
}

// FUNCTION: IMPERIALISM 0x00589f90
TRailAmtBar::TRailAmtBar() : TIndustryAmtBar() {}

// FUNCTION: IMPERIALISM 0x00589fd0
TRailAmtBar::~TRailAmtBar() {}

// FUNCTION: IMPERIALISM 0x0058a020
void TRailAmtBar::DoPostCreate(TDocument* document) {
  NationState* nationState = reinterpret_cast<NationState**>(
      kAddrGlobalNationStates)[g_pUiRuntimeContext->GetActiveNationId()];
  NationCityTradeState* cityState =
      nationState != 0 ? nationState->cityState : 0;
  int summaryTag = *reinterpret_cast<int*>(reinterpret_cast<char*>(this->field20) + 0x1c);

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
  this->thunk_NoOpUiLifecycleHook(reinterpret_cast<int>(document));
}

// FUNCTION: IMPERIALISM 0x0058a1c0
void TRailAmtBar::DrawAmt() {
  QuickDrawSurfaceGuard surface;
  TradeControl* control = reinterpret_cast<TradeControl*>(this);
  reinterpret_cast<void(__cdecl*)(int)>(ApplyHitRegionToClipState)(surface.surfaceWrapper);

  if (control != 0 && control->IsActionable() != 0) {
    control->Refresh();
    if (control->IsActionable() != 0) {
      int boundsRect[4] = {0, 0, 0, 0};
      control->QueryBounds(boundsRect);
      ApplyRectClipRegion(boundsRect);
      control->QueryBounds(boundsRect);
      control->CtrlSlot78();

      short styleValueAt60 = *reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x60);
      if (styleValueAt60 > 0) {
        SetQuickDrawTextOrigin(0, 1);
        ApplyQuickDrawStyleFromRuntime(0);
        SetQuickDrawStylePair(1, 4);
        DrawCenteredGuideLine((short)(styleValueAt60 - 1), 1);
        reinterpret_cast<void(__cdecl*)()>(ResetQuickDrawStrokeState)();
      }

      short overlayOffsetX = *reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x62);
      short overlayOffsetY = *reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x38);
      SetQuickDrawTextOrigin(overlayOffsetX, 0);
      SetQuickDrawFillColor(0);
      reinterpret_cast<void(__cdecl*)()>(ResetQuickDrawStrokeState)();
      DrawCenteredGuideLine(overlayOffsetX, (short)(overlayOffsetY - 2));

      reinterpret_cast<void(__cdecl*)()>(SnapshotHitRegionToClipCache)();
      TradeControl* owner = reinterpret_cast<TradeControl*>(CallOwnerPanelSlot58(control));
      if (owner != 0) {
        owner->InvokeSlot13C();
      }
    }
  }
}
