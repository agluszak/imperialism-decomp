#include "game/TIndustryCluster.h"
#include "game/TRailCluster.h"
#include "game/TShipyardCluster.h"
#include "game/TTradeCluster.h"

#include "game/TAmtBar.h"
#include "game/TIndustryAmtBar.h"
#include "game/trade_quickdraw.h"
#include "game/TradeCommodityMetricRecord.h"
#include "game/UiRuntimeContext.h"
#include "game/quickdraw_guards.h"
#include "game/win_rect.h"
#include "game/ui_widget_thunks.h"
#include <new>
#include "game/TGreatPower.h"
#include "game/TCity.h"
#include "game/UiRuntimeContext.h"
#include "game/ui_widget_thunks.h"
#include "game/quickdraw_guards.h"
#include <new>

#include "game/CRuntimeClass.h"

extern "C" {
// GLOBAL: IMPERIALISM 0x00662fb0
CRuntimeClass g_pClassDescTIndustryAmtBar = {0};
}

// FUNCTION: IMPERIALISM 0x00589110
TIndustryAmtBar* __cdecl CreateTIndustryAmtBarInstance(void) {
  TIndustryAmtBar* amountBar =
      reinterpret_cast<TIndustryAmtBar*>(AllocateWithFallbackHandler(0x6c));
  if (amountBar != 0) {
    new (amountBar) TIndustryAmtBar;
  }
  return amountBar;
}

// FUNCTION: IMPERIALISM 0x005891b0
CRuntimeClass* TIndustryAmtBar::GetRuntimeClass() {
  return &g_pClassDescTIndustryAmtBar;
}

// FUNCTION: IMPERIALISM 0x005891d0
TIndustryAmtBar::TIndustryAmtBar() : TAmtBar(), selectedMetricRecord(0) {}

// FUNCTION: IMPERIALISM 0x00589210
TIndustryAmtBar::~TIndustryAmtBar() {}

// FUNCTION: IMPERIALISM 0x00589260
void TIndustryAmtBar::DoPostCreate(TDocument* document) {
  // ORIG_CALLCONV: __thiscall
  TGreatPower* nationState = reinterpret_cast<TGreatPower**>(
      kAddrGlobalNationStates)[g_pUiRuntimeContext->GetActiveNationId()];
  NationCityTradeState* cityState =
      nationState != 0 ? GetNationTradeCityState(nationState) : 0;
  short summaryTagIndex = 0;
  int mappedTag = GetTradeSummarySelectionTagByIndex(summaryTagIndex);
  int summaryTag = *reinterpret_cast<int*>(reinterpret_cast<char*>(this->ownerContext) + 0x1c);
  while (mappedTag != summaryTag) {
    summaryTagIndex = (short)(summaryTagIndex + 1);
    mappedTag = GetTradeSummarySelectionTagByIndex(summaryTagIndex);
  }

  selectedMetricRecord = cityState->tradeCommodityRecordPtrs[summaryTagIndex];
  int productionValue = nationState->GetCityState()->GetBuildingProductionValueBySlot(
      selectedMetricRecord->buildingSlot);

  short stepValue = selectedMetricRecord->QueryStepValue();
  short productionCap = (short)productionValue;
  int rangeRaw = this->field34;
  stepOrCurrentValue = (short)((stepValue * rangeRaw) / productionCap);

  auxValueA = productionCap;
  auxValueB = 0x3a;
  rangeOrMaxValue = (short)((selectedMetricRecord->controlValue * rangeRaw) / productionCap);

  this->thunk_NoOpUiLifecycleHook(reinterpret_cast<int>(document));
}

// FUNCTION: IMPERIALISM 0x00589dd0
void TIndustryAmtBar::DrawAmt() {
  QuickDrawSurfaceGuard surface;
  TAmtBar* control = reinterpret_cast<TAmtBar*>(this);
  reinterpret_cast<void(__cdecl*)(int)>(ApplyHitRegionToClipState)(surface.surfaceWrapper);

  if (control != 0 && control->IsActionable() != 0) {
    control->Refresh();
    if (control->IsActionable() != 0) {
      RECT boundsRect = {0, 0, 0, 0};
      control->QueryBounds(&boundsRect);
      ApplyRectClipRegion(&boundsRect);
      control->QueryBounds(&boundsRect);
      control->vmethod_0078();

      short styleValueAt60 = *reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x60);
      if (styleValueAt60 > 0) {
        ApplyQuickDrawStyleFromRuntime(0);
        SetQuickDrawStylePair(1, 4);
        SetQuickDrawTextOrigin(0, 1);
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

undefined4 thunk_InvalidateCityDialogRectRegion(void);

const unsigned int kAddrOverlayClipCacheParamX = 0x006A4450;
const unsigned int kAddrOverlayClipCacheParamY = 0x006A4454;

// FUNCTION: IMPERIALISM 0x00589540
void __fastcall RenderQuickDrawOverlayWithHitRegion_00589540(TAmtBar* control, int unusedEdx,
                                                             short selectedValue) {
  (void)unusedEdx;
  QuickDrawSurfaceGuard surface;
  *reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x62) = selectedValue;
  reinterpret_cast<void(__cdecl*)(int)>(ApplyHitRegionToClipState)(surface.surfaceWrapper);

  if (control != 0 && control->IsActionable() != 0) {
    control->Refresh();
    if (control->IsActionable() != 0) {
      int cachedX = ReadIntAt(kAddrOverlayClipCacheParamX);
      int cachedY = ReadIntAt(kAddrOverlayClipCacheParamY);
      int invalidRect[4] = {cachedX, cachedY, 0, 0};
      control->vmethod_0078();
      invalidRect[2] =
          cachedX + (int)*reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x34);
      invalidRect[3] =
          cachedY + (int)*reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x38);
      reinterpret_cast<void(__stdcall*)(int, int)>(thunk_InvalidateCityDialogRectRegion)(
          (int)invalidRect, 1);
    }
  }
}
