// Included by src/game/trade_screen.cpp.
// Contains trade-screen core logic functions (address-ordered).

// GHIDRA_NAME InitializeTradeSellControlState
// GHIDRA_PROTO void __cdecl InitializeTradeSellControlState(void)
// GHIDRA_COMMENT_BEGIN
// GHIDRA_COMMENT Initializes Sell/Bar/Arrow control style and enabled state for current
// nation/resource context; then initializes move/bar controls baseline. GHIDRA_COMMENT_END
/* Initializes Sell/Bar/Arrow control style and enabled state for current nation/resource context;
   then initializes move/bar controls baseline. */

#include "game/TIndustryAmtBar.h"
#include "game/TradeControl.h"
#include "game/UiRuntimeContext.h"
#include "game/ui_widget_thunks.h"
#include "game/win_rect.h"
#include <new>

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
void* __cdecl GetTIndustryAmtBarClassNamePointer(void) {
  return reinterpret_cast<void*>(kAddrClassDescTIndustryAmtBar);
}

// FUNCTION: IMPERIALISM 0x005891d0
TIndustryAmtBar::TIndustryAmtBar() : TAmtBar(), selectedMetricRecord(0) {
}

// FUNCTION: IMPERIALISM 0x00589210
TIndustryAmtBar::~TIndustryAmtBar() {
}

// FUNCTION: IMPERIALISM 0x00589260
void TIndustryAmtBar::DoPostCreate(TDocument* document) {
  // ORIG_CALLCONV: __thiscall
  NationState* nationState =
      reinterpret_cast<NationState**>(kAddrGlobalNationStates)[g_pUiRuntimeContext->GetActiveNationId()];
  NationCityTradeState* cityState = nationState != 0 ? reinterpret_cast<NationCityTradeState*>(nationState->cityState) : 0;
  short summaryTagIndex = 0;
  int mappedTag = GetTradeSummarySelectionTagByIndex(summaryTagIndex);
  while (mappedTag != ownerPanelContext()->summaryTag) {
    summaryTagIndex = (short)(summaryTagIndex + 1);
    mappedTag = GetTradeSummarySelectionTagByIndex(summaryTagIndex);
  }

  selectedMetricRecord = cityState->tradeCommodityRecordPtrs[summaryTagIndex];
  int productionValue = TradeScreenRuntimeBridge::GetCityBuildingProductionValueBySlot(
      cityState, selectedMetricRecord->buildingSlot);

  short stepValue = selectedMetricRecord->QueryStepValue();
  short productionCap = (short)productionValue;
  int rangeRaw = barRangeRaw();
  stepOrCurrentValue = (short)((stepValue * rangeRaw) / productionCap);

  auxValueA = productionCap;
  auxValueB = 0x3a;
  rangeOrMaxValue = (short)((selectedMetricRecord->controlValue * rangeRaw) / productionCap);

  this->thunk_NoOpUiLifecycleHook(reinterpret_cast<int>(document));
}

// FUNCTION: IMPERIALISM 0x00589da0
void TradeMoveStepCluster::HandleTradeMovePageStepCommand(int commandId, void* eventArg,
                                                          int eventExtra) {
  // ORIG_CALLCONV: __thiscall
  void* owner = this;
  if (commandId == 100) {
    TradeControl* moveControl = ResolveOwnerControl(owner, kControlTagMove);
    if (moveControl == 0) {
      MessageBoxA(0, kNilPointerText, kFailureCaption, 0x30);
    }
    short moveValue = (short)moveControl->QueryValue();
    CallApplyMoveValueSlot1D0(owner, (int)field_8e + (int)moveValue);
    return;
  }
  if (commandId != 0x65) {
    HandleTradeMoveControlAdjustment(this, commandId, eventArg, eventExtra);
    return;
  }
  TradeControl* moveControl = ResolveOwnerControl(owner, kControlTagMove);
  if (moveControl == 0) {
    MessageBoxA(0, kNilPointerText, kFailureCaption, 0x30);
  }
  short moveValue = (short)moveControl->QueryValue();
  CallApplyMoveValueSlot1D0(owner, (int)moveValue - (int)field_8e);
}
void TIndustryAmtBarState::DrawAmt() {
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
        ApplyQuickDrawStyleFromRuntime(0);
        SetQuickDrawStylePair(1, 4);
        SetQuickDrawTextOrigin(0, 1);
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

// FUNCTION: IMPERIALISM 0x00589540
void __fastcall RenderQuickDrawOverlayWithHitRegion_00589540(TradeControl* control, int unusedEdx,
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
      control->CtrlSlot78();
      invalidRect[2] =
          cachedX + (int)*reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x34);
      invalidRect[3] =
          cachedY + (int)*reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x38);
      reinterpret_cast<void(__stdcall*)(int, int)>(thunk_InvalidateCityDialogRectRegion)(
          (int)invalidRect, 1);
    }
  }
}

// FUNCTION: IMPERIALISM 0x00589720
void __fastcall ConstructTradeMoveScaledControlPanel(TradeMoveStepCluster* cluster) {
  TradeScreenRuntimeBridge::ConstructTUberClusterBaseState(cluster);
  cluster->vftable = reinterpret_cast<void*>(kVtableTRailCluster);
  cluster->field_88 = 0;
  cluster->field_8e = 0;
