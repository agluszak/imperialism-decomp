#include "game/TAmtBar.h"
#include "game/TShipAmtBar.h"
#include "game/trade_quickdraw.h"
#include "game/TradeCommodityMetricRecord.h"
#include "game/NationState.h"
#include "game/UiRuntimeContext.h"
#include "game/ui_widget_thunks.h"
#include "game/quickdraw_guards.h"
#include <new>

#pragma optimize("y", on)

extern "C" char g_pClassDescTShipAmtBar;

// FUNCTION: IMPERIALISM 0x0058aaa0
TShipAmtBar* __cdecl CreateTShipAmtBarInstance(void) {
  TShipAmtBar* amountBar = reinterpret_cast<TShipAmtBar*>(AllocateWithFallbackHandler(0x6c));
  if (amountBar != 0) {
    new (amountBar) TShipAmtBar;
  }
  return amountBar;
}

// FUNCTION: IMPERIALISM 0x0058ab40
void* __cdecl GetTShipAmtBarClassNamePointer(void) {
  return reinterpret_cast<void*>(&g_pClassDescTShipAmtBar);
}

// FUNCTION: IMPERIALISM 0x0058ab60
TShipAmtBar::TShipAmtBar() : TIndustryAmtBar() {}

// FUNCTION: IMPERIALISM 0x0058aba0
TShipAmtBar::~TShipAmtBar() {}

// FUNCTION: IMPERIALISM 0x0058abf0
void TShipAmtBar::DoPostCreate(TDocument* document) {
  NationState* nationState = reinterpret_cast<NationState**>(
      kAddrGlobalNationStates)[g_pUiRuntimeContext->GetActiveNationId()];
  NationCityTradeState* cityState =
      nationState != 0 ? nationState->cityState : 0;
  selectedMetricRecord = cityState->specialCommodityRecordAt190;
  short productionCap =
      *(short*)(reinterpret_cast<char*>(cityState->scenarioTradeDescriptor) + 0x1c);
  stepOrCurrentValue = (short)this->field34;
  auxValueA = productionCap;
  auxValueB = 0x3a;
  rangeOrMaxValue = (short)(0 / (int)productionCap);
  this->thunk_NoOpUiLifecycleHook(reinterpret_cast<int>(document));
}

// FUNCTION: IMPERIALISM 0x0058ac80
void TShipAmtBar::DrawAmt() {
  QuickDrawSurfaceGuard surface;
  TAmtBar* control = reinterpret_cast<TAmtBar*>(this);
  reinterpret_cast<void(__cdecl*)(int)>(ApplyHitRegionToClipState)(surface.surfaceWrapper);

  if (control != 0 && control->IsActionable() != 0) {
    control->Refresh();
    if (control->IsActionable() != 0) {
      int boundsRect[4] = {0, 0, 0, 0};
      control->QueryBounds(boundsRect);
      ApplyRectClipRegion(boundsRect);
      control->QueryBounds(boundsRect);
      control->vmethod_0078();

      short styleValueAt60 = *reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x60);
      if (styleValueAt60 > 0) {
        short styleValueAt66 = *reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x66);
        SetQuickDrawTextOrigin(0, 1);
        ApplyQuickDrawStyleFromRuntime(styleValueAt66);
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
      TAmtBar* owner = reinterpret_cast<TAmtBar*>(reinterpret_cast<TView*>(control)->OwnerPanel());
      if (owner != 0) {
        owner->InvokeSlot13C();
      }
    }
  }
}
