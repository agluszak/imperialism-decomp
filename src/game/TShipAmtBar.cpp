#include "game/TIndustryCluster.h"
#include "game/TRailCluster.h"
#include "game/TShipyardCluster.h"
#include "game/TTradeCluster.h"
#include "game/mfc.h"

#include "game/TAmtBar.h"
#include "game/TShipAmtBar.h"
#include "game/global_data_tables.h"
#include "game/ui_invalidation_guard.h"
#include "game/quickdraw_rendering.h"
#include "game/TradeCommodityMetricRecord.h"
#include "game/TCity.h"
#include "game/TGreatPower.h"
#include "game/UiRuntimeContext.h"
#include "game/ui_widget_thunks.h"
#include "game/quickdraw_guards.h"
#include <new>

IMPLEMENT_DYNCREATE(TShipAmtBar, TAmtBar)

// FUNCTION: IMPERIALISM 0x0058aaa0
TShipAmtBar* __cdecl CreateTShipAmtBarInstance(void) {
  return new TShipAmtBar();
}

// FUNCTION: IMPERIALISM 0x0058ab60
TShipAmtBar::TShipAmtBar() : TIndustryAmtBar() {}

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x0058aba0
// TShipAmtBar::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x0058abf0
void TShipAmtBar::NoOpUiLifecycleHook(int arg) {
  TGreatPower* nationState = GetActiveNationState();
  TCity* cityState = nationState != 0 ? nationState->GetCityState() : 0;
  selectedMetricRecord = cityState->specialCommodityRecordAt190;
  short productionCap = cityState->productionSummary1d8->stockLevel1c;
  stepOrCurrentValue = (short)this->field34;
  auxValueA = productionCap;
  auxValueB = 0x3a;
  rangeOrMaxValue = (short)(0 / (int)productionCap);
  reinterpret_cast<TView*>(this)->TView::NoOpUiLifecycleHook(arg);
}

// FUNCTION: IMPERIALISM 0x0058ac80
void TShipAmtBar::RenderPrimarySurfaceOverlayPanelWithClipCache() {
  QuickDrawSurfaceGuard surface;
  TAmtBar* control = reinterpret_cast<TAmtBar*>(this);
  reinterpret_cast<void(__cdecl*)(int*)>(ApplyHitRegionToClipState)(reinterpret_cast<int*>(surface.surfaceWrapper));

  if (control != 0 && control->IsActionable() != 0) {
    control->Refresh();
    if (control->IsActionable() != 0) {
      RECT boundsRect = {0, 0, 0, 0};
      control->QueryBounds(&boundsRect);
      reinterpret_cast<void(__cdecl*)(RECT*)>(ApplyRectClipRegionToGlobalClipState)(&boundsRect);
      control->QueryBounds(&boundsRect);
      control->TranslatePointToParentChain4E();

      short styleValueAt60 = *reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x60);
      if (styleValueAt60 > 0) {
        short styleValueAt66 = *reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x66);
        reinterpret_cast<void(__cdecl*)(short, short)>(SetQuickDrawTextOriginWithContextOffset)(0, 1);
        g_pUiRuntimeContext->ApplyLegendSplitSlot34(styleValueAt66);
        SetQuickDrawStylePair_1D08_1D0C_AndMarkDirty(1, 4);
        reinterpret_cast<void(__cdecl*)(short, short)>(DrawCenteredGuideLineOnMapDc)((short)(styleValueAt60 - 1), 1);
        ResetQuickDrawStrokeState();
      }

      short overlayOffsetX = *reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x62);
      short overlayOffsetY = *reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x38);
      reinterpret_cast<void(__cdecl*)(short, short)>(SetQuickDrawTextOriginWithContextOffset)(overlayOffsetX, 0);
      SetQuickDrawFillColor(0);
      ResetQuickDrawStrokeState();
      reinterpret_cast<void(__cdecl*)(short, short)>(DrawCenteredGuideLineOnMapDc)(overlayOffsetX, (short)(overlayOffsetY - 2));

      reinterpret_cast<void(__cdecl*)()>(SnapshotHitRegionToClipCache)();
      TAmtBar* owner = reinterpret_cast<TAmtBar*>(reinterpret_cast<TView*>(control)->OwnerPanel());
      if (owner != 0) {
        owner->InvokeSlot13C();
      }
    }
  }
}
