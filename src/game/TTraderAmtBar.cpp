#include "game/TIndustryCluster.h"
#include "game/TRailCluster.h"
#include "game/TShipyardCluster.h"
#include "game/TTradeCluster.h"

#include "game/TAmtBar.h"
#include "game/TPictureResourceEntryBase.h"
#include "game/trade_quickdraw.h"
#include "game/TradeCommodityMetricRecord.h"
#include "game/TGreatPower.h"

#include "decomp_types.h"
#include "game/TGreatPower.h"
#include "game/TTraderAmtBar.h"
#include "game/UiRuntimeContext.h"
#include "game/quickdraw_guards.h"
#include "game/trade_quickdraw.h"
#include "game/ui_widget_thunks.h"
#include "game/mfc.h"
#include <new>
#include "game/mfc.h"

undefined4 ApplyHitRegionToClipState(void);
undefined4 thunk_SetQuickDrawTextOriginWithContextOffset(void);
undefined4 thunk_SetQuickDrawStylePair_1D08_1D0C_AndMarkDirty(void);
undefined4 thunk_DrawCenteredGuideLineOnMapDc(void);
int AllocateWithFallbackHandler(undefined4 size_bytes);
void FreeHeapBufferIfNotNull(undefined4 ptr_value);

namespace {

extern "C" CRuntimeClass g_pClassDescTTraderAmtBar = {nullptr, 0, 0, nullptr, nullptr};
extern "C" char g_vtblTTraderAmtBar = 0;

const int kScenarioRecordTags[] = {
    0x72733020, 0x72733120, 0x72733220, 0x72733320, 0x72733420, 0x72733520,
    0x72733620, 0x6d613020, 0x6d613120, 0x6d613220, 0x6d613320, 0x6d613420,
    0x6d613520, 0x67643020, 0x67643120, 0x67643220, 0x67643320,
};

} // namespace

TTraderAmtBar::TTraderAmtBar() : TAmtBar() {}

// FUNCTION: IMPERIALISM 0x0058ae30
TTraderAmtBar* __cdecl CreateTTraderAmtBarInstance(void) {
  TTraderAmtBar* amountBar = reinterpret_cast<TTraderAmtBar*>(AllocateWithFallbackHandler(0x68));
  if (amountBar != 0) {
    new (amountBar) TTraderAmtBar;
  }
  return amountBar;
}

// FUNCTION: IMPERIALISM 0x0058aed0
CRuntimeClass* TTraderAmtBar::GetRuntimeClass() const {
  return &g_pClassDescTTraderAmtBar;
}

// Destructors are compiler-generated (implicit) from real inheritance.
// SYNTHETIC: IMPERIALISM 0x0058af30
// TTraderAmtBar::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x0058af80
void TTraderAmtBar::NoOpUiLifecycleHook(int arg) {
  (void)arg;
  TGreatPower* nationState = GetActiveNationState();
  int scenarioTag = *reinterpret_cast<int*>(reinterpret_cast<char*>(this->ownerContext) + 0x1c);

  short recordIndex = 0;
  while (recordIndex < 0x11) {
    if (kScenarioRecordTags[recordIndex] == scenarioTag) {
      break;
    }
    recordIndex = (short)(recordIndex + 1);
  }

  short tradeCapacity = nationState != 0 ? nationState->tradeCapacity : 0;
  if (tradeCapacity == 0) {
    stepOrCurrentValue = 0;
  } else {
    short currentValue = nationState->GetDiplomacyExternalStateB6ByTarget(recordIndex);
    stepOrCurrentValue =
        (short)((((int)tradeCapacity - (int)currentValue) * this->field34) / (int)tradeCapacity);
  }

  short gaugeValue = 0;
  if (nationState != 0) {
    gaugeValue = nationState->QueryNationMetricBySlot7C(recordIndex);
  }
  if (tradeCapacity == 0) {
    rangeOrMaxValue = 0;
  } else {
    rangeOrMaxValue = (short)((this->field38 * (int)gaugeValue) / (int)tradeCapacity);
  }

  auxValueA = tradeCapacity;
  auxValueB = 0x37;
  TView::NoOpUiLifecycleHook(arg);
}

// FUNCTION: IMPERIALISM 0x0058b040
void TTraderAmtBar::UpdateFromScaleOrRatio(int scaleValue, int ratioValue) {
  this->field34 = scaleValue;
  this->field38 = ratioValue;
}

// FUNCTION: IMPERIALISM 0x0058b070
int TTraderAmtBar::ApplyMoveClamp(int baseValue, int requestedValue) {
  short priorResult = static_cast<short>(baseValue);
  short requested = static_cast<short>(requestedValue);
  short result = priorResult;
  if (requestedValue > 0) {
    TGreatPower* nationState = GetActiveNationState();
    short tradeCapacity = nationState->tradeCapacity;
    if (tradeCapacity != 0) {
      if ((int)requestedValue < (this->field38 / (int)tradeCapacity)) {
        TAmtBar* sellControl = reinterpret_cast<TAmtBar*>(
            reinterpret_cast<TView*>(reinterpret_cast<void*>(this->ownerContext))
                ->ResolveControlByTag(kControlTagSell));
        if (sellControl != 0) {
          result = 1;
        }
      }
    }
  }
  return static_cast<int>(result);
}

// FUNCTION: IMPERIALISM 0x0058b0f0
void TTraderAmtBar::RenderPrimarySurfaceOverlayPanelWithClipCache() {
  QuickDrawSurfaceGuard surface;
  TAmtBar* control = reinterpret_cast<TAmtBar*>(this);
  reinterpret_cast<void(__cdecl*)(int)>(ApplyHitRegionToClipState)(surface.surfaceWrapper);

  if (control != 0 && control->IsActionable() != 0) {
    control->Refresh();
    if (control->IsActionable() != 0) {
      RECT boundsRect = {0, 0, 0, 0};
      control->QueryBounds(&boundsRect);
      control->ApplyBounds(&boundsRect, 1);
      control->QueryBounds(&boundsRect);
      control->vmethod_0078();

      short styleValueAt60 = rangeOrMaxValue;
      if (styleValueAt60 > 0) {
        short styleValueAt66 = auxValueB;
        SetQuickDrawTextOrigin(0, 0);
        ApplyQuickDrawStyleFromRuntime(styleValueAt66);
        SetQuickDrawStylePair(1, 5);
        DrawCenteredGuideLine((short)(styleValueAt60 - 1), 0);
        ResetQuickDrawStrokeState();
      }

      SnapshotHitRegionToClipCache(0);
      TAmtBar* owner = reinterpret_cast<TAmtBar*>(reinterpret_cast<TView*>(control)->OwnerPanel());
      if (owner != 0) {
        owner->InvokeSlot13C();
      }
    }
  }
}
