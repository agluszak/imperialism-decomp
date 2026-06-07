#include "game/trade_quickdraw.h"
#include "game/TradeCommodityMetricRecord.h"
#include "game/NationState.h"
#pragma once

#include "decomp_types.h"
#include "game/NationState.h"
#include "game/TTraderAmtBar.h"
#include "game/TradeControl.h"
#include "game/UiRuntimeContext.h"
#include "game/quickdraw_guards.h"
#include "game/trade_quickdraw.h"
#include "game/ui_widget_thunks.h"
#include "game/win_rect.h"
#include <new>

undefined4 ApplyHitRegionToClipState(void);
undefined4 ResetQuickDrawStrokeState(void);
undefined4 thunk_SetQuickDrawTextOriginWithContextOffset(void);
undefined4 thunk_SetQuickDrawStylePair_1D08_1D0C_AndMarkDirty(void);
undefined4 thunk_DrawCenteredGuideLineOnMapDc(void);
int AllocateWithFallbackHandler(undefined4 size_bytes);
void FreeHeapBufferIfNotNull(undefined4 ptr_value);

namespace {

extern "C" char g_pClassDescTTraderAmtBar;

struct TradeControlOwnerSlotView {
  virtual void Slot00(void) = 0;
  virtual void Slot04(void) = 0;
  virtual void Slot08(void) = 0;
  virtual void Slot0C(void) = 0;
  virtual void Slot10(void) = 0;
  virtual void Slot14(void) = 0;
  virtual void Slot18(void) = 0;
  virtual void Slot1C(void) = 0;
  virtual void Slot20(void) = 0;
  virtual void Slot24(void) = 0;
  virtual void Slot28(void) = 0;
  virtual void Slot2C(void) = 0;
  virtual void Slot30(void) = 0;
  virtual void Slot34(void) = 0;
  virtual void Slot38(void) = 0;
  virtual void Slot3C(void) = 0;
  virtual void Slot40(void) = 0;
  virtual void Slot44(void) = 0;
  virtual void Slot48(void) = 0;
  virtual void Slot4C(void) = 0;
  virtual void Slot50(void) = 0;
  virtual void Slot54(void) = 0;
  virtual void* OwnerPanelSlot58(void) = 0;
};

struct TradeControlResolverView : public TradeControlOwnerSlotView {
  virtual void Slot5C(void) = 0;
  virtual void Slot60(void) = 0;
  virtual void Slot64(void) = 0;
  virtual void Slot68(void) = 0;
  virtual void Slot6C(void) = 0;
  virtual void Slot70(void) = 0;
  virtual void Slot74(void) = 0;
  virtual void Slot78(void) = 0;
  virtual void Slot7C(void) = 0;
  virtual void Slot80(void) = 0;
  virtual void Slot84(void) = 0;
  virtual void Slot88(void) = 0;
  virtual void Slot8C(void) = 0;
  virtual void Slot90(void) = 0;
  virtual TradeControl* ResolveControlByTagSlot94(int controlTag) = 0;
};

struct TradeNationMetricView {
  virtual void Slot00(void) = 0;
  virtual void Slot04(void) = 0;
  virtual void Slot08(void) = 0;
  virtual void Slot0C(void) = 0;
  virtual void Slot10(void) = 0;
  virtual void Slot14(void) = 0;
  virtual void Slot18(void) = 0;
  virtual void Slot1C(void) = 0;
  virtual void Slot20(void) = 0;
  virtual void Slot24(void) = 0;
  virtual void Slot28(void) = 0;
  virtual void Slot2C(void) = 0;
  virtual void Slot30(void) = 0;
  virtual void Slot34(void) = 0;
  virtual void Slot38(void) = 0;
  virtual void Slot3C(void) = 0;
  virtual void Slot40(void) = 0;
  virtual void Slot44(void) = 0;
  virtual void Slot48(void) = 0;
  virtual void Slot4C(void) = 0;
  virtual void Slot50(void) = 0;
  virtual void Slot54(void) = 0;
  virtual void Slot58(void) = 0;
  virtual void Slot5C(void) = 0;
  virtual void Slot60(void) = 0;
  virtual void Slot64(void) = 0;
  virtual void Slot68(void) = 0;
  virtual void Slot6C(void) = 0;
  virtual void Slot70(void) = 0;
  virtual void Slot74(void) = 0;
  virtual short QueryNationMetricBySlot78(short metricSlot) = 0;
  virtual short QueryNationMetricBySlot7C(short metricSlot) = 0;
};

struct UiRuntimeStyleView {
  virtual void Slot00(void) = 0;
  virtual void Slot04(void) = 0;
  virtual void Slot08(void) = 0;
  virtual void Slot0C(void) = 0;
  virtual void Slot10(void) = 0;
  virtual void Slot14(void) = 0;
  virtual void Slot18(void) = 0;
  virtual void Slot1C(void) = 0;
  virtual void Slot20(void) = 0;
  virtual void Slot24(void) = 0;
  virtual void Slot28(void) = 0;
  virtual void Slot2C(void) = 0;
  virtual void Slot30(void) = 0;
  virtual void ApplyQuickDrawStyleSlot34(int styleIndex) = 0;
};

static __inline short CallQueryNationMetricBySlot78(NationState* nationState, short metricSlot) {
  return reinterpret_cast<TradeNationMetricView*>(nationState)
      ->QueryNationMetricBySlot78(metricSlot);
}

static __inline short CallQueryNationMetricBySlot7C(NationState* nationState, short metricSlot) {
  return reinterpret_cast<TradeNationMetricView*>(nationState)
      ->QueryNationMetricBySlot7C(metricSlot);
}

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
void* __cdecl GetTTraderAmtBarClassNamePointer(void) {
  return reinterpret_cast<void*>(&g_pClassDescTTraderAmtBar);
}

// FUNCTION: IMPERIALISM 0x0058af30
TTraderAmtBar::~TTraderAmtBar() {}

// FUNCTION: IMPERIALISM 0x0058af80
void TTraderAmtBar::DoPostCreate(TDocument* document) {
  NationState* nationState = GetActiveNationState();
  int scenarioTag = *reinterpret_cast<int*>(reinterpret_cast<char*>(this->field20) + 0x1c);

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
    short currentValue = CallQueryNationMetricBySlot78(nationState, recordIndex);
    stepOrCurrentValue =
        (short)((((int)tradeCapacity - (int)currentValue) * this->field34) / (int)tradeCapacity);
  }

  short gaugeValue = 0;
  if (nationState != 0) {
    gaugeValue = CallQueryNationMetricBySlot7C(nationState, recordIndex);
  }
  if (tradeCapacity == 0) {
    rangeOrMaxValue = 0;
  } else {
    rangeOrMaxValue = (short)((this->field38 * (int)gaugeValue) / (int)tradeCapacity);
  }

  auxValueA = tradeCapacity;
  auxValueB = 0x37;
  reinterpret_cast<TView*>(this)->thunk_NoOpUiLifecycleHook(reinterpret_cast<int>(document));
}

// FUNCTION: IMPERIALISM 0x0058b070
short TTraderAmtBar::AdjustForZero(short priorResult, short requestedValue) {
  short result = priorResult;
  if (requestedValue > 0) {
    NationState* nationState = GetActiveNationState();
    short tradeCapacity = nationState->tradeCapacity;
    if (tradeCapacity != 0) {
      if ((int)requestedValue < (this->field38 / (int)tradeCapacity)) {
        TradeControl* sellControl =
            ResolveOwnerControl(reinterpret_cast<void*>(this->field20), kControlTagSell);
        if (sellControl != 0) {
          result = 1;
        }
      }
    }
  }
  return result;
}

// FUNCTION: IMPERIALISM 0x0058b040
void TTraderAmtBar::UpdateFromScaleOrRatio(int scaleValue, int ratioValue) {
  this->field34 = scaleValue;
  this->field38 = ratioValue;
}

// FUNCTION: IMPERIALISM 0x0058b0f0
void TTraderAmtBar::DrawAmt() {
  QuickDrawSurfaceGuard surface;
  TradeControl* control = reinterpret_cast<TradeControl*>(this);
  reinterpret_cast<void(__cdecl*)(int)>(ApplyHitRegionToClipState)(surface.surfaceWrapper);

  if (control != 0 && control->IsActionable() != 0) {
    control->Refresh();
    if (control->IsActionable() != 0) {
      int boundsRect[4] = {0, 0, 0, 0};
      control->QueryBounds(boundsRect);
      control->ApplyBounds(boundsRect, 1);
      control->QueryBounds(boundsRect);
      control->CtrlSlot78();

      short styleValueAt60 = rangeOrMaxValue;
      if (styleValueAt60 > 0) {
        short styleValueAt66 = auxValueB;
        SetQuickDrawTextOrigin(0, 0);
        ApplyQuickDrawStyleFromRuntime(styleValueAt66);
        SetQuickDrawStylePair(1, 5);
        DrawCenteredGuideLine((short)(styleValueAt60 - 1), 0);
        reinterpret_cast<void(__cdecl*)()>(ResetQuickDrawStrokeState)();
      }

      reinterpret_cast<void(__cdecl*)()>(SnapshotHitRegionToClipCache)();
      TradeControl* owner = reinterpret_cast<TradeControl*>(CallOwnerPanelSlot58(control));
      if (owner != 0) {
        owner->InvokeSlot13C();
      }
    }
  }
}
