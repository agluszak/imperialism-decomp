#include "game/TIndustryCluster.h"
#include "game/TRailCluster.h"
#include "game/TShipyardCluster.h"
#include "game/TTradeCluster.h"

#include "game/TAmtBar.h"
#include "game/trade_quickdraw.h"
#include "game/TradeCommodityMetricRecord.h"
#include "game/NationState.h"

#include "decomp_types.h"
#include "game/NationState.h"
#include "game/TTraderAmtBar.h"
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

extern "C" char g_pClassDescTTraderAmtBar = 0;
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
void* __cdecl GetTTraderAmtBarClassNamePointer(void) {
  return reinterpret_cast<void*>(&g_pClassDescTTraderAmtBar);
}

// FUNCTION: IMPERIALISM 0x0058af30
TTraderAmtBar::~TTraderAmtBar() {}

// FUNCTION: IMPERIALISM 0x0058af80
void TTraderAmtBar::DoPostCreate(TDocument* document) {
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
    short currentValue = nationState->QueryNationMetricBySlot78(recordIndex);
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
  reinterpret_cast<TView*>(this)->thunk_NoOpUiLifecycleHook(reinterpret_cast<int>(document));
}

// FUNCTION: IMPERIALISM 0x0058b070
short TTraderAmtBar::AdjustForZero(short priorResult, short requestedValue) {
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
  TAmtBar* control = reinterpret_cast<TAmtBar*>(this);
  reinterpret_cast<void(__cdecl*)(int)>(ApplyHitRegionToClipState)(surface.surfaceWrapper);

  if (control != 0 && control->IsActionable() != 0) {
    control->Refresh();
    if (control->IsActionable() != 0) {
      int boundsRect[4] = {0, 0, 0, 0};
      control->QueryBounds(boundsRect);
      control->ApplyBounds(boundsRect, 1);
      control->QueryBounds(boundsRect);
      control->vmethod_0078();

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
      TAmtBar* owner = reinterpret_cast<TAmtBar*>(reinterpret_cast<TView*>(control)->OwnerPanel());
      if (owner != 0) {
        owner->InvokeSlot13C();
      }
    }
  }
}

const unsigned int kAddrStrategicMapViewSystem = 0x006A21A8;

// FUNCTION: IMPERIALISM 0x0058b4f0
void __fastcall BlitHintOverlayRectWithCtrlModifierPalette(void* control) {
  if (*reinterpret_cast<int*>(reinterpret_cast<char*>(control) + 4) != 0) {
    reinterpret_cast<void(__fastcall*)(void*)>(thunk_RenderHintHelperWithCtrlModifierOverlay)(
        control);
  }
  reinterpret_cast<void(__stdcall*)(unsigned int)>(UpdatePaletteIndexWithDefaultFallback)(0x10);

  RECT srcRect;
  srcRect.left = (int)*reinterpret_cast<short*>(reinterpret_cast<char*>(control) + 0x98);
  srcRect.top = 0;
  srcRect.right = srcRect.left + 0x40;
  srcRect.bottom = 0x40;

  RECT dstRect;
  dstRect.left = 0;
  dstRect.top = 2;
  dstRect.right = 0x40;
  dstRect.bottom = 0x42;

  int strategicMapViewSystem = (int)ReadPointerAt(kAddrStrategicMapViewSystem);
  int activeQuickDrawSurfaceContext = (int)ReadPointerAt(kAddrActiveQuickDrawSurfaceContext);
  reinterpret_cast<void(__stdcall*)(void*, void*, RECT*, RECT*, unsigned char, void*)>(
      BlitRectWithOptionalTransparency)(
      reinterpret_cast<void*>(*reinterpret_cast<int*>(strategicMapViewSystem + 0x66c) + 4),
      reinterpret_cast<void*>(activeQuickDrawSurfaceContext + 4), &srcRect, &dstRect, 0x24, 0);

  reinterpret_cast<void(__stdcall*)(unsigned int)>(UpdatePaletteIndexWithDefaultFallback)(0x13);
}
