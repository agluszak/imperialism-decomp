#include "game/TIndustryCluster.h"
#include "game/TRailCluster.h"
#include "game/TShipyardCluster.h"
#include "game/ui_widget_thunks.h"
#include "game/mfc.h"
#include "game/UiRuntimeContext.h"
#include "game/quickdraw_guards.h"
#include <new>

extern "C" CRuntimeClass g_pClassDescTTradeCluster = {nullptr, 0, 0, nullptr, nullptr};
extern "C" char PTR_thunk_GetTTradeClusterClassNamePointer_00665a70 = 0;

// TTradeCluster (VTABLE 0x665a70): the trade-screen sell/bid/offer cluster.
// Owns the Sell/Bar/Bid/Offer child-control state machine for one trade row.

#include "decomp_types.h"

#include "game/TTradeCluster.h"
#include "game/TUberCluster.h"
#include "game/TView.h"
#include "game/TAmtBar.h"
#include "game/TPictureResourceEntryBase.h"
#include "game/TGreatPower.h"
#include "game/trade_quickdraw.h"
#include "game/CRuntimeClass.h"
#include "game/TEvent.h"

// Bid/Offer picture-button bitmap states (enabled / row-selected variants).
const short kTradeBitmapBidStateA = 0x083f;
const short kTradeBitmapBidStateB = 0x084d;
const short kTradeBitmapBidSecondaryStateA = 0x0840;
const short kTradeBitmapBidSecondaryStateB = 0x084e;
const short kTradeBitmapOfferStateA = 0x0841;
const short kTradeBitmapOfferStateB = 0x084f;
const short kTradeBitmapOfferSecondaryStateA = 0x0842;
const short kTradeBitmapOfferSecondaryStateB = 0x0850;
const int kTradeRowStateTag_67643020 = 0x67643020;

// Assert source-line numbers in USmallViews.cpp / USuperMap.cpp.
const int kAssertLineBidSecondary = 0x907;
const int kAssertLineBidActionable = 0x8de;
const int kAssertLineOfferActionable = 0x8f2;
const int kAssertLineBidControl = 0x92e;
const int kAssertLineBidGree = 0x93f;
const int kAssertLineBidLeft = 0x941;
const int kAssertLineBidRight = 0x943;
const int kAssertLineOfferControl = 0x95c;
const int kAssertLineOfferGree = 0x970;
const int kAssertLineOfferLeft = 0x972;
const int kAssertLineOfferRight = 0x974;
const int kAssertLineOfferSecondaryOffr = 0x98f;
const int kAssertLineOfferSecondaryGree = 0x9ad;
const int kAssertLineOfferSecondaryLeft = 0x9af;
const int kAssertLineOfferSecondaryRight = 0x9b1;
const int kAssertLineInitBar = 0x7a2;
const int kAssertLineInitLeft = 0x7a6;
const int kAssertLineInitRight = 0x7a8;
const int kAssertLineInitGree = 0x7b8;
const int kAssertLineUpdateSell = 0x9e0;
const int kAssertLineUpdateBar = 0x9e4;
const int kAssertLineUpdateGree = 0x9e7;
const int kAssertLineToolSubcontrolToggle = 0xac7;

const int kAssertLineTradeSellIncSell = 0x816;
const int kAssertLineTradeSellIncCap = 0x81d;
const int kAssertLineTradeSellDecSell = 0x82f;
const int kAssertLineTradeSellMoveSell = 0x85a;
const int kAssertLineTradeSellMoveBar = 0x874;
const int kAssertLineTradeSellZeroBar = 0x896;

extern const int kTradeSellPropagationTags[17];

const char kUSuperMapCppPath[] = "D:\\Ambit\\Cross\\USuperMap.cpp";

// Layout view of the Bar child control: barRange/barSteps drive the fill ratio.
struct TradeBarControlLayout {
  void* vftable;
  char pad_04[0x30];
  short barRange;
  char pad_36[0x2e];
  short barSteps;
};

static __inline short QueryNationTradeCapacity(TGreatPower* nationState) {
  return nationState->tradeCapacity;
}

#if defined(_MSC_VER)
#pragma auto_inline(off)
#pragma optimize("y", off)
#endif

// FUNCTION: IMPERIALISM 0x004032fb
void __fastcall thunk_SetTradeToolSubcontrolEnabledStateByFlag(TTradeCluster* self, int unusedEdx,
                                                               unsigned char enabledFlag) {
  (void)unusedEdx;
  self->SetTradeToolSubcontrolEnabledStateByFlag(enabledFlag);
}

// FUNCTION: IMPERIALISM 0x00587010
void* CreateTradeSellControlPanel(void) {
  TTradeCluster* cluster =
      reinterpret_cast<TTradeCluster*>(AllocateWithFallbackHandler(sizeof(TTradeCluster)));
  if (cluster != 0) {
    new (cluster) TTradeCluster();
  }
  return cluster;
}

// FUNCTION: IMPERIALISM 0x00587090
CRuntimeClass* TTradeCluster::GetRuntimeClass() const {
  return &g_pClassDescTTradeCluster;
}

// FUNCTION: IMPERIALISM 0x005870b0
TTradeCluster::TTradeCluster() : TUberCluster() {}

// SYNTHETIC: IMPERIALISM 0x005870e0
// TTradeCluster::`scalar deleting destructor'

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif

// Initializes Sell/Bar/Arrow control style and enabled state for the current
// nation/resource context, then initializes the move/bar controls baseline.
// FUNCTION: IMPERIALISM 0x00587130
void TTradeCluster::NoOpUiLifecycleHook(int styleSeed) {
  TAmtBar* sellControl = reinterpret_cast<TAmtBar*>(this->ResolveControlByTag(kControlTagSell));
  if (sellControl != 0) {
    int styleDescriptor[5];
    reinterpret_cast<void(__cdecl*)(int, void*, int, int, int)>(
        thunk_InitializeUiTextStyleDescriptor)(0, styleDescriptor, 0xe, 0x2b68, 2);
    sellControl->ApplyStyleDescriptor(styleDescriptor, 0);
    sellControl->SetStyleState(-1, 0);
    RECT boundsBuffer;
    boundsBuffer.left = 0;
    boundsBuffer.top = 0;
    sellControl->QueryBounds(&boundsBuffer);
    boundsBuffer.top = boundsBuffer.top - 2;
    sellControl->ApplyBounds(&boundsBuffer, 1);
    sellControl->SetState(-1, 0);
  }

  TAmtBar* barControl = reinterpret_cast<TAmtBar*>(this->ResolveControlByTag(kControlTagBar));
  if (barControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineInitBar);
  }
  barControl->SetState(0, 0);

  TAmtBar* leftControl = reinterpret_cast<TAmtBar*>(this->ResolveControlByTag(kControlTagLeft));
  if (leftControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineInitLeft);
  }
  TAmtBar* rightControl = reinterpret_cast<TAmtBar*>(this->ResolveControlByTag(kControlTagRght));
  if (rightControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineInitRight);
  }
  leftControl->SetState(0, 0);
  rightControl->SetState(0, 0);

  short activeNationSlot = g_pUiRuntimeContext->GetActiveNationId();
  TGreatPower* activeNationState = GetNationStateBySlot(activeNationSlot);
  if (activeNationState != 0 && QueryNationTradeCapacity(activeNationState) == 0) {
    leftControl->SetEnabled(0, 0);
    rightControl->SetEnabled(0, 0);
    barControl->SetEnabled(0, 0);
    TAmtBar* greenControl = reinterpret_cast<TAmtBar*>(this->ResolveControlByTag(kControlTagGree));
    if (greenControl == 0) {
      FailNilPointerInUSmallViews(kAssertLineInitGree);
    }
    if (greenControl != 0) {
      greenControl->SetEnabled(0, 0);
    }
  }

  this->InitializeTradeMoveAndBarControls(styleSeed);
}

// FUNCTION: IMPERIALISM 0x005873e0
void TTradeCluster::HandleEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  TView* ownerPanel = this->OwnerPanel();

  switch (commandId) {
  case 100: {
    if (this->GetBoolSlot1DC() != '\0') {
      TAmtBar* sellControl = reinterpret_cast<TAmtBar*>(this->ResolveControlByTag(kControlTagSell));
      if (sellControl == 0) {
        FailNilPointerInUSmallViews(kAssertLineTradeSellIncSell);
      }

      int sellValue = sellControl->QueryValue();
      short activeNationSlot = g_pUiRuntimeContext->GetActiveNationId();
      TGreatPower* activeNationState = GetNationStateBySlot(activeNationSlot);
      short maxByNationMetric = 0;
      if (activeNationState != 0) {
        maxByNationMetric = QueryNationMetricBySlot(activeNationState, tradeMetricSlot);
      }

      TAmtBar* capacityControl =
          reinterpret_cast<TAmtBar*>(ownerPanel->ResolveControlByTag(0x6d436170));
      if (capacityControl == 0) {
        FailNilPointerInUSmallViews(kAssertLineTradeSellIncCap);
      }

      if ((int)maxByNationMetric < sellValue) {
        int capacityValue = capacityControl->QueryValue();
        if ((int)maxByNationMetric < capacityValue) {
          sellControl->SetEnabled(maxByNationMetric + 1 != 0, 1);
          this->ApplyMoveValue(maxByNationMetric + 1);
          return;
        }
      }
    }
    break;
  }
  case 0x65: {
    TAmtBar* sellControl = reinterpret_cast<TAmtBar*>(this->ResolveControlByTag(kControlTagSell));
    if (sellControl == 0) {
      FailNilPointerInUSmallViews(kAssertLineTradeSellDecSell);
    }
    int sellValue = sellControl->QueryValue();
    if (1 < sellValue) {
      this->ApplyMoveValue(sellValue - 1);
      return;
    }
    break;
  }
  case 0x67:
    g_pUiRuntimeContext->ApplyUiRuntimeSlot68(-1);
    if (QueryUiScreenModeRaw(g_pUiRuntimeContext) == 3) {
      for (int i = 0;
           i < (int)(sizeof(kTradeSellPropagationTags) / sizeof(kTradeSellPropagationTags[0]));
           ++i) {
        TControl* rowControl = ownerPanel->ResolveControlByTag(kTradeSellPropagationTags[i]);
        if (rowControl != 0 &&
            reinterpret_cast<TUberCluster*>(rowControl)->GetControlFlag() == '\0') {
          reinterpret_cast<TUberCluster*>(rowControl)->DoControlAction();
        }
      }
      return;
    }
    break;
  case 0x68:
    g_pUiRuntimeContext->ApplyUiRuntimeSlot68(1);
    if (QueryUiScreenModeRaw(g_pUiRuntimeContext) == 4) {
      for (int i = 0;
           i < (int)(sizeof(kTradeSellPropagationTags) / sizeof(kTradeSellPropagationTags[0]));
           ++i) {
        TControl* rowControl = ownerPanel->ResolveControlByTag(kTradeSellPropagationTags[i]);
        if (rowControl != 0 &&
            reinterpret_cast<TUberCluster*>(rowControl)->GetControlFlag() == '\0') {
          reinterpret_cast<TUberCluster*>(rowControl)->DoControlAction();
        }
      }
      return;
    }
    break;
  case 0x69: {
    short activeNationSlot = g_pUiRuntimeContext->GetActiveNationId();
    TGreatPower* activeNationState = GetNationStateBySlot(activeNationSlot);
    short maxByNationMetric = 0;
    if (activeNationState != 0) {
      maxByNationMetric = QueryNationMetricBySlot(activeNationState, tradeMetricSlot);
    }

    TAmtBar* capacityControl =
        reinterpret_cast<TAmtBar*>(ownerPanel->ResolveControlByTag(0x6d436170));
    if (capacityControl == 0) {
      FailNilPointerInUSmallViews(kAssertLineTradeSellMoveSell);
    }
    short cappedValue = (short)capacityControl->QueryValue();
    int applyValue = (int)maxByNationMetric;
    if ((int)cappedValue <= (int)maxByNationMetric) {
      applyValue = (int)cappedValue;
    }

    TControl* sellControl = this->ResolveControlByTag(kControlTagSell);
    sellControl->SetEnabled(1, 1);

    TControl* barControl = this->ResolveControlByTag(kControlTagBar);
    if (barControl == 0) {
      FailNilPointerInUSmallViews(kAssertLineTradeSellMoveBar);
    }
    barControl->SetState(1, 0);
    this->ApplyMoveValue(applyValue);
    return;
  }
  case 0x6a: {
    TControl* sellControl = this->ResolveControlByTag(kControlTagSell);
    sellControl->SetEnabled(0, 1);

    TControl* barControl = this->ResolveControlByTag(kControlTagBar);
    if (barControl == 0) {
      FailNilPointerInUSmallViews(kAssertLineTradeSellZeroBar);
    }
    barControl->SetState(0, 1);
    this->ApplyMoveValue(0);
    return;
  }
  default:
    this->HandleTradeMoveControlAdjustment(commandId, sourceHandler, reinterpret_cast<int>(event));
    return;
  }

  this->HandleTradeMoveControlAdjustment(commandId, sourceHandler, reinterpret_cast<int>(event));
}

// Returns early if UI mode is outside trade range (>3); otherwise reports
// whether the current Sell control quantity is at its minimum.
// FUNCTION: IMPERIALISM 0x00587900
int TTradeCluster::IsTradeControlAtMinimum() {
  if (QueryUiScreenModeRaw(g_pUiRuntimeContext) > 3) {
    return 0;
  }
  TAmtBar* sellControl = reinterpret_cast<TAmtBar*>(this->ResolveControlByTag(kControlTagSell));
  return sellControl->QueryValue() <= 0 ? 1 : 0;
}

// Returns the current Sell control quantity.
// FUNCTION: IMPERIALISM 0x00587950
int TTradeCluster::NotifyControlSelectionChange(void* boundEntry, int arg2) {
  TAmtBar* sellControl = reinterpret_cast<TAmtBar*>(this->ResolveControlByTag(kControlTagSell));
  return sellControl->QueryValue();
}

// Bid control is actionable when its 'card' bitmap is in a Bid state and the
// control reports actionable.
// FUNCTION: IMPERIALISM 0x00587980
int TTradeCluster::GetControlFlag(int arg1, int arg2) {
  TPictureResourceEntryBase* bidControl =
      reinterpret_cast<TPictureResourceEntryBase*>(this->ResolveControlByTag(kControlTagCard));
  if (bidControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineBidActionable);
  }

  if (bidControl->bitmapId != kTradeBitmapBidStateA &&
      bidControl->bitmapId != kTradeBitmapBidStateB) {
    return 0;
  }

  char actionable = bidControl->IsActionable();
  if (actionable == 0) {
    return 0;
  }
  return 1;
}

// Offer control is actionable when its 'offr' bitmap is in an Offer state and
// the control reports actionable.
// FUNCTION: IMPERIALISM 0x00587a10
int TTradeCluster::GetBoolSlot1DC() {
  TPictureResourceEntryBase* offerControl =
      reinterpret_cast<TPictureResourceEntryBase*>(this->ResolveControlByTag(kControlTagOffr));
  if (offerControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineOfferActionable);
  }

  if (offerControl->bitmapId != kTradeBitmapOfferStateA &&
      offerControl->bitmapId != kTradeBitmapOfferStateB) {
    return 0;
  }

  char actionable = offerControl->IsActionable();
  if (actionable == 0) {
    return 0;
  }
  return 1;
}

// Bid secondary-state updater: assigns the secondary 'card' bitmap (row-state
// dependent) when the screen mode gate passes, else disables the control.
// FUNCTION: IMPERIALISM 0x00587aa0
void TTradeCluster::DoControlAction() {
  TAmtBar* bidControl = reinterpret_cast<TAmtBar*>(this->ResolveControlByTag(kControlTagCard));
  if (bidControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineBidSecondary);
  }

  int layoutCapture[2];
  layoutCapture[0] = 0x11;
  layoutCapture[1] = 0x14;
  bidControl->CaptureLayout(layoutCapture, 1);

  if (QueryUiScreenModeRaw(g_pUiRuntimeContext) < 4) {
    bidControl->SetEnabled(1, 1);
    if (controlTag == kTradeRowStateTag_67643020) {
      bidControl->SetBitmap(kTradeBitmapBidSecondaryStateB, 0);
    } else {
      bidControl->SetBitmap(kTradeBitmapBidSecondaryStateA, 0);
    }
    bidControl->Refresh();
    bidControl->UpdateAfterBitmapChange(0);
    return;
  }

  bidControl->SetEnabled(0, 1);
}

// Bid-state updater: assigns the 'card' bitmap (row-state dependent) and clears
// the gree/left/rght companion controls.
// FUNCTION: IMPERIALISM 0x00587bb0
void TTradeCluster::SetTradeBidControlBitmap() {
  TAmtBar* bidControl = reinterpret_cast<TAmtBar*>(this->ResolveControlByTag(kControlTagCard));
  if (bidControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineBidControl);
  }

  bidControl->SetEnabled(1, 0);
  if (controlTag == kTradeRowStateTag_67643020) {
    bidControl->SetBitmap(kTradeBitmapBidStateB, 0);
  } else {
    bidControl->SetBitmap(kTradeBitmapBidStateA, 0);
  }

  int layoutCapture[2] = {0x41, 0x14};
  bidControl->CaptureLayout(layoutCapture, 1);

  TAmtBar* greenControl = reinterpret_cast<TAmtBar*>(this->ResolveControlByTag(kControlTagGree));
  if (greenControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineBidGree);
  }
  TAmtBar* leftControl = reinterpret_cast<TAmtBar*>(this->ResolveControlByTag(kControlTagLeft));
  if (leftControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineBidLeft);
  }
  TAmtBar* rightControl = reinterpret_cast<TAmtBar*>(this->ResolveControlByTag(kControlTagRght));
  if (rightControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineBidRight);
  }

  greenControl->SetEnabled(0, 1);
  leftControl->SetEnabled(0, 1);
  rightControl->SetEnabled(0, 1);
  greenControl->SetState(0, 1);
  leftControl->SetState(0, 1);
  rightControl->SetState(0, 1);

  bidControl->Refresh();
  bidControl->UpdateAfterBitmapChange(0);
}

// Offer-state updater: assigns the 'offr' bitmap (row-state dependent) and
// enables the gree/left/rght companion controls.
// FUNCTION: IMPERIALISM 0x00587dd0
void TTradeCluster::SetTradeOfferControlBitmap() {
  TAmtBar* offerControl = reinterpret_cast<TAmtBar*>(this->ResolveControlByTag(kControlTagOffr));
  if (offerControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineOfferControl);
  }

  offerControl->SetEnabled(1, 0);
  if (controlTag == kTradeRowStateTag_67643020) {
    offerControl->SetBitmap(kTradeBitmapOfferStateB, 0);
  } else {
    offerControl->SetBitmap(kTradeBitmapOfferStateA, 0);
  }

  int layoutCaptureF4[2] = {0x41, 0x14};
  offerControl->CaptureLayout(layoutCaptureF4, 1);
  int layoutCaptureF0[2] = {0x73, 0};
  offerControl->CaptureLayoutF0(layoutCaptureF0, 1);

  TAmtBar* greenControl = reinterpret_cast<TAmtBar*>(this->ResolveControlByTag(kControlTagGree));
  if (greenControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineOfferGree);
  }
  TAmtBar* leftControl = reinterpret_cast<TAmtBar*>(this->ResolveControlByTag(kControlTagLeft));
  if (leftControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineOfferLeft);
  }
  TAmtBar* rightControl = reinterpret_cast<TAmtBar*>(this->ResolveControlByTag(kControlTagRght));
  if (rightControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineOfferRight);
  }

  greenControl->SetEnabled(1, 1);
  leftControl->SetEnabled(1, 1);
  rightControl->SetEnabled(1, 1);
  greenControl->SetState(1, 1);
  leftControl->SetState(1, 1);
  rightControl->SetState(1, 1);

  offerControl->Refresh();
  offerControl->UpdateAfterBitmapChange(0);
}

// Offer secondary-state updater: assigns the secondary 'offr' bitmap when the
// nation availability/capacity gates pass, else disables the control.
// FUNCTION: IMPERIALISM 0x00588030
void TTradeCluster::SetTradeOfferSecondaryBitmap() {
  TAmtBar* offerControl = reinterpret_cast<TAmtBar*>(this->ResolveControlByTag(kControlTagOffr));
  if (offerControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineOfferSecondaryOffr);
  }

  int layoutCaptureF4[2] = {0x11, 0x14};
  offerControl->CaptureLayout(layoutCaptureF4, 1);

  short activeNationSlot = g_pUiRuntimeContext->GetActiveNationId();
  TGreatPower* activeNationState = GetNationStateBySlot(activeNationSlot);
  short tradeMetricAvailable = QueryNationMetricBySlot(activeNationState, tradeMetricSlot);

  if (tradeMetricAvailable != 0) {
    short activeNationSlotAgain = g_pUiRuntimeContext->GetActiveNationId();
    TGreatPower* activeNationStateAgain = GetNationStateBySlot(activeNationSlotAgain);
    if (QueryNationTradeCapacity(activeNationStateAgain) != 0) {
      offerControl->SetEnabled(1, 0);
      if (controlTag == kTradeRowStateTag_67643020) {
        offerControl->SetBitmap(kTradeBitmapOfferSecondaryStateB, 0);
      } else {
        offerControl->SetBitmap(kTradeBitmapOfferSecondaryStateA, 0);
      }
      int layoutCaptureF0[2] = {0xa3, 0};
      offerControl->CaptureLayoutF0(layoutCaptureF0, 1);
    } else {
      offerControl->SetEnabled(0, 1);
    }
  } else {
    offerControl->SetEnabled(0, 1);
  }

  TAmtBar* greenControl = reinterpret_cast<TAmtBar*>(this->ResolveControlByTag(kControlTagGree));
  if (greenControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineOfferSecondaryGree);
  }
  TAmtBar* leftControl = reinterpret_cast<TAmtBar*>(this->ResolveControlByTag(kControlTagLeft));
  if (leftControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineOfferSecondaryLeft);
  }
  TAmtBar* rightControl = reinterpret_cast<TAmtBar*>(this->ResolveControlByTag(kControlTagRght));
  if (rightControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineOfferSecondaryRight);
  }

  greenControl->SetEnabled(0, 1);
  leftControl->SetEnabled(0, 1);
  rightControl->SetEnabled(0, 1);
  greenControl->SetState(0, 1);
  leftControl->SetState(0, 1);
  rightControl->SetState(0, 1);

  offerControl->Refresh();
  offerControl->UpdateAfterBitmapChange(0);
}

// Updates the Sell control quantity and the Bar fill from the nation's current
// trade metric, clamped to metricClampMax.
// FUNCTION: IMPERIALISM 0x005882f0
void TTradeCluster::ApplyMoveValue(int metricClampMax) {
  short activeNationSlot = g_pUiRuntimeContext->GetActiveNationId();
  TGreatPower* activeNationState = GetNationStateBySlot(activeNationSlot);
  int tradeMetricValue = (int)QueryNationMetricBySlot(activeNationState, tradeMetricSlot);
  if (tradeMetricValue > metricClampMax) {
    tradeMetricValue = metricClampMax;
  }

  TAmtBar* sellControl = reinterpret_cast<TAmtBar*>(this->ResolveControlByTag(kControlTagSell));
  if (sellControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineUpdateSell);
  }
  if (sellControl != 0) {
    sellControl->SetControlValueSlot1E4(tradeMetricValue, 1);
  }

  TAmtBar* barControl = reinterpret_cast<TAmtBar*>(this->ResolveControlByTag(kControlTagBar));
  if (barControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineUpdateBar);
  }
  TAmtBar* greenControl = reinterpret_cast<TAmtBar*>(this->ResolveControlByTag(kControlTagGree));
  if (greenControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineUpdateGree);
  }

  if (barControl != 0) {
    TradeBarControlLayout* barLayout = reinterpret_cast<TradeBarControlLayout*>(barControl);
    int barRange = (int)barLayout->barRange;
    if (tradeMetricValue != 0) {
      int barSteps = (int)barLayout->barSteps;
      float barScale = 9999.0f;
      if (barSteps != 0) {
        barScale = (float)barRange / (float)barSteps;
      }
      int scaledMetricValue = (int)((float)tradeMetricValue * barScale);
      barControl->SetBarMetric(scaledMetricValue, barRange);
      return;
    }

    barControl->SetBarMetric(0, barRange);
  }

  if (greenControl != 0) {
    greenControl->SetEnabled(0, 1);
  }
}

// Toggles the enabled state of the trade tool subcontrols (seas/year/trea/tree).
// FUNCTION: IMPERIALISM 0x0059a180
void TTradeCluster::SetTradeToolSubcontrolEnabledStateByFlag(unsigned char enabledFlag) {
  TAmtBar* toolControl = reinterpret_cast<TAmtBar*>(this->ResolveControlByTag(0x746f6f6c));
  if (toolControl == 0) {
    FailNilPointerWithAssert(kUSuperMapCppPath, kAssertLineToolSubcontrolToggle);
  }

  TAmtBar* control = reinterpret_cast<TAmtBar*>(
      reinterpret_cast<TView*>(toolControl)->ResolveControlByTag(0x73656173));
  if (control != 0) {
    control->SetEnabled((int)enabledFlag, 1);
  }
  control = reinterpret_cast<TAmtBar*>(
      reinterpret_cast<TView*>(toolControl)->ResolveControlByTag(0x79656172));
  if (control != 0) {
    control->SetEnabled((int)enabledFlag, 1);
  }
  control = reinterpret_cast<TAmtBar*>(
      reinterpret_cast<TView*>(toolControl)->ResolveControlByTag(0x74726561));
  if (control != 0) {
    control->SetEnabled((int)enabledFlag, 1);
  }
  control = reinterpret_cast<TAmtBar*>(
      reinterpret_cast<TView*>(toolControl)->ResolveControlByTag(0x74726565));
  if (control != 0) {
    control->SetEnabled((int)enabledFlag, 1);
  }
}

#if defined(_MSC_VER)
#pragma optimize("y", on)
#pragma auto_inline(on)
#endif

#if defined(_MSC_VER)
#pragma optimize("y", on)
#endif
