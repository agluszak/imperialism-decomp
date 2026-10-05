#include "game/ui_widgets/TIndustryCluster.h"
#include "game/ui_core/TNumberText.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_widgets.h"
#include "game/ui_core/TWindow.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_widgets/TRailCluster.h"
#include "game/ui_widgets/TShipyardCluster.h"
#include "game/mfc.h"
#include "game/ui_core/TViewMgr.h"
#include "game/quickdraw_guards.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_widgets_globals.h"
#include <new>

// TTradeCluster (VTABLE 0x665a70): the trade-screen sell/bid/offer cluster.
// Owns the Sell/Bar/Bid/Offer child-control state machine for one trade row.

#include "decomp_types.h"

#include "game/ui_widgets/TTradeCluster.h"
#include "game/ui_core/TView.h"
#include "game/ui_widgets/TAmtBar.h"
#include "game/ui_core/TPicture.h"
#include "game/nation/TGreatPower.h"
#include "game/gfx/ui_invalidation_guard.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/TEvent.h"
#include "game/ui_text_label_helpers_decls.h"

// Bid/Offer picture-button bitmap states (enabled / row-selected variants).
const short kTradeBitmapBidStateA = 0x083f;
const short kTradeBitmapBidStateB = 0x084d;
const short kTradeBitmapBidSecondaryStateA = 0x0840;
const short kTradeBitmapBidSecondaryStateB = 0x084e;
const short kTradeBitmapOfferStateA = 0x0841;
const short kTradeBitmapOfferStateB = 0x084f;
const short kTradeBitmapOfferSecondaryStateA = 0x0842;
const short kTradeBitmapOfferSecondaryStateB = 0x0850;
const int kTradeRowStateTag_67643020 = kControlTagGd0Sp;

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

const char kUSuperMapCppPath[] = "D:\\Ambit\\Cross\\USuperMap.cpp";

static short QueryNationTradeCapacity(TGreatPower* nationState) {
  return nationState->merchantCapacity;
}

IMPLEMENT_DYNCREATE(TTradeCluster, TAmtBarCluster)

// FUNCTION: IMPERIALISM 0x005870b0
TTradeCluster::TTradeCluster() : TAmtBarCluster() {}

// FUNCTION: IMPERIALISM 0x00587130
void TTradeCluster::DoPostCreate(int styleSeed) {
  TNumberText* sellControl = static_cast<TNumberText*>(this->ResolveControlByTag(kControlTagSell));
  if (sellControl != 0) {
    TextStyle style;
    InitializeUiTextStyleDescriptor(&style, 0, 0xe, 0x2b68, 2);
    sellControl->InstallTextStyle(style, 0);
    sellControl->SetJustification(-1, false);
    CRect boundsBuffer;
    boundsBuffer.left = 0;
    boundsBuffer.top = 0;
    sellControl->QueryBounds(&boundsBuffer);
    boundsBuffer.top = boundsBuffer.top - 2;
    sellControl->ApplyBounds(&boundsBuffer, true);
  }

  TAmtBar* barControl = static_cast<TAmtBar*>(this->ResolveControlByTag(kControlTagBar));
  if (barControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineInitBar);
  }
  barControl->ViewEnable(0, 0);

  TView* leftControl = this->ResolveControlByTag(kControlTagLeft);
  if (leftControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineInitLeft);
  }
  TView* rightControl = this->ResolveControlByTag(kControlTagRght);
  if (rightControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineInitRight);
  }
  leftControl->ViewEnable(0, 0);
  rightControl->ViewEnable(0, 0);

  short activeNationSlot = g_pSimMgr->GetPlayerCountry();
  TGreatPower* activeNationState = g_apNationStates[activeNationSlot];
  if (activeNationState != 0 && QueryNationTradeCapacity(activeNationState) == 0) {
    leftControl->Show(0, 0);
    rightControl->Show(0, 0);
    barControl->Show(0, 0);
    TView* greenControl = this->ResolveControlByTag(kControlTagGree);
    if (greenControl == 0) {
      FailNilPointerInUSmallViews(kAssertLineInitGree);
    }
    if (greenControl != 0) {
      greenControl->Show(0, 0);
    }
  }

  TAmtBarCluster::DoPostCreate(styleSeed);
}

// FUNCTION: IMPERIALISM 0x005873e0
void TTradeCluster::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  TView* ownerPanel = this->GetWindow();

  switch (commandId) {
  case 100: {
    if (this->IsSellOffer() != '\0') {
      TNumberText* sellControl =
          static_cast<TNumberText*>(this->ResolveControlByTag(kControlTagSell));
      if (sellControl == 0) {
        FailNilPointerInUSmallViews(kAssertLineTradeSellIncSell);
      }

      int sellValue = sellControl->UpdateControlCachedIntFromWindowText();
      short activeNationSlot = g_pSimMgr->GetPlayerCountry();
      TGreatPower* activeNationState = g_apNationStates[activeNationSlot];
      short maxByNationMetric = activeNationState->GetStockpile(tradeMetricSlot);

      TNumberText* capacityControl =
          static_cast<TNumberText*>(ownerPanel->ResolveControlByTag(kControlTagMCap));
      if (capacityControl == 0) {
        FailNilPointerInUSmallViews(kAssertLineTradeSellIncCap);
      }

      if (sellValue < (int)maxByNationMetric) {
        int capacityValue = capacityControl->UpdateControlCachedIntFromWindowText();
        if (sellValue < capacityValue) {
          sellControl->Show(sellValue + 1 != 0, 1);
          this->SetMoveAmount(static_cast<short>(sellValue + 1));
          return;
        }
      }
    }
    break;
  }
  case 0x65: {
    TNumberText* sellControl =
        static_cast<TNumberText*>(this->ResolveControlByTag(kControlTagSell));
    if (sellControl == 0) {
      FailNilPointerInUSmallViews(kAssertLineTradeSellDecSell);
    }
    int sellValue = sellControl->UpdateControlCachedIntFromWindowText();
    if (1 < sellValue) {
      this->SetMoveAmount(static_cast<short>(sellValue - 1));
      return;
    }
    return;
  }
  case 0x66:
    return;
  case 0x67:
    g_pViewMgr->AddPendingTurnOverlayCode(-1);
    if (g_pViewMgr->GetPendingTurnOverlayCode() == 3) {
      for (int i = 0;
           i < (int)(sizeof(kTradeSellPropagationTags) / sizeof(kTradeSellPropagationTags[0]));
           ++i) {
        TTradeCluster* rowControl = static_cast<TTradeCluster*>(
            ownerPanel->ResolveControlByTag(kTradeSellPropagationTags[i]));
        if (rowControl != 0 && rowControl->IsSelectionAllowed() == '\0') {
          rowControl->DoControlAction();
        }
      }
      return;
    }
    break;
  case 0x68:
    g_pViewMgr->AddPendingTurnOverlayCode(1);
    if (g_pViewMgr->GetPendingTurnOverlayCode() == 4) {
      for (int i = 0;
           i < (int)(sizeof(kTradeSellPropagationTags) / sizeof(kTradeSellPropagationTags[0]));
           ++i) {
        TTradeCluster* rowControl = static_cast<TTradeCluster*>(
            ownerPanel->ResolveControlByTag(kTradeSellPropagationTags[i]));
        if (rowControl != 0 && rowControl->IsSelectionAllowed() == '\0') {
          rowControl->DoControlAction();
        }
      }
      return;
    }
    break;
  case 0x69: {
    short activeNationSlot = g_pSimMgr->GetPlayerCountry();
    TGreatPower* activeNationState = g_apNationStates[activeNationSlot];
    short maxByNationMetric = activeNationState->GetStockpile(tradeMetricSlot);

    TNumberText* capacityControl =
        static_cast<TNumberText*>(ownerPanel->ResolveControlByTag(kControlTagMCap));
    if (capacityControl == 0) {
      FailNilPointerInUSmallViews(kAssertLineTradeSellMoveSell);
    }
    short cappedValue = (short)capacityControl->UpdateControlCachedIntFromWindowText();
    int applyValue = (int)maxByNationMetric;
    if ((int)cappedValue <= (int)maxByNationMetric) {
      applyValue = (int)cappedValue;
    }

    TControl* sellControl = static_cast<TControl*>(this->ResolveControlByTag(kControlTagSell));
    sellControl->Show(1, 1);

    TControl* barControl = static_cast<TControl*>(this->ResolveControlByTag(kControlTagBar));
    if (barControl == 0) {
      FailNilPointerInUSmallViews(kAssertLineTradeSellMoveBar);
    }
    barControl->ViewEnable(1, 0);
    this->SetMoveAmount(static_cast<short>(applyValue));
    return;
  }
  case 0x6a: {
    TControl* sellControl = static_cast<TControl*>(this->ResolveControlByTag(kControlTagSell));
    sellControl->Show(0, 1);

    TControl* barControl = static_cast<TControl*>(this->ResolveControlByTag(kControlTagBar));
    if (barControl == 0) {
      FailNilPointerInUSmallViews(kAssertLineTradeSellZeroBar);
    }
    barControl->ViewEnable(0, 1);
    this->SetMoveAmount(0);
    return;
  }
  default:
    TAmtBarCluster::DoEvent(commandId, sourceHandler, event);
    return;
  }
}

// FUNCTION: IMPERIALISM 0x00587900
char TTradeCluster::IsTradeControlAtMinimum() {
  if (g_pViewMgr->GetPendingTurnOverlayCode() > 3) {
    return 0;
  }
  TNumberText* sellControl = static_cast<TNumberText*>(this->ResolveControlByTag(kControlTagSell));
  return sellControl->UpdateControlCachedIntFromWindowText() <= 0 ? 1 : 0;
}

// FUNCTION: IMPERIALISM 0x00587950
int TTradeCluster::GetTradeSellControlValue() {
  TNumberText* sellControl = static_cast<TNumberText*>(this->ResolveControlByTag(kControlTagSell));
  return sellControl->UpdateControlCachedIntFromWindowText();
}

// FUNCTION: IMPERIALISM 0x00587980
unsigned char TTradeCluster::IsSelectionAllowed() {
  TPicture* bidControl = static_cast<TPicture*>(this->ResolveControlByTag(kControlTagCard));
  if (bidControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineBidActionable);
  }

  if (bidControl->glyphBase84 != kTradeBitmapBidStateA &&
      bidControl->glyphBase84 != kTradeBitmapBidStateB) {
    return 0;
  }

  bool actionable = bidControl->IsActionable();
  if (!actionable) {
    return 0;
  }
  return 1;
}

// FUNCTION: IMPERIALISM 0x00587a10
int TTradeCluster::IsSellOffer() {
  TPicture* offerControl = static_cast<TPicture*>(this->ResolveControlByTag(kControlTagOffr));
  if (offerControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineOfferActionable);
  }

  if (offerControl->glyphBase84 != kTradeBitmapOfferStateA &&
      offerControl->glyphBase84 != kTradeBitmapOfferStateB) {
    return 0;
  }

  bool actionable = offerControl->IsActionable();
  if (!actionable) {
    return 0;
  }
  return 1;
}

// FUNCTION: IMPERIALISM 0x00587aa0
void TTradeCluster::DoControlAction() {
  TPicture* bidControl = static_cast<TPicture*>(this->ResolveControlByTag(kControlTagCard));
  if (bidControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineBidSecondary);
  }

  CPoint size(0x11, 0x14);
  bidControl->Resize(size, true);

  if (g_pViewMgr->GetPendingTurnOverlayCode() < 4) {
    bidControl->Show(1, 1);
    if (controlTag == kTradeRowStateTag_67643020) {
      bidControl->SetPictureRsrcID(kTradeBitmapBidSecondaryStateB, 0);
    } else {
      bidControl->SetPictureRsrcID(kTradeBitmapBidSecondaryStateA, 0);
    }
    bidControl->PrepareForDrawing();
    bidControl->PaintOrInvalidateControl();
    return;
  }

  bidControl->Show(0, 1);
}

// FUNCTION: IMPERIALISM 0x00587bb0
void TTradeCluster::SetTradeBidControlBitmap() {
  TPicture* bidControl = static_cast<TPicture*>(this->ResolveControlByTag(kControlTagCard));
  if (bidControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineBidControl);
  }

  bidControl->Show(1, 0);
  if (controlTag == kTradeRowStateTag_67643020) {
    bidControl->SetPictureRsrcID(kTradeBitmapBidStateB, 0);
  } else {
    bidControl->SetPictureRsrcID(kTradeBitmapBidStateA, 0);
  }

  CPoint size(0x41, 0x14);
  bidControl->Resize(size, true);

  TView* greenControl = this->ResolveControlByTag(kControlTagGree);
  if (greenControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineBidGree);
  }
  TView* leftControl = this->ResolveControlByTag(kControlTagLeft);
  if (leftControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineBidLeft);
  }
  TView* rightControl = this->ResolveControlByTag(kControlTagRght);
  if (rightControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineBidRight);
  }

  greenControl->Show(0, 1);
  leftControl->Show(0, 1);
  rightControl->Show(0, 1);
  greenControl->ViewEnable(0, 1);
  leftControl->ViewEnable(0, 1);
  rightControl->ViewEnable(0, 1);

  bidControl->PrepareForDrawing();
  bidControl->PaintOrInvalidateControl();
}

// FUNCTION: IMPERIALISM 0x00587dd0
void TTradeCluster::SetTradeOfferControlBitmap() {
  TPicture* offerControl = static_cast<TPicture*>(this->ResolveControlByTag(kControlTagOffr));
  if (offerControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineOfferControl);
  }

  offerControl->Show(1, 0);
  if (controlTag == kTradeRowStateTag_67643020) {
    offerControl->SetPictureRsrcID(kTradeBitmapOfferStateB, 0);
  } else {
    offerControl->SetPictureRsrcID(kTradeBitmapOfferStateA, 0);
  }

  CPoint size(0x41, 0x14);
  offerControl->Resize(size, true);
  CPoint layoutCaptureF0(0x73, 0);
  offerControl->Locate(layoutCaptureF0, true);

  TView* greenControl = this->ResolveControlByTag(kControlTagGree);
  if (greenControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineOfferGree);
  }
  TView* leftControl = this->ResolveControlByTag(kControlTagLeft);
  if (leftControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineOfferLeft);
  }
  TView* rightControl = this->ResolveControlByTag(kControlTagRght);
  if (rightControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineOfferRight);
  }

  greenControl->Show(1, 1);
  leftControl->Show(1, 1);
  rightControl->Show(1, 1);
  greenControl->ViewEnable(1, 1);
  leftControl->ViewEnable(1, 1);
  rightControl->ViewEnable(1, 1);

  offerControl->PrepareForDrawing();
  offerControl->PaintOrInvalidateControl();
}

// FUNCTION: IMPERIALISM 0x00588030
void TTradeCluster::SetTradeOfferSecondaryBitmap() {
  TPicture* offerControl = static_cast<TPicture*>(this->ResolveControlByTag(kControlTagOffr));
  if (offerControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineOfferSecondaryOffr);
  }

  CPoint size(0x11, 0x14);
  offerControl->Resize(size, true);

  short activeNationSlot = g_pSimMgr->GetPlayerCountry();
  TGreatPower* activeNationState = g_apNationStates[activeNationSlot];
  short tradeMetricAvailable = activeNationState->GetStockpile(tradeMetricSlot);

  if (tradeMetricAvailable != 0) {
    short activeNationSlotAgain = g_pSimMgr->GetPlayerCountry();
    TGreatPower* activeNationStateAgain = g_apNationStates[activeNationSlotAgain];
    if (QueryNationTradeCapacity(activeNationStateAgain) != 0) {
      offerControl->Show(1, 0);
      if (controlTag == kTradeRowStateTag_67643020) {
        offerControl->SetPictureRsrcID(kTradeBitmapOfferSecondaryStateB, 0);
      } else {
        offerControl->SetPictureRsrcID(kTradeBitmapOfferSecondaryStateA, 0);
      }
      CPoint layoutCaptureF0(0xa3, 0);
      offerControl->Locate(layoutCaptureF0, true);
    } else {
      offerControl->Show(0, 1);
    }
  } else {
    offerControl->Show(0, 1);
  }

  TView* greenControl = this->ResolveControlByTag(kControlTagGree);
  if (greenControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineOfferSecondaryGree);
  }
  TView* leftControl = this->ResolveControlByTag(kControlTagLeft);
  if (leftControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineOfferSecondaryLeft);
  }
  TView* rightControl = this->ResolveControlByTag(kControlTagRght);
  if (rightControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineOfferSecondaryRight);
  }

  greenControl->Show(0, 1);
  leftControl->Show(0, 1);
  rightControl->Show(0, 1);
  greenControl->ViewEnable(0, 1);
  leftControl->ViewEnable(0, 1);
  rightControl->ViewEnable(0, 1);

  offerControl->PrepareForDrawing();
  offerControl->PaintOrInvalidateControl();
}

// FUNCTION: IMPERIALISM 0x005882f0
void TTradeCluster::SetMoveAmount(short metricClampMax) {
  short activeNationSlot = g_pSimMgr->GetPlayerCountry();
  TGreatPower* activeNationState = g_apNationStates[activeNationSlot];
  int tradeMetricValue = (int)activeNationState->GetStockpile(tradeMetricSlot);
  if (tradeMetricValue > metricClampMax) {
    tradeMetricValue = metricClampMax;
  }

  TNumberText* sellControl = static_cast<TNumberText*>(this->ResolveControlByTag(kControlTagSell));
  if (sellControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineUpdateSell);
  }
  sellControl->SetControlValue(tradeMetricValue, 1);

  TAmtBar* barControl = static_cast<TAmtBar*>(this->ResolveControlByTag(kControlTagBar));
  if (barControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineUpdateBar);
  }
  TView* greenControl = this->ResolveControlByTag(kControlTagGree);
  if (greenControl == 0) {
    FailNilPointerInUSmallViews(kAssertLineUpdateGree);
  }

  int barRange = barControl->frameWidth;
  if (tradeMetricValue != 0) {
    int barSteps = barControl->auxValueA;
    float barScale = 9999.0f;
    if (barSteps != 0) {
      barScale = (float)barRange / (float)barSteps;
    }
    int scaledMetricValue = (int)((float)tradeMetricValue * barScale);
    barControl->UpdateBarValuesAndRefresh(static_cast<short>(scaledMetricValue),
                                          static_cast<short>(barRange));
    return;
  }

  barControl->UpdateBarValuesAndRefresh(0, static_cast<short>(barRange));
  greenControl->Show(0, 1);
}
