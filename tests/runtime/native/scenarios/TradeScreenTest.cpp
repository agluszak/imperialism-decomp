#include "RuntimeScenario.h"
#include "flows/RandomGameFlow.h"
#include "RuntimeUiDriver.h"
#include "screens/StrategicMapDriver.h"

#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_core_globals.h"
#include "game/globals/ui_widgets_globals.h"
#include "game/map/TMapUberPicture.h"
#include "game/nation/TGreatPower.h"
#include "game/turn_event_codes.h"
#include "game/ui_core/TNumberText.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_tags_common.h"
#include "game/ui_widgets/TAmtBar.h"
#include "game/ui_widgets/TTradeCluster.h"
#include "game/ui_widgets/TTradeOrderPicture.h"
#include "game/ui_widgets/TTradeScreenPicture.h"

namespace {

class TradeScreenTestCase : public RandomGameScenario {
public:
  TradeScreenTestCase()
      : phase(kActivateTradeScreen), selectedRow(0), selectedSellRow(0), initialBidBitmap(0),
        initialSellValue(0), initialBarValue(0) {}
  int DifficultyLevel() const override {
    return 1;
  }
  bool RecordsGameFlow() const override {
    return true;
  }
  bool RequiresScenarioUiSnapshot() const override {
    return true;
  }

  void OnMapReadyWithoutCapitalSelection() override {
    phase = kActivateTradeScreen;
    EnterScenarioStep("activating_trade_screen", "easy_combined_map_ready_for_trade_screen");
    RequestScenarioTick();
  }

  void TickScenario() override {
    if (phase == kActivateTradeScreen) {
      ActivateTradeScreen();
    } else if (phase == kWaitForTradeScreen) {
      WaitForTradeScreen();
    } else if (phase == kActivateBid) {
      ActivateBid();
    } else if (phase == kVerifyBid) {
      VerifyBid();
    } else if (phase == kActivateOffer) {
      ActivateOffer();
    } else if (phase == kVerifyOffer) {
      VerifyOffer();
    } else if (phase == kVerifyDecrease) {
      VerifyDecrease();
    } else if (phase == kVerifyIncrease) {
      VerifyIncrease();
    } else if (phase == kReturnToMap) {
      ReturnToMap();
    } else {
      WaitForMap();
    }
  }

  void ObserveScenarioUiTree(int eventCode, TView* root) override {
    if (eventCode == kTurnEventTradeOverview) {
      CaptureScenarioUiSnapshot(eventCode, root);
    }
  }

private:
  enum Phase {
    kActivateTradeScreen,
    kWaitForTradeScreen,
    kActivateBid,
    kVerifyBid,
    kActivateOffer,
    kVerifyOffer,
    kVerifyDecrease,
    kVerifyIncrease,
    kReturnToMap,
    kWaitForMap
  };

  void ActivateTradeScreen() {
    if (ScenarioPhaseTicks() < 60) {
      RequestScenarioTick();
      return;
    }
    TView* mainView = CurrentMainView();
    if (g_pUiRuntimeContext->currentTurnEventCode != kTurnEventStrategicMap || mainView == 0 ||
        mainView->IsKindOf(RUNTIME_CLASS(TMapUberPicture)) == 0 || !g_ModalViewStack.IsEmpty()) {
      WaitForScenarioTick("\"combined map was not idle before opening the trade screen\"");
      return;
    }
    phase = kWaitForTradeScreen;
    EnterScenarioStep("waiting_for_trade_screen", "activate_trade_toolbar_control");
    StrategicMapDriver map(mainView);
    if (!map.ActivateTradeSemantically()) {
      FailScenario("\"trade toolbar control is missing or disabled\"");
      return;
    }
    RequestScenarioTick();
  }

  void WaitForTradeScreen() {
    TView* mainView = CurrentMainView();
    if (g_pUiRuntimeContext->currentTurnEventCode != kTurnEventTradeOverview || mainView == 0 ||
        mainView->IsKindOf(RUNTIME_CLASS(TTradeScreenPicture)) == 0) {
      WaitForScenarioTick("\"trade toolbar action did not activate the Board of Trade\"");
      return;
    }
    if (!g_ModalViewStack.IsEmpty()) {
      RecordUnexpectedModalView(static_cast<TView*>(g_ModalViewStack.GetHead()));
      FailScenario("\"trade toolbar action opened an unexpected modal\"");
      return;
    }
    if (mainView->ResolveControlByTag(kControlTagMCap) == 0 ||
        mainView->ResolveControlByTag(kTradeSellPropagationTags[0]) == 0 ||
        mainView->ResolveControlByTag(kControlTagEnd) == 0) {
      FailScenario("\"Board of Trade is missing capacity, commodity, or back controls\"");
      return;
    }
    if (RuntimeTradeDynamicDrawCount() == 0) {
      FailScenario("\"Board of Trade did not render its dynamic price and availability cells\"");
      return;
    }
    if (RuntimeTradeTransparentTextDrawCount() == 0) {
      FailScenario("\"Board of Trade dynamic text was rendered with an opaque background\"");
      return;
    }
    if (ScenarioPhaseElapsedMs() < 1000) {
      RequestScenarioTick();
      return;
    }
    if (HoldAtScenarioScreen("trade")) {
      RedrawWindow(mainView->nativeWindow50->m_hWnd, NULL, NULL, RDW_INVALIDATE | RDW_UPDATENOW);
      Pass();
      return;
    }
    phase = kActivateBid;
    EnterScenarioStep("activating_trade_bid", "select_first_actionable_trade_bid");
    RequestScenarioTick();
  }

  void ActivateBid() {
    TView* mainView = CurrentMainView();
    if (mainView == 0 || mainView->IsKindOf(RUNTIME_CLASS(TTradeScreenPicture)) == 0) {
      FailScenario("\"Board of Trade disappeared before bid selection\"");
      return;
    }
    TTradeOrderPicture* bid = 0;
    for (short commodity = 0; commodity < 0x11; ++commodity) {
      TTradeCluster* row = static_cast<TTradeCluster*>(
          mainView->ResolveControlByTag(kTradeSellPropagationTags[commodity]));
      TTradeOrderPicture* candidate =
          row != 0 ? static_cast<TTradeOrderPicture*>(row->ResolveControlByTag(kControlTagCard))
                   : 0;
      if (candidate != 0 && candidate->IsActionable() != 0 &&
          (candidate->glyphBase84 == 0x840 || candidate->glyphBase84 == 0x84e)) {
        selectedRow = row;
        bid = candidate;
        break;
      }
    }
    if (bid == 0) {
      FailScenario("\"Board of Trade has no inactive actionable bid control\"");
      return;
    }
    initialBidBitmap = bid->glyphBase84;
    phase = kVerifyBid;
    EnterScenarioStep("verifying_trade_bid", "click_first_trade_bid_control");
    if (!RuntimeUiDriver::ClickViewThroughNativeMessages(bid)) {
      FailScenario("\"Board of Trade bid control has no native host\"");
      return;
    }
    RequestScenarioTick();
  }

  void VerifyBid() {
    TView* mainView = CurrentMainView();
    TTradeOrderPicture* bid =
        selectedRow != 0
            ? static_cast<TTradeOrderPicture*>(selectedRow->ResolveControlByTag(kControlTagCard))
            : 0;
    const short expectedBidBitmap =
        selectedRow != 0 && selectedRow->controlTag == kControlTagGd0Sp ? 0x84d : 0x83f;
    if (bid == 0 || bid->glyphBase84 == initialBidBitmap || bid->glyphBase84 != expectedBidBitmap ||
        selectedRow->IsSelectionAllowed() == 0) {
      FailScenario("\"Board of Trade bid selection did not enter the active bid state\"");
      return;
    }
    phase = kActivateOffer;
    EnterScenarioStep("activating_trade_offer", "select_actionable_trade_offer");
    RequestScenarioTick();
  }

  void ActivateOffer() {
    TView* mainView = CurrentMainView();
    if (mainView == 0 || mainView->IsKindOf(RUNTIME_CLASS(TTradeScreenPicture)) == 0) {
      FailScenario("\"Board of Trade disappeared before offer selection\"");
      return;
    }

    TTradeOrderPicture* offer = 0;
    for (short commodity = 0; commodity < 0x11; ++commodity) {
      TTradeCluster* row = static_cast<TTradeCluster*>(
          mainView->ResolveControlByTag(kTradeSellPropagationTags[commodity]));
      TTradeOrderPicture* candidate =
          row != 0 ? static_cast<TTradeOrderPicture*>(row->ResolveControlByTag(kControlTagOffr))
                   : 0;
      TGreatPower* activeNation = g_apNationStates[g_pSimMgr->GetActiveNationId()];
      if (candidate != 0 && candidate->IsActionable() != 0 &&
          (candidate->glyphBase84 == 0x842 || candidate->glyphBase84 == 0x850) &&
          activeNation != 0 && QueryNationMetricBySlot(activeNation, row->tradeMetricSlot) > 1) {
        selectedSellRow = row;
        offer = candidate;
        break;
      }
    }
    if (offer == 0) {
      FailScenario("\"Board of Trade has no inactive actionable offer control\"");
      return;
    }

    TGreatPower* activeNation = g_apNationStates[g_pSimMgr->GetActiveNationId()];
    TNumberText* capacity =
        static_cast<TNumberText*>(mainView->ResolveControlByTag(kControlTagMCap));
    int available = QueryNationMetricBySlot(activeNation, selectedSellRow->tradeMetricSlot);
    int testCapacity = available < 3 ? available : 3;
    if (capacity == 0 || testCapacity <= 1) {
      FailScenario("\"Board of Trade could not seed an adjustable sell capacity\"");
      return;
    }
    activeNation->tradeCapacity = static_cast<short>(testCapacity);
    capacity->SetControlValue(testCapacity, 1);
    TAmtBar* sellBar = static_cast<TAmtBar*>(selectedSellRow->ResolveControlByTag(kControlTagBar));
    if (sellBar == 0) {
      FailScenario("\"Board of Trade offer is missing its amount bar\"");
      return;
    }
    sellBar->auxValueA = static_cast<short>(testCapacity);

    phase = kVerifyOffer;
    EnterScenarioStep("verifying_trade_offer", "click_trade_offer_control");
    if (!RuntimeUiDriver::ClickViewThroughNativeMessages(offer)) {
      FailScenario("\"Board of Trade offer control has no native host\"");
      return;
    }
    RequestScenarioTick();
  }

  bool ResolveSellControls(TNumberText** sellOut, TAmtBar** barOut, TView** leftOut,
                           TView** rightOut) {
    if (selectedSellRow == 0) {
      return false;
    }
    *sellOut = static_cast<TNumberText*>(selectedSellRow->ResolveControlByTag(kControlTagSell));
    *barOut = static_cast<TAmtBar*>(selectedSellRow->ResolveControlByTag(kControlTagBar));
    *leftOut = selectedSellRow->ResolveControlByTag(kControlTagLeft);
    *rightOut = selectedSellRow->ResolveControlByTag(kControlTagRght);
    return *sellOut != 0 && *barOut != 0 && *leftOut != 0 && *rightOut != 0;
  }

  bool SellLabelHasOwnLayout(TNumberText* sell, TView* left, TView* right) {
    CRect sellBounds;
    CRect leftBounds;
    CRect rightBounds;
    sell->QueryBounds(&sellBounds);
    left->QueryBounds(&leftBounds);
    right->QueryBounds(&rightBounds);
    return sellBounds.left >= 0 && sellBounds.top >= -2 &&
           sellBounds.bottom <= selectedSellRow->frameHeight38 &&
           sellBounds.right <= leftBounds.left && leftBounds.right <= rightBounds.left;
  }

  void VerifyOffer() {
    TNumberText* sell;
    TAmtBar* bar;
    TView* left;
    TView* right;
    if (!ResolveSellControls(&sell, &bar, &left, &right)) {
      FailScenario("\"active trade offer is missing its quantity controls\"");
      return;
    }
    initialSellValue = sell->UpdateControlCachedIntFromWindowText();
    initialBarValue = bar->rangeOrMaxValue;
    if (selectedSellRow->GetBoolSlot1DC() == 0 || initialSellValue <= 1 ||
        !SellLabelHasOwnLayout(sell, left, right)) {
      FailScenario("\"trade offer did not expose a non-overlapping adjustable sell quantity\"");
      return;
    }

    phase = kVerifyDecrease;
    EnterScenarioStep("decreasing_trade_sell_amount", "click_trade_sell_left_arrow");
    if (!RuntimeUiDriver::ClickViewThroughNativeMessages(left)) {
      FailScenario("\"trade sell decrease control has no native host\"");
      return;
    }
    RequestScenarioTick();
  }

  void VerifyDecrease() {
    TNumberText* sell;
    TAmtBar* bar;
    TView* left;
    TView* right;
    if (!ResolveSellControls(&sell, &bar, &left, &right)) {
      FailScenario("\"trade sell controls disappeared after decrease\"");
      return;
    }
    int decreasedValue = sell->UpdateControlCachedIntFromWindowText();
    if (decreasedValue != initialSellValue - 1 || bar->rangeOrMaxValue >= initialBarValue ||
        !SellLabelHasOwnLayout(sell, left, right)) {
      char failure[160];
      wsprintfA(failure, "\"trade sell decrease mismatch: sell %d->%d bar %d->%d label_layout=%d\"",
                initialSellValue, decreasedValue, initialBarValue, bar->rangeOrMaxValue,
                SellLabelHasOwnLayout(sell, left, right));
      FailScenario(failure);
      return;
    }

    phase = kVerifyIncrease;
    EnterScenarioStep("increasing_trade_sell_amount", "click_trade_sell_right_arrow");
    if (!RuntimeUiDriver::ClickViewThroughNativeMessages(right)) {
      FailScenario("\"trade sell increase control has no native host\"");
      return;
    }
    RequestScenarioTick();
  }

  void VerifyIncrease() {
    TNumberText* sell;
    TAmtBar* bar;
    TView* left;
    TView* right;
    if (!ResolveSellControls(&sell, &bar, &left, &right) ||
        sell->UpdateControlCachedIntFromWindowText() != initialSellValue ||
        bar->rangeOrMaxValue != initialBarValue || !SellLabelHasOwnLayout(sell, left, right)) {
      FailScenario("\"trade sell increase did not restore the number and bar after a decrease\"");
      return;
    }
    phase = kReturnToMap;
    EnterScenarioStep("returning_from_trade_screen", "click_trade_end_control");
    RequestScenarioTick();
  }

  void ReturnToMap() {
    TView* mainView = CurrentMainView();
    if (mainView == 0 || mainView->IsKindOf(RUNTIME_CLASS(TTradeScreenPicture)) == 0) {
      FailScenario("\"Board of Trade disappeared before back navigation\"");
      return;
    }
    phase = kWaitForMap;
    EnterScenarioStep("waiting_for_map_after_trade", "activate_trade_end_control");
    if (!RuntimeUiDriver::ClickControlThroughNativeMessages(mainView, kControlTagEnd)) {
      FailScenario("\"Board of Trade back control is missing or cannot receive native input\"");
      return;
    }
    RequestScenarioTick();
  }

  void WaitForMap() {
    TView* mainView = CurrentMainView();
    if (g_pUiRuntimeContext->currentTurnEventCode != kTurnEventStrategicMap || mainView == 0 ||
        mainView->IsKindOf(RUNTIME_CLASS(TMapUberPicture)) == 0) {
      WaitForScenarioTick("\"Board of Trade back control did not restore the strategic map\"");
      return;
    }
    if (!g_ModalViewStack.IsEmpty()) {
      RecordUnexpectedModalView(static_cast<TView*>(g_ModalViewStack.GetHead()));
      FailScenario("\"Board of Trade back navigation left an unexpected modal\"");
      return;
    }
    if (ScenarioPhaseTicks() < 20) {
      RequestScenarioTick();
      return;
    }
    Pass();
  }

  Phase phase;
  TTradeCluster* selectedRow;
  TTradeCluster* selectedSellRow;
  short initialBidBitmap;
  int initialSellValue;
  short initialBarValue;
};

TradeScreenTestCase g_test;

} // namespace

RuntimeTestCase* TradeScreenTest() {
  return &g_test;
}
