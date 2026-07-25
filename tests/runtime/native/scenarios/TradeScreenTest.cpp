#include "RuntimeScenario.h"
#include "RuntimeUiDriver.h"
#include "screens/StrategicMapDriver.h"

#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_core_globals.h"
#include "game/globals/ui_widgets_globals.h"
#include "game/map/TMapUberPicture.h"
#include "game/turn_event_codes.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_tags_common.h"
#include "game/ui_widgets/TTradeCluster.h"
#include "game/ui_widgets/TTradeOrderPicture.h"
#include "game/ui_widgets/TTradeScreenPicture.h"

namespace {

class TradeScreenTestCase : public RuntimeScenario {
public:
  TradeScreenTestCase() : phase(kActivateTradeScreen), selectedRow(0), initialBidBitmap(0) {}

  const char* Name() const override {
    return "trade_screen_operates";
  }
  bool UsesRandomGameFlow() const override {
    return true;
  }
  bool UsesEasyDifficulty() const override {
    return true;
  }
  bool RecordsGameFlow() const override {
    return true;
  }
  bool RequiresScenarioUiSnapshot() const override {
    return true;
  }

  void OnEasyMapReady() override {
    phase = kActivateTradeScreen;
    EnterScenarioStep("activating_trade_screen", "easy_combined_map_ready_for_trade_screen");
    RequestScenarioTick();
  }

  void RunScenarioStep() override {
    if (phase == kActivateTradeScreen) {
      ActivateTradeScreen();
    } else if (phase == kWaitForTradeScreen) {
      WaitForTradeScreen();
    } else if (phase == kActivateBid) {
      ActivateBid();
    } else if (phase == kVerifyBid) {
      VerifyBid();
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
    if (!map.ActivateTrade()) {
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
    if (!RuntimeUiDriver::ClickView(bid)) {
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
    if (!RuntimeUiDriver::ClickControl(mainView, kControlTagEnd)) {
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
  short initialBidBitmap;
};

TradeScreenTestCase g_test;

} // namespace

RuntimeTestCase* TradeScreenTest() {
  return &g_test;
}
