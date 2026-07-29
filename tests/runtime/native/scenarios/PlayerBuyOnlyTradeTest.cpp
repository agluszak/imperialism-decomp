#include "RuntimeScenario.h"
#include "flows/RandomGameFlow.h"
#include "RuntimeUiDriver.h"
#include "screens/StrategicMapDriver.h"

#include "game/diplomacy_domain_types.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_widgets_globals.h"
#include "game/map/TMapUberPicture.h"
#include "game/nation/TGreatPower.h"
#include "game/trade_ui/TOfferDeskPicture.h"
#include "game/turn_event_codes.h"
#include "game/ui_core/TControl.h"
#include "game/ui_core/TDialogBehavior.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_core/TWindow.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_tags_common.h"
#include "game/ui_widgets/TTradeCluster.h"
#include "game/ui_widgets/TTradeOrderPicture.h"
#include "game/ui_widgets/TTradeScreenPicture.h"
#include "game/globals/view_registries.h"

namespace {

class PlayerBuyOnlyTradeTestCase : public RandomGameScenario {
public:
  PlayerBuyOnlyTradeTestCase()
      : phase(kActivateTrade), activeNationSlot(-1), baselineEconomicTurn(0), initialBidBitmap(0),
        leftDealBook(false), sawTurnAlert(false), resubmittedEndTurn(false) {
    for (int resource = 0; resource < kResourceKindCount; ++resource) {
      baselinePurchaseAmounts[resource] = 0;
    }
  }

  int DifficultyLevel() const override {
    return 1;
  }

  bool RecordsGameFlow() const override {
    return true;
  }

  void OnMapReadyWithoutCapitalSelection() override {
    phase = kActivateTrade;
    activeNationSlot = g_pSimMgr->GetActiveNationId();
    TGreatPower* player = g_apNationStates[activeNationSlot];
    if (player == 0 || player->diplomacyEligibilityA0 == 0) {
      FailScenario("\"active player nation was not initialized as human controlled\"");
      return;
    }
    EnterScenarioStep("activating_trade_for_buy_only_order", "reach_combined_map");
    RequestScenarioTick();
  }

  void TickScenario() override {
    if (phase == kActivateTrade) {
      ActivateTrade();
    } else if (phase == kWaitForTrade) {
      WaitForTrade();
    } else if (phase == kActivateIronBid) {
      ActivateIronBid();
    } else if (phase == kVerifyIronBid) {
      VerifyIronBid();
    } else if (phase == kReturnToMap) {
      ReturnToMap();
    } else if (phase == kWaitForMap) {
      WaitForMap();
    } else if (phase == kActivateEndTurn) {
      ActivateEndTurn();
    } else {
      WaitForTurnProcessed();
    }
  }

private:
  enum Phase {
    kActivateTrade,
    kWaitForTrade,
    kActivateIronBid,
    kVerifyIronBid,
    kReturnToMap,
    kWaitForMap,
    kActivateEndTurn,
    kWaitForTurnProcessed
  };

  void ActivateTrade() {
    if (ScenarioPhaseTicks() < 60) {
      RequestScenarioTick();
      return;
    }
    TView* mainView = CurrentMainView();
    if (g_pViewMgr->currentTurnEventCode != kTurnEventStrategicMap || mainView == 0 ||
        mainView->IsKindOf(RUNTIME_CLASS(TMapUberPicture)) == 0 || !g_ModalViewStack.IsEmpty()) {
      WaitForScenarioTick("\"combined map was not idle before opening trade\"");
      return;
    }
    phase = kWaitForTrade;
    EnterScenarioStep("waiting_for_buy_only_trade_screen", "activate_trade_toolbar_control");
    StrategicMapDriver map(mainView);
    if (!map.ActivateTradeSemantically()) {
      FailScenario("\"trade toolbar control is missing or disabled\"");
      return;
    }
    RequestScenarioTick();
  }

  void WaitForTrade() {
    TView* mainView = CurrentMainView();
    if (g_pViewMgr->currentTurnEventCode != kTurnEventTradeOverview || mainView == 0 ||
        mainView->IsKindOf(RUNTIME_CLASS(TTradeScreenPicture)) == 0) {
      WaitForScenarioTick("\"trade toolbar action did not open the Board of Trade\"");
      return;
    }
    TGreatPower* player = g_apNationStates[activeNationSlot];
    for (short resource = 0; resource < kResourceKindCount; ++resource) {
      if (player->GetTradeOffersFor(resource) > 0) {
        FailScenario("\"fresh human nation entered trade with a positive sell order\"");
        return;
      }
    }
    phase = kActivateIronBid;
    EnterScenarioStep("activating_buy_only_iron_bid", "trade_screen_ready_without_sell_orders");
    RequestScenarioTick();
  }

  void ActivateIronBid() {
    TView* mainView = CurrentMainView();
    TTradeCluster* ironRow =
        mainView != 0 ? static_cast<TTradeCluster*>(
                            mainView->ResolveControlByTag(kTradeSellPropagationTags[kResourceIron]))
                      : 0;
    TTradeOrderPicture* bid =
        ironRow != 0
            ? static_cast<TTradeOrderPicture*>(ironRow->ResolveControlByTag(kControlTagCard))
            : 0;
    if (bid == 0 || bid->IsActionable() == 0) {
      FailScenario("\"iron row has no actionable buy control\"");
      return;
    }
    if ((bid->glyphBase84 == 0x83f || bid->glyphBase84 == 0x84d) &&
        ironRow->IsSelectionAllowed() != 0) {
      phase = kReturnToMap;
      EnterScenarioStep("returning_after_buy_only_order", "preserve_existing_iron_buy_order");
      RequestScenarioTick();
      return;
    }
    if (bid->glyphBase84 != 0x840 && bid->glyphBase84 != 0x84e) {
      FailScenario("\"iron buy control is in an unknown bitmap state\"");
      return;
    }
    initialBidBitmap = bid->glyphBase84;
    phase = kVerifyIronBid;
    EnterScenarioStep("verifying_buy_only_iron_bid", "click_iron_buy_control");
    if (!RuntimeUiDriver::ClickViewThroughNativeMessages(bid)) {
      FailScenario("\"iron buy control has no native host\"");
      return;
    }
    RequestScenarioTick();
  }

  void VerifyIronBid() {
    TView* mainView = CurrentMainView();
    TTradeCluster* ironRow =
        mainView != 0 ? static_cast<TTradeCluster*>(
                            mainView->ResolveControlByTag(kTradeSellPropagationTags[kResourceIron]))
                      : 0;
    TTradeOrderPicture* bid =
        ironRow != 0
            ? static_cast<TTradeOrderPicture*>(ironRow->ResolveControlByTag(kControlTagCard))
            : 0;
    if (bid == 0 || bid->glyphBase84 == initialBidBitmap || ironRow->IsSelectionAllowed() == 0) {
      FailScenario("\"iron buy control did not enter the selected bid state\"");
      return;
    }
    phase = kReturnToMap;
    EnterScenarioStep("returning_after_buy_only_order", "click_trade_end_control");
    RequestScenarioTick();
  }

  void ReturnToMap() {
    TView* mainView = CurrentMainView();
    if (mainView == 0 || mainView->IsKindOf(RUNTIME_CLASS(TTradeScreenPicture)) == 0 ||
        !RuntimeUiDriver::ClickControlThroughNativeMessages(mainView, kControlTagEnd)) {
      FailScenario("\"Board of Trade back control could not receive native input\"");
      return;
    }
    phase = kWaitForMap;
    EnterScenarioStep("waiting_for_map_after_buy_only_order", "activate_trade_end_control");
    RequestScenarioTick();
  }

  void WaitForMap() {
    TView* mainView = CurrentMainView();
    if (g_pViewMgr->currentTurnEventCode != kTurnEventStrategicMap || mainView == 0 ||
        mainView->IsKindOf(RUNTIME_CLASS(TMapUberPicture)) == 0 || !g_ModalViewStack.IsEmpty()) {
      WaitForScenarioTick("\"Board of Trade did not return to the combined map\"");
      return;
    }
    TGreatPower* player = g_apNationStates[activeNationSlot];
    if (player == 0 || player->GetTradeOffersFor(kResourceIron) != -1) {
      FailScenario("\"selected iron buy order was not committed as a request\"");
      return;
    }
    for (short resource = 0; resource < kResourceKindCount; ++resource) {
      if (resource != kResourceIron && player->GetTradeOffersFor(resource) > 0) {
        char failure[128];
        wsprintfA(failure, "\"player acquired an unsolicited sell order for resource %d\"",
                  resource);
        FailScenario(failure);
        return;
      }
      baselinePurchaseAmounts[resource] = player->purchasedItemsByResource[resource];
    }
    phase = kActivateEndTurn;
    EnterScenarioStep("activating_end_turn_after_buy_only_order", "verify_posted_trade_orders");
    RequestScenarioTick();
  }

  void ActivateEndTurn() {
    TView* mainView = CurrentMainView();
    baselineEconomicTurn = g_pSimMgr->economicTurn;
    leftDealBook = false;
    sawTurnAlert = false;
    resubmittedEndTurn = false;
    ResetNewspaperAdvance();
    phase = kWaitForTurnProcessed;
    StrategicMapDriver map(mainView);
    if (!map.EndTurnThroughNativeMessages()) {
      FailScenario("\"end-turn control is missing after the buy-only order\"");
      return;
    }
    EnterScenarioStep("waiting_for_buy_only_trade_results", "activate_map_done");
    RequestScenarioTick();
  }

  bool PlayerExecutedNoSales() {
    TGreatPower* player = g_apNationStates[activeNationSlot];
    for (short resource = 0; resource < kResourceKindCount; ++resource) {
      if (player->purchasedItemsByResource[resource] < baselinePurchaseAmounts[resource]) {
        return false;
      }
    }
    return true;
  }

  void WaitForTurnProcessed() {
    if (!g_ModalViewStack.IsEmpty()) {
      TWindow* modal = g_ModalViewStack.GetHead();
      TDialogBehavior* behavior = modal->GetDialogBehavior();
      unsigned long command = behavior != 0 ? behavior->defaultCommandCode : 0;
      TControl* control = static_cast<TControl*>(modal->ResolveControlByTag(command));
      if (behavior == 0 || (command != kControlTagOkay && command != kControlTagPic5) ||
          control == 0 || !RuntimeUiDriver::ActivateControlSemantically(modal, command)) {
        RecordUnexpectedModalView(modal);
        FailScenario("\"buy-only turn opened an unrecognized modal\"");
        return;
      }
      if (command == kControlTagOkay) {
        sawTurnAlert = true;
      }
      RequestScenarioTick();
      return;
    }
    if (g_pViewMgr->currentTurnEventCode == kTurnEventOfferSheet) {
      TView* mainView = CurrentMainView();
      if (mainView == 0 || mainView->IsKindOf(RUNTIME_CLASS(TOfferDeskPicture)) == 0) {
        WaitForScenarioTick("\"offer-sheet event did not construct TOfferDeskPicture\"");
        return;
      }
      TOfferDeskPicture* offerDesk = static_cast<TOfferDeskPicture*>(mainView);
      if (offerDesk->respondingNationSlot != activeNationSlot ||
          offerDesk->offeringNationSlot == activeNationSlot) {
        FailScenario("\"buy-only turn presented an offer not addressed to the player\"");
        return;
      }
      TView* reject = mainView != 0 ? mainView->ResolveControlByTag(kControlTagReje) : 0;
      if (reject == 0 || !RuntimeUiDriver::ActivateControlSemantically(mainView, kControlTagReje)) {
        FailScenario("\"buy-only trade offer reject control could not be activated\"");
        return;
      }
      RequestScenarioTick();
      return;
    }
    if (g_pViewMgr->currentTurnEventCode == kTurnEventDealBook && !leftDealBook) {
      if (!PlayerExecutedNoSales()) {
        FailScenario("\"player sold goods during a turn containing only a buy order\"");
        return;
      }
      leftDealBook = true;
      g_pSimMgr->StartNextPhase();
      RequestScenarioTick();
      return;
    }
    if (AdvanceNewspaperIfNeeded()) {
      return;
    }
    TView* mainView = CurrentMainView();
    if (sawTurnAlert && !resubmittedEndTurn &&
        g_pViewMgr->currentTurnEventCode == kTurnEventStrategicMap && mainView != 0 &&
        mainView->IsKindOf(RUNTIME_CLASS(TMapUberPicture)) != 0 &&
        g_pSimMgr->economicTurn == baselineEconomicTurn) {
      resubmittedEndTurn = true;
      StrategicMapDriver map(mainView);
      if (!map.EndTurnThroughNativeMessages()) {
        FailScenario("\"end-turn control disappeared after turn alerts\"");
        return;
      }
      RequestScenarioTick();
      return;
    }
    if (g_pViewMgr->currentTurnEventCode != kTurnEventStrategicMap || mainView == 0 ||
        mainView->IsKindOf(RUNTIME_CLASS(TMapUberPicture)) == 0 ||
        g_pSimMgr->economicTurn == baselineEconomicTurn) {
      WaitForScenarioTick("\"buy-only turn did not advance to the combined map\"");
      return;
    }
    if (!PlayerExecutedNoSales()) {
      FailScenario("\"player trade history contains an unsolicited sale\"");
      return;
    }
    Pass();
  }

  Phase phase;
  short activeNationSlot;
  short baselineEconomicTurn;
  short initialBidBitmap;
  short baselinePurchaseAmounts[kResourceKindCount];
  bool leftDealBook;
  bool sawTurnAlert;
  bool resubmittedEndTurn;
};

PlayerBuyOnlyTradeTestCase g_test;

} // namespace

RuntimeTestCase* PlayerBuyOnlyTradeTest() {
  return &g_test;
}
