#include "RuntimeScenario.h"
#include "flows/RandomGameFlow.h"
#include "RuntimeUiDriver.h"
#include "screens/StrategicMapDriver.h"

#include "game/app/TAnimation.h"
#include "game/app/TAnimator.h"
#include "game/diplomacy_domain_types.h"
#include "game/diplomacy_ui/TDiplomacyMapView.h"
#include "game/TList.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_core_globals.h"
#include "game/globals/ui_widgets_globals.h"
#include "game/map/TMapUberPicture.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/nation/TGreatPower.h"
#include "game/resource_manifest_tags.h"
#include "game/trade_ui/TDealBookPicture.h"
#include "game/trade_ui/TOfferDeskPicture.h"
#include "game/trade_ui/TDealTabControl.h"
#include "game/trade_ui/TTradePageBuyView.h"
#include "game/trade_ui/TTradePageSellView.h"
#include "game/turn_event_codes.h"
#include "game/ui_core/TNumberText.h"
#include "game/ui_core/TStaticText.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_screens/TSidewaysArrow.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_city.h"
#include "game/ui_tags_diplomacy.h"
#include "game/ui_widgets/TAmtBar.h"
#include "game/ui_widgets/TDropShadowText.h"
#include "game/ui_widgets/TTradeCluster.h"
#include "game/ui_widgets/TTradeMgr.h"
#include "game/ui_widgets/TTradeOrderPicture.h"
#include "game/ui_widgets/TTradeScreenPicture.h"
#include "game/globals/view_registries.h"

namespace {

class TradeScreenTestCase : public RandomGameScenario {
public:
  TradeScreenTestCase()
      : phase(kActivateDiplomacyScreen), warTargetNation(-1), warPolicyBeforeAction(-1),
        selectedRow(0), selectedSellRow(0), selectedBidCommodity(-1), selectedSellCommodity(-1),
        initialBidBitmap(0), initialSellValue(0), initialBarValue(0), baselineEconomicTurn(0),
        handledOffers(0), leftDealBook(false), verifiedOfferPresentation(false),
        exercisedOfferBookmark(false), offerRegressionPosed(false), offerBookmarkRow(0),
        offerRegressionCompleted(false), offerAcceptancePosed(false),
        offerAcceptanceCompleted(false), verifiedPostedTradeDirections(false) {}
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
    phase = kActivateDiplomacyScreen;
    EnterScenarioStep("activating_diplomacy_before_trade", "easy_combined_map_ready_for_diplomacy");
    ContinueAfterAction();
  }

  void AdvanceScenario() override {
    if (phase == kActivateDiplomacyScreen) {
      ActivateDiplomacyScreen();
    } else if (phase == kWaitForDiplomacyScreen) {
      WaitForDiplomacyScreen();
    } else if (phase == kActivateTreatiesTopic) {
      ActivateTreatiesTopic();
    } else if (phase == kSelectWarAction) {
      SelectWarAction();
    } else if (phase == kDeclareWar) {
      DeclareWar();
    } else if (phase == kVerifyWarOrder) {
      VerifyWarOrder();
    } else if (phase == kReturnFromDiplomacy) {
      ReturnFromDiplomacy();
    } else if (phase == kWaitForMapBeforeTrade) {
      WaitForMapBeforeTrade();
    } else if (phase == kActivateTradeScreen) {
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
    } else if (phase == kWaitForMap) {
      WaitForMap();
    } else if (phase == kWaitForOfferRegression) {
      WaitForOfferRegression();
    } else if (phase == kWaitForOfferAcceptance) {
      WaitForOfferAcceptance();
    } else {
      WaitForEndTurn();
    }
  }

  void ObserveScenarioUiTree(int eventCode, TView* root) override {
    if (eventCode == kTurnEventTradeOverview) {
      CaptureScenarioUiSnapshot(eventCode, root);
    }
  }

private:
  enum { kMapAnimationRegressionTag = 0x74727374 };

  enum Phase {
    kActivateDiplomacyScreen,
    kWaitForDiplomacyScreen,
    kActivateTreatiesTopic,
    kSelectWarAction,
    kDeclareWar,
    kVerifyWarOrder,
    kReturnFromDiplomacy,
    kWaitForMapBeforeTrade,
    kActivateTradeScreen,
    kWaitForTradeScreen,
    kActivateBid,
    kVerifyBid,
    kActivateOffer,
    kVerifyOffer,
    kVerifyDecrease,
    kVerifyIncrease,
    kReturnToMap,
    kWaitForMap,
    kWaitForOfferRegression,
    kWaitForOfferAcceptance,
    kWaitForEndTurn
  };

  TDiplomacyMapView* DiplomacyView() const {
    TView* mainView = CurrentMainView();
    if (mainView == 0 || mainView->IsKindOf(RUNTIME_CLASS(TDiplomacyMapView)) == 0) {
      return 0;
    }
    return static_cast<TDiplomacyMapView*>(mainView);
  }

  void ActivateDiplomacyScreen() {
    TView* mainView = CurrentMainView();
    if (g_pViewMgr->currentTurnEventCode != kTurnEventStrategicMap || mainView == 0 ||
        mainView->IsKindOf(RUNTIME_CLASS(TMapUberPicture)) == 0 || !g_ModalViewStack.IsEmpty()) {
      AwaitUiChange("\"combined map was not idle before declaring war\"");
      return;
    }
    phase = kWaitForDiplomacyScreen;
    EnterScenarioStep("waiting_for_diplomacy_before_trade", "activate_diplomacy_toolbar_control");
    StrategicMapDriver map(mainView);
    if (!map.OpenDiplomacy()) {
      FailScenario("\"diplomacy toolbar control is missing or disabled\"");
      return;
    }
    Await(kObserveRuntimeBarrier, "\"pre-trade diplomacy transition did not reach its barrier\"");
    if (!RuntimeUiDriver::PostBarrier()) {
      FailScenario("\"pre-trade diplomacy barrier could not be posted\"");
    }
  }

  void WaitForDiplomacyScreen() {
    TDiplomacyMapView* diplomacy = DiplomacyView();
    if (g_pViewMgr->currentTurnEventCode != kTurnEventDiplomacyMap || diplomacy == 0) {
      AwaitUiChange("\"diplomacy toolbar action did not activate diplomacy orders\"");
      return;
    }
    phase = kActivateTreatiesTopic;
    EnterScenarioStep("activating_treaties_before_trade", "click_treaties_action_topic");
    ContinueAfterAction();
  }

  void ActivateTreatiesTopic() {
    TDiplomacyMapView* diplomacy = DiplomacyView();
    if (diplomacy == 0) {
      FailScenario("\"diplomacy treaties action topic is unavailable\"");
      return;
    }
    diplomacy->ChangeSelectedActionTopic(1);
    phase = kSelectWarAction;
    EnterScenarioStep("selecting_war_before_trade", "click_declare_war_action");
    ContinueAfterAction();
  }

  void SelectWarAction() {
    TDiplomacyMapView* diplomacy = DiplomacyView();
    if (diplomacy == 0 || diplomacy->RuntimeActionTopicIndex() != 1) {
      AwaitUiChange("\"diplomacy treaties action did not become active\"");
      return;
    }
    if (!RuntimeUiDriver::Activate(
            diplomacy, RuntimeControlSelector(kControlTagScr0 + 4, RUNTIME_CLASS(TControl)))) {
      FailScenario("\"declare-war action is missing or cannot receive input\"");
      return;
    }
    phase = kDeclareWar;
    EnterScenarioStep("declaring_war_before_trade", "click_valid_war_target_nation");
    ContinueAfterAction();
  }

  void DeclareWar() {
    TDiplomacyMapView* diplomacy = DiplomacyView();
    if (diplomacy == 0 || diplomacy->actionCodeBC != kDipActionDeclareWar) {
      AwaitUiChange("\"declare-war action did not become active\"");
      return;
    }
    const short activeNation = g_pSimMgr->GetActiveNationId();
    for (short nation = 0; nation < 7; ++nation) {
      if (nation != activeNation && g_apTerrainTypeDescriptorTable[nation] != 0 &&
          g_pDiplomacyTurnStateManager->ValidateDiplomacyActionTypeAgainstTargetAndSetRejectCode(
              activeNation, nation, kDipActionDeclareWar)) {
        warTargetNation = nation;
        break;
      }
    }
    TGreatPower* sourceNation = g_apNationStates[activeNation];
    if (warTargetNation < 0 || sourceNation == 0 ||
        g_apTerrainTypeDescriptorTable[warTargetNation] == 0) {
      FailScenario("\"diplomacy map has no valid major-nation war target\"");
      return;
    }
    warPolicyBeforeAction = sourceNation->diplomacyPolicyByNation[warTargetNation];
    diplomacy->ActivateNation(warTargetNation);
    phase = kVerifyWarOrder;
    EnterScenarioStep("verifying_war_before_trade", "verify_declare_war_policy");
    ContinueAfterAction();
  }

  void VerifyWarOrder() {
    TGreatPower* sourceNation = g_apNationStates[g_pSimMgr->GetActiveNationId()];
    const short expectedPolicy = warPolicyBeforeAction == kDiplomacyProposalDeclareWar
                                     ? -1
                                     : static_cast<short>(kDiplomacyProposalDeclareWar);
    if (DiplomacyView() == 0 || sourceNation == 0 ||
        sourceNation->diplomacyPolicyByNation[warTargetNation] != expectedPolicy ||
        !g_ModalViewStack.IsEmpty()) {
      FailScenario("\"declare-war action did not update the target policy\"");
      return;
    }
    phase = kReturnFromDiplomacy;
    EnterScenarioStep("returning_from_diplomacy_before_trade", "click_diplomacy_end_control");
    ContinueAfterAction();
  }

  void ReturnFromDiplomacy() {
    TDiplomacyMapView* diplomacy = DiplomacyView();
    if (diplomacy == 0 ||
        !RuntimeUiDriver::Activate(
            diplomacy, RuntimeControlSelector(kControlTagEnd, RUNTIME_CLASS(TControl)))) {
      FailScenario("\"diplomacy back control is missing or cannot receive native input\"");
      return;
    }
    phase = kWaitForMapBeforeTrade;
    EnterScenarioStep("waiting_for_map_before_trade", "activate_diplomacy_end_control");
    ContinueAfterAction();
  }

  void WaitForMapBeforeTrade() {
    TView* mainView = CurrentMainView();
    if (g_pViewMgr->currentTurnEventCode != kTurnEventStrategicMap || mainView == 0 ||
        mainView->IsKindOf(RUNTIME_CLASS(TMapUberPicture)) == 0 || !g_ModalViewStack.IsEmpty()) {
      AwaitUiChange("\"diplomacy back control did not restore the strategic map\"");
      return;
    }
    phase = kActivateTradeScreen;
    EnterScenarioStep("activating_trade_screen", "declared_war_and_returned_to_map");
    ContinueAfterAction();
  }

  void ActivateTradeScreen() {
    TView* mainView = CurrentMainView();
    if (g_pViewMgr->currentTurnEventCode != kTurnEventStrategicMap || mainView == 0 ||
        mainView->IsKindOf(RUNTIME_CLASS(TMapUberPicture)) == 0 || !g_ModalViewStack.IsEmpty()) {
      AwaitUiChange("\"combined map was not idle before opening the trade screen\"");
      return;
    }
    if (g_pUiAnimator == 0 || g_pUiAnimator->registryList24 == 0) {
      FailScenario("\"UI animator registry is unavailable before opening trade\"");
      return;
    }
    RECT animationBounds = {0, 0, 1, 1};
    TAnimation* mapAnimation = new TAnimation();
    mapAnimation->IAnimation(mainView, &animationBounds, 2, 0, 0x7fffffff,
                             kMapAnimationRegressionTag);
    g_pUiAnimator->AddObjectToUiTransientRegistry(mapAnimation);
    if (g_pUiAnimator->FindRegisteredAnimationByTag(kMapAnimationRegressionTag) != mapAnimation) {
      FailScenario("\"map-owned animation was not registered before opening trade\"");
      return;
    }
    phase = kWaitForTradeScreen;
    EnterScenarioStep("waiting_for_trade_screen", "activate_trade_toolbar_control");
    StrategicMapDriver map(mainView);
    if (!map.OpenTrade()) {
      FailScenario("\"trade toolbar control is missing or disabled\"");
      return;
    }
    ContinueAfterAction();
  }

  void WaitForTradeScreen() {
    TView* mainView = CurrentMainView();
    if (g_pViewMgr->currentTurnEventCode != kTurnEventTradeOverview || mainView == 0 ||
        mainView->IsKindOf(RUNTIME_CLASS(TTradeScreenPicture)) == 0) {
      AwaitUiChange("\"trade toolbar action did not activate the Board of Trade\"");
      return;
    }
    if (!g_ModalViewStack.IsEmpty()) {
      RecordUnexpectedModalView(g_ModalViewStack.GetHead());
      FailScenario("\"trade toolbar action opened an unexpected modal\"");
      return;
    }
    if (g_pUiAnimator == 0 || g_pUiAnimator->registryList24 == 0 ||
        g_pUiAnimator->registryList24->GetCount() != 0) {
      FailScenario("\"map-owned animations survived into the Board of Trade\"");
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
    if (HoldAtScenarioScreen("trade")) {
      RedrawWindow(mainView->nativeWindow50->m_hWnd, NULL, NULL, RDW_INVALIDATE | RDW_UPDATENOW);
      Pass();
      return;
    }
    phase = kActivateBid;
    EnterScenarioStep("activating_trade_bid", "select_first_actionable_trade_bid");
    ContinueAfterAction();
  }

  void ActivateBid() {
    TView* mainView = CurrentMainView();
    if (mainView == 0 || mainView->IsKindOf(RUNTIME_CLASS(TTradeScreenPicture)) == 0) {
      FailScenario("\"Board of Trade disappeared before bid selection\"");
      return;
    }
    TTradeOrderPicture* bid = 0;
    for (short commodity = kResourceIron; commodity <= kResourceIron; ++commodity) {
      TTradeCluster* row = static_cast<TTradeCluster*>(
          mainView->ResolveControlByTag(kTradeSellPropagationTags[commodity]));
      TTradeOrderPicture* candidate =
          row != 0 ? static_cast<TTradeOrderPicture*>(row->ResolveControlByTag(kControlTagCard))
                   : 0;
      if (candidate != 0 && candidate->IsActionable() != 0 &&
          (candidate->glyphBase84 == 0x840 || candidate->glyphBase84 == 0x84e)) {
        selectedRow = row;
        selectedBidCommodity = commodity;
        bid = candidate;
        break;
      }
    }
    if (bid == 0) {
      Await(kObserveGameStateChanged | kObserveAnimationRemoved | kObservePaintCompleted,
            "\"Board of Trade has no inactive actionable bid control yet\"");
      return;
    }
    initialBidBitmap = bid->glyphBase84;
    phase = kVerifyBid;
    EnterScenarioStep("verifying_trade_bid", "activate_first_trade_bid");
    if (RuntimeUiDriver::RequireControl(
            bid, RuntimeControlSelector(bid->controlTag, RUNTIME_CLASS(TTradeOrderPicture)), 0) ==
        0) {
      FailScenario("\"Board of Trade bid control is not ready for semantic activation\"");
      return;
    }
    bid->ActivateOrderSemantically();
    ContinueAfterAction();
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
    ContinueAfterAction();
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
      if (commodity != selectedBidCommodity && candidate != 0 && candidate->IsActionable() != 0 &&
          (candidate->glyphBase84 == 0x842 || candidate->glyphBase84 == 0x850) &&
          activeNation != 0 && QueryNationMetricBySlot(activeNation, row->tradeMetricSlot) > 1) {
        selectedSellRow = row;
        selectedSellCommodity = commodity;
        offer = candidate;
        break;
      }
    }
    if (offer == 0) {
      Await(kObserveGameStateChanged | kObserveAnimationRemoved | kObservePaintCompleted,
            "\"Board of Trade has no inactive actionable offer control yet\"");
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
    activeNation->merchantCapacity = static_cast<short>(testCapacity);
    capacity->SetControlValue(testCapacity, 1);
    TAmtBar* sellBar = static_cast<TAmtBar*>(selectedSellRow->ResolveControlByTag(kControlTagBar));
    if (sellBar == 0) {
      FailScenario("\"Board of Trade offer is missing its amount bar\"");
      return;
    }
    sellBar->auxValueA = static_cast<short>(testCapacity);

    phase = kVerifyOffer;
    EnterScenarioStep("verifying_trade_offer", "activate_trade_offer");
    if (RuntimeUiDriver::RequireControl(
            offer, RuntimeControlSelector(offer->controlTag, RUNTIME_CLASS(TTradeOrderPicture)),
            0) == 0) {
      FailScenario("\"Board of Trade offer control is not ready for semantic activation\"");
      return;
    }
    offer->ActivateOrderSemantically();
    ContinueAfterAction();
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
    EnterScenarioStep("decreasing_trade_sell_amount", "decrease_trade_sell_amount");
    if (RuntimeUiDriver::RequireControl(
            left, RuntimeControlSelector(left->controlTag, RUNTIME_CLASS(TSidewaysArrow)), 0) ==
        0) {
      FailScenario("\"trade sell decrease control is not ready\"");
      return;
    }
    selectedSellRow->HandleEvent(0x65, left, 0);
    ContinueAfterAction();
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
    EnterScenarioStep("increasing_trade_sell_amount", "increase_trade_sell_amount");
    if (RuntimeUiDriver::RequireControl(
            right, RuntimeControlSelector(right->controlTag, RUNTIME_CLASS(TSidewaysArrow)), 0) ==
        0) {
      FailScenario("\"trade sell increase control is not ready\"");
      return;
    }
    selectedSellRow->HandleEvent(100, right, 0);
    ContinueAfterAction();
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
    ContinueAfterAction();
  }

  void ReturnToMap() {
    TView* mainView = CurrentMainView();
    if (mainView == 0 || mainView->IsKindOf(RUNTIME_CLASS(TTradeScreenPicture)) == 0) {
      FailScenario("\"Board of Trade disappeared before back navigation\"");
      return;
    }
    phase = kWaitForMap;
    EnterScenarioStep("waiting_for_map_after_trade", "activate_trade_end_control");
    if (!RuntimeUiDriver::Activate(
            mainView, RuntimeControlSelector(kControlTagEnd, RUNTIME_CLASS(TControl)))) {
      FailScenario("\"Board of Trade back control is missing or cannot receive native input\"");
      return;
    }
    ContinueAfterAction();
  }

  void WaitForMap() {
    TView* mainView = CurrentMainView();
    if (offerAcceptanceCompleted && g_pViewMgr->currentTurnEventCode == kTurnEventDealBook) {
      if (mainView == 0 || mainView->IsKindOf(RUNTIME_CLASS(TDealBookPicture)) == 0) {
        FailScenario("\"trade completion did not construct the Deal Book\"");
        return;
      }
      TDealBookPicture* dealBook = static_cast<TDealBookPicture*>(mainView);
      if (dealBook->cachedSellPageView != dealBook->soldTradesView ||
          dealBook->cachedBuyPageView != dealBook->boughtTradesView ||
          dealBook->cachedSellPageView->ownerLocalX != 0x41 ||
          dealBook->cachedBuyPageView->ownerLocalX != 0x13a) {
        FailScenario("\"Deal Book opened with bought and sold history pages conflated\"");
        return;
      }
      TDealTabControl* tabs =
          static_cast<TDealTabControl*>(dealBook->ResolveControlByTag(kControlTagTabs));
      bool categoryClicked = tabs != 0 && tabs->ActivateRow(0);
      if (!categoryClicked || !dealBook->alternatePageMode ||
          dealBook->cachedSellPageView != dealBook->sellPageView ||
          dealBook->cachedBuyPageView != dealBook->buyPageView ||
          dealBook->cachedSellPageView->ownerLocalX != 0x41 ||
          dealBook->cachedBuyPageView->ownerLocalX != 0x13a || dealBook->glyphBase84 != 0x2263) {
        char failure[220];
        wsprintfA(failure,
                  "\"Deal Book category pages were wrong: click %d mode %d sellcache %d "
                  "buycache %d sellx %d buyx %d bitmap %d\"",
                  categoryClicked, dealBook->alternatePageMode,
                  dealBook->cachedSellPageView == dealBook->sellPageView,
                  dealBook->cachedBuyPageView == dealBook->buyPageView,
                  dealBook->cachedSellPageView->ownerLocalX,
                  dealBook->cachedBuyPageView->ownerLocalX, dealBook->glyphBase84);
        FailScenario(failure);
        return;
      }
      if (!RuntimeUiDriver::Activate(
              dealBook, RuntimeControlSelector(kControlTagMark, RUNTIME_CLASS(TControl))) ||
          dealBook->alternatePageMode || dealBook->cachedSellPageView != dealBook->soldTradesView ||
          dealBook->cachedBuyPageView != dealBook->boughtTradesView ||
          dealBook->cachedSellPageView->ownerLocalX != 0x41 ||
          dealBook->cachedBuyPageView->ownerLocalX != 0x13a || dealBook->glyphBase84 != 0x2260) {
        FailScenario(
            "\"Deal Book history control did not restore distinct bought and sold pages\"");
        return;
      }
      g_pSimMgr->StartNextPhase();
      ContinueAfterAction();
      return;
    }
    if (offerAcceptanceCompleted && AdvanceNewspaperIfNeeded()) {
      return;
    }
    if (g_pViewMgr->currentTurnEventCode != kTurnEventStrategicMap || mainView == 0 ||
        mainView->IsKindOf(RUNTIME_CLASS(TMapUberPicture)) == 0) {
      AwaitUiChange("\"Board of Trade back control did not restore the strategic map\"");
      return;
    }
    if (!g_ModalViewStack.IsEmpty()) {
      RecordUnexpectedModalView(g_ModalViewStack.GetHead());
      FailScenario("\"Board of Trade back navigation left an unexpected modal\"");
      return;
    }
    if (!verifiedPostedTradeDirections) {
      TGreatPower* activeNation = g_apNationStates[g_pSimMgr->GetActiveNationId()];
      if (activeNation == 0 || selectedBidCommodity != kResourceIron ||
          activeNation->GetTradeOffersFor(selectedBidCommodity) != -1 ||
          selectedSellCommodity < 0 ||
          activeNation->GetTradeOffersFor(selectedSellCommodity) <= 0) {
        FailScenario("\"Board of Trade conflated the posted buy and sell directions\"");
        return;
      }
      verifiedPostedTradeDirections = true;
    }
    if (offerAcceptanceCompleted) {
      if (g_pSimMgr->economicTurn != baselineEconomicTurn + 1) {
        FailScenario("\"accepting the final trade offer did not advance exactly one turn\"");
        return;
      }
      Pass();
      return;
    }
    if (!offerRegressionCompleted) {
      short activeNation = g_pSimMgr->GetActiveNationId();
      g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventOfferSheet), activeNation);
      TView* mainView = CurrentMainView();
      if (mainView == 0 || mainView->IsKindOf(RUNTIME_CLASS(TOfferDeskPicture)) == 0) {
        FailScenario("\"offer-sheet event did not construct TOfferDeskPicture\"");
        return;
      }
      phase = kWaitForOfferRegression;
      EnterScenarioStep("verifying_offer_sheet_bookmark", "construct_offer_sheet_for_bookmark");
      ContinueAfterAction();
      return;
    }
    if (!offerAcceptanceCompleted) {
      short activeNation = g_pSimMgr->GetActiveNationId();
      baselineEconomicTurn = g_pSimMgr->economicTurn;
      ResetNewspaperAdvance();
      g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventOfferSheet), activeNation);
      TView* offerView = CurrentMainView();
      if (offerView == 0 || offerView->IsKindOf(RUNTIME_CLASS(TOfferDeskPicture)) == 0) {
        FailScenario("\"offer-sheet event did not construct the final acceptance control\"");
        return;
      }
      phase = kWaitForOfferAcceptance;
      EnterScenarioStep("accepting_final_trade_offer", "construct_final_trade_offer");
      ContinueAfterAction();
      return;
    }
    baselineEconomicTurn = g_pSimMgr->economicTurn;
    handledOffers = 0;
    leftDealBook = false;
    ResetNewspaperAdvance();
    StrategicMapDriver map(mainView);
    if (!map.EndTurn()) {
      FailScenario("\"end-turn control is missing after war and trade orders\"");
      return;
    }
    phase = kWaitForEndTurn;
    EnterScenarioStep("handling_diplomatic_offers_after_trade",
                      "end_turn_after_war_sell_and_bid_orders");
    ContinueAfterAction();
  }

  void WaitForOfferAcceptance() {
    TView* mainView = CurrentMainView();
    if (g_pViewMgr->currentTurnEventCode != kTurnEventOfferSheet || mainView == 0 ||
        mainView->IsKindOf(RUNTIME_CLASS(TOfferDeskPicture)) == 0) {
      AwaitUiChange("\"final deterministic trade offer is not active\"");
      return;
    }
    if (!offerAcceptancePosed) {
      short activeNation = g_pSimMgr->GetActiveNationId();
      g_pViewMgr->DispatchNationActionToMainControl(activeNation, activeNation, 3, 17,
                                                    kResourceFood);
      offerAcceptancePosed = true;
      EnterScenarioStep("presenting_final_trade_offer", "pose_final_trade_offer");
      ContinueAfterAction();
      return;
    }
    if (!RuntimeUiDriver::Activate(
            mainView, RuntimeControlSelector(kControlTagAcce, RUNTIME_CLASS(TControl)))) {
      FailScenario("\"final deterministic trade offer could not be accepted semantically\"");
      return;
    }
    offerAcceptanceCompleted = true;
    phase = kWaitForMap;
    EnterScenarioStep("returning_to_map_after_offer_accept", "accept_final_trade_offer");
    ContinueAfterAction();
  }

  void WaitForOfferRegression() {
    TView* mainView = CurrentMainView();
    if (g_pViewMgr->currentTurnEventCode != kTurnEventOfferSheet || mainView == 0 ||
        mainView->IsKindOf(RUNTIME_CLASS(TOfferDeskPicture)) == 0) {
      AwaitUiChange("\"deterministic offer sheet is not active\"");
      return;
    }
    if (!offerRegressionPosed) {
      short activeNation = g_pSimMgr->GetActiveNationId();
      g_pViewMgr->DispatchNationActionToMainControl(activeNation, activeNation, 3, 17,
                                                    kResourceFood);
      offerRegressionPosed = true;
      EnterScenarioStep("presenting_offer_sheet_regression", "pose_retail_offer_sheet_action");
      ContinueAfterAction();
      return;
    }
    TDropShadowText* season =
        static_cast<TDropShadowText*>(mainView->ResolveControlByTag(kControlTagSeas));
    TStaticText* offerText = static_cast<TStaticText*>(
        mainView->ResolveControlByTag(IMPERIALISM_FOURCC('o', 'f', 'f', 'e')));
    TNumberText* purchaseControl =
        static_cast<TNumberText*>(mainView->ResolveControlByTag(kControlTagPurc));
    TView* tabs = mainView->ResolveControlByTag(kControlTagTabs);
    CString displayedOffer;
    CString sellerName = g_pSimMgr->LoadNormalizedCredentialName(g_pSimMgr->GetActiveNationId());
    if (offerText != 0) {
      offerText->CopyTextTo(&displayedOffer);
    }
    if (offerText == 0 || displayedOffer.GetLength() == 0 ||
        strstr(static_cast<LPCSTR>(displayedOffer), static_cast<LPCSTR>(sellerName)) == 0 ||
        season == 0 || season->textStyle78.textColor != PALETTEINDEX(0)) {
      FailScenario("\"offer sheet did not present its retail seller text and white season label\"");
      return;
    }
    if (purchaseControl == 0 || purchaseControl->value != 3 || purchaseControl->maximumValue != 3) {
      FailScenario("\"offer sheet did not default the purchase field to the offered amount\"");
      return;
    }
    if (tabs == 0 || tabs->IsKindOf(RUNTIME_CLASS(TDealTabControl)) == 0) {
      FailScenario("\"offer-sheet bookmark control could not receive native input\"");
      return;
    }
    TDealTabControl* tabControl = static_cast<TDealTabControl*>(tabs);
    if (tabControl->tabCount <= 0 || tabControl->tabCount > 17) {
      FailScenario("\"offer-sheet bookmark control has an invalid retail tab count\"");
      return;
    }
    if (offerBookmarkRow < tabControl->tabCount) {
      const short row = offerBookmarkRow;
      if (!tabControl->ActivateRow(row) || tabControl->selectedRow != row) {
        FailScenario("\"offer-sheet bookmark could not be selected through native input\"");
        return;
      }
      ++offerBookmarkRow;
      EnterScenarioStep("verifying_offer_sheet_bookmarks", "click_offer_sheet_bookmark");
      ContinueAfterAction();
      return;
    }
    offerRegressionCompleted = true;
    g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventStrategicMap),
                                  g_pSimMgr->GetActiveNationId());
    phase = kWaitForMap;
    EnterScenarioStep("returning_to_map_after_offer_bookmark", "click_offer_sheet_bookmark");
    ContinueAfterAction();
  }

  void WaitForEndTurn() {
    if (g_pViewMgr->currentTurnEventCode == kTurnEventOfferSheet) {
      TView* mainView = CurrentMainView();
      if (mainView == 0 || mainView->IsKindOf(RUNTIME_CLASS(TOfferDeskPicture)) == 0) {
        AwaitUiChange("\"offer-sheet event did not construct TOfferDeskPicture\"");
        return;
      }
      if (!verifiedOfferPresentation) {
        TStaticText* offerText = static_cast<TStaticText*>(
            mainView->ResolveControlByTag(IMPERIALISM_FOURCC('o', 'f', 'f', 'e')));
        TDropShadowText* season =
            static_cast<TDropShadowText*>(mainView->ResolveControlByTag(kControlTagSeas));
        CString displayedOffer;
        if (offerText == 0 || season == 0) {
          Await(kObserveUiTreeBuilt | kObservePaintCompleted | kObserveGameStateChanged,
                "\"offer sheet is missing its offer or season text control yet\"");
          return;
        }
        offerText->CopyTextTo(&displayedOffer);
        if (displayedOffer.GetLength() == 0 || season->textStyle78.textColor == 0) {
          Await(kObservePaintCompleted | kObserveGameStateChanged,
                "\"offer sheet has not presented offer text with a visible season label yet\"");
          return;
        }
        verifiedOfferPresentation = true;
      }
      if (!exercisedOfferBookmark) {
        TView* tabs = mainView->ResolveControlByTag(kControlTagTabs);
        if (tabs == 0 || tabs->IsKindOf(RUNTIME_CLASS(TDealTabControl)) == 0 ||
            !static_cast<TDealTabControl*>(tabs)->ActivateRow(0)) {
          FailScenario("\"offer-sheet bookmark control could not receive native input\"");
          return;
        }
        exercisedOfferBookmark = true;
        EnterScenarioStep("switching_offer_sheet_bookmark", "click_offer_sheet_bookmark");
        ContinueAfterAction();
        return;
      }
      TView* reject = mainView->ResolveControlByTag(kControlTagReje);
      if (reject != 0) {
        if (!RuntimeUiDriver::Activate(
                reject, RuntimeControlSelector(reject->controlTag, RUNTIME_CLASS(TControl)))) {
          Await(kObserveGameStateChanged | kObservePaintCompleted,
                "\"diplomatic-offer Reject control is not ready yet\"");
          return;
        }
        ++handledOffers;
        EnterScenarioStep("advancing_after_diplomatic_offer", "reject_end_turn_diplomatic_offer");
      }
      ContinueAfterAction();
      return;
    }
    if (g_pViewMgr->currentTurnEventCode == kTurnEventDealBook && !leftDealBook) {
      TGreatPower* activeNation = g_apNationStates[g_pSimMgr->GetActiveNationId()];
      short bidEntryCount = activeNation->GetTrackedSlotEntryCountLow(selectedBidCommodity);
      short sellEntryCount = activeNation->GetTrackedSlotEntryCountLow(selectedSellCommodity);
      bool bidDirectionValid = bidEntryCount > 0;
      bool sellDirectionValid = sellEntryCount > 0;
      short kind;
      short value;
      short targetNation;
      int payload;
      for (short ordinal = 1; ordinal <= bidEntryCount; ++ordinal) {
        activeNation->ReadTrackedSlotEntryFields(selectedBidCommodity, ordinal, &kind, &value,
                                                 &targetNation, &payload);
        if (kind != kTrackedSlotOfferEntry) {
          bidDirectionValid = false;
        }
      }
      for (short sellOrdinal = 1; sellOrdinal <= sellEntryCount; ++sellOrdinal) {
        activeNation->ReadTrackedSlotEntryFields(selectedSellCommodity, sellOrdinal, &kind, &value,
                                                 &targetNation, &payload);
        if (kind != kTrackedSlotAcceptEntry) {
          sellDirectionValid = false;
        }
      }
      if (!bidDirectionValid || !sellDirectionValid) {
        char failure[180];
        wsprintfA(failure,
                  "\"trade result directions were conflated: buy slot %d count %d valid %d, sell "
                  "slot %d count %d valid %d\"",
                  selectedBidCommodity, bidEntryCount, bidDirectionValid, selectedSellCommodity,
                  sellEntryCount, sellDirectionValid);
        FailScenario(failure);
        return;
      }
      leftDealBook = true;
      g_pSimMgr->StartNextPhase();
      ContinueAfterAction();
      return;
    }
    if (AdvanceNewspaperIfNeeded()) {
      return;
    }
    TView* mainView = CurrentMainView();
    if (g_pViewMgr->currentTurnEventCode != kTurnEventStrategicMap || mainView == 0 ||
        mainView->IsKindOf(RUNTIME_CLASS(TMapUberPicture)) == 0 || !g_ModalViewStack.IsEmpty() ||
        g_pSimMgr->economicTurn == baselineEconomicTurn) {
      AwaitUiChange("\"war and trade end turn did not return to the strategic map\"");
      return;
    }
    if (g_pSimMgr->economicTurn != baselineEconomicTurn + 1) {
      FailScenario("\"war and trade end turn advanced by more than one\"");
      return;
    }
    Pass();
  }

  Phase phase;
  short warTargetNation;
  short warPolicyBeforeAction;
  TTradeCluster* selectedRow;
  TTradeCluster* selectedSellRow;
  short selectedBidCommodity;
  short selectedSellCommodity;
  short initialBidBitmap;
  int initialSellValue;
  short initialBarValue;
  short baselineEconomicTurn;
  int handledOffers;
  bool leftDealBook;
  bool verifiedOfferPresentation;
  bool exercisedOfferBookmark;
  bool offerRegressionPosed;
  short offerBookmarkRow;
  bool offerRegressionCompleted;
  bool offerAcceptancePosed;
  bool offerAcceptanceCompleted;
  bool verifiedPostedTradeDirections;
};

TradeScreenTestCase g_test;

} // namespace

RuntimeTestCase* TradeScreenTest() {
  return &g_test;
}
