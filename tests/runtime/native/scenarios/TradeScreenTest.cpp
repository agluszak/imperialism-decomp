#include "RuntimeScenario.h"
#include "flows/RandomGameFlow.h"
#include "RuntimeUiDriver.h"
#include "screens/StrategicMapDriver.h"

#include "game/app/TAnimation.h"
#include "game/app/TAnimator.h"
#include "game/diplomacy_domain_types.h"
#include "game/diplomacy_ui/TDiplomacyMapView.h"
#include "game/TList.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_core_globals.h"
#include "game/globals/ui_widgets_globals.h"
#include "game/map/TMapUberPicture.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/nation/TGreatPower.h"
#include "game/resource_manifest_tags.h"
#include "game/trade_ui/TOfferDeskPicture.h"
#include "game/turn_event_codes.h"
#include "game/ui_core/TNumberText.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_diplomacy.h"
#include "game/ui_widgets/TAmtBar.h"
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
        selectedRow(0), selectedSellRow(0), initialBidBitmap(0), initialSellValue(0),
        initialBarValue(0), baselineEconomicTurn(0), handledOffers(0), leftDealBook(false) {}
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
    RequestScenarioTick();
  }

  void TickScenario() override {
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
    if (ScenarioPhaseTicks() < 60) {
      RequestScenarioTick();
      return;
    }
    TView* mainView = CurrentMainView();
    if (g_pUiRuntimeContext->currentTurnEventCode != kTurnEventStrategicMap || mainView == 0 ||
        mainView->IsKindOf(RUNTIME_CLASS(TMapUberPicture)) == 0 || !g_ModalViewStack.IsEmpty()) {
      WaitForScenarioTick("\"combined map was not idle before declaring war\"");
      return;
    }
    phase = kWaitForDiplomacyScreen;
    EnterScenarioStep("waiting_for_diplomacy_before_trade", "activate_diplomacy_toolbar_control");
    StrategicMapDriver map(mainView);
    if (!map.ActivateDiplomacySemantically()) {
      FailScenario("\"diplomacy toolbar control is missing or disabled\"");
      return;
    }
    RequestScenarioTick();
  }

  void WaitForDiplomacyScreen() {
    TDiplomacyMapView* diplomacy = DiplomacyView();
    if (g_pUiRuntimeContext->currentTurnEventCode != kTurnEventDiplomacyMap || diplomacy == 0) {
      WaitForScenarioTick("\"diplomacy toolbar action did not activate diplomacy orders\"");
      return;
    }
    phase = kActivateTreatiesTopic;
    EnterScenarioStep("activating_treaties_before_trade", "click_treaties_action_topic");
    RequestScenarioTick();
  }

  void ActivateTreatiesTopic() {
    TDiplomacyMapView* diplomacy = DiplomacyView();
    if (diplomacy == 0 ||
        !RuntimeUiDriver::ClickControlThroughNativeMessages(diplomacy, kControlTagTrtt)) {
      FailScenario("\"diplomacy treaties action control is missing or cannot receive input\"");
      return;
    }
    phase = kSelectWarAction;
    EnterScenarioStep("selecting_war_before_trade", "click_declare_war_action");
    RequestScenarioTick();
  }

  void SelectWarAction() {
    TDiplomacyMapView* diplomacy = DiplomacyView();
    if (diplomacy == 0 || diplomacy->RuntimeActionTopicIndex() != 1) {
      WaitForScenarioTick("\"diplomacy treaties action did not become active\"");
      return;
    }
    if (!RuntimeUiDriver::ClickControlThroughNativeMessages(diplomacy, kControlTagScr0 + 4)) {
      FailScenario("\"declare-war action is missing or cannot receive input\"");
      return;
    }
    phase = kDeclareWar;
    EnterScenarioStep("declaring_war_before_trade", "click_valid_war_target_nation");
    RequestScenarioTick();
  }

  void DeclareWar() {
    TDiplomacyMapView* diplomacy = DiplomacyView();
    if (diplomacy == 0 || diplomacy->actionCodeBC != kDipActionDeclareWar) {
      WaitForScenarioTick("\"declare-war action did not become active\"");
      return;
    }
    const short activeNation = g_pSimMgr->GetActiveNationId();
    CPoint point;
    for (short nation = 0; nation < 7; ++nation) {
      if (nation != activeNation && g_apTerrainTypeDescriptorTable[nation] != 0 &&
          diplomacy->RuntimeGetNationSelectionPoint(nation, &point) &&
          g_pDiplomacyTurnStateManager->ValidateDiplomacyActionTypeAgainstTargetAndSetRejectCode(
              activeNation, nation, kDipActionDeclareWar)) {
        warTargetNation = nation;
        break;
      }
    }
    TGreatPower* sourceNation = g_apNationStates[activeNation];
    if (warTargetNation < 0 || sourceNation == 0 ||
        !diplomacy->RuntimeGetNationSelectionPoint(warTargetNation, &point)) {
      FailScenario("\"diplomacy map has no valid major-nation war target\"");
      return;
    }
    warPolicyBeforeAction = sourceNation->diplomacyPolicyByNation[warTargetNation];
    if (!RuntimeUiDriver::ClickViewPointThroughNativeMessages(diplomacy, point.x, point.y)) {
      FailScenario("\"declare-war target could not receive native input\"");
      return;
    }
    phase = kVerifyWarOrder;
    EnterScenarioStep("verifying_war_before_trade", "verify_declare_war_policy");
    RequestScenarioTick();
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
    RequestScenarioTick();
  }

  void ReturnFromDiplomacy() {
    TDiplomacyMapView* diplomacy = DiplomacyView();
    if (diplomacy == 0 ||
        !RuntimeUiDriver::ClickControlThroughNativeMessages(diplomacy, kControlTagEnd)) {
      FailScenario("\"diplomacy back control is missing or cannot receive native input\"");
      return;
    }
    phase = kWaitForMapBeforeTrade;
    EnterScenarioStep("waiting_for_map_before_trade", "activate_diplomacy_end_control");
    RequestScenarioTick();
  }

  void WaitForMapBeforeTrade() {
    TView* mainView = CurrentMainView();
    if (g_pUiRuntimeContext->currentTurnEventCode != kTurnEventStrategicMap || mainView == 0 ||
        mainView->IsKindOf(RUNTIME_CLASS(TMapUberPicture)) == 0 || !g_ModalViewStack.IsEmpty()) {
      WaitForScenarioTick("\"diplomacy back control did not restore the strategic map\"");
      return;
    }
    phase = kActivateTradeScreen;
    EnterScenarioStep("activating_trade_screen", "declared_war_and_returned_to_map");
    RequestScenarioTick();
  }

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
    activeNation->merchantCapacity = static_cast<short>(testCapacity);
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
      RecordUnexpectedModalView(g_ModalViewStack.GetHead());
      FailScenario("\"Board of Trade back navigation left an unexpected modal\"");
      return;
    }
    baselineEconomicTurn = g_pSimMgr->economicTurn;
    handledOffers = 0;
    leftDealBook = false;
    ResetNewspaperAdvance();
    StrategicMapDriver map(mainView);
    if (!map.EndTurnThroughNativeMessages()) {
      FailScenario("\"end-turn control is missing after war and trade orders\"");
      return;
    }
    phase = kWaitForEndTurn;
    EnterScenarioStep("handling_diplomatic_offers_after_trade",
                      "end_turn_after_war_sell_and_bid_orders");
    RequestScenarioTick();
  }

  void WaitForEndTurn() {
    if (g_pUiRuntimeContext->currentTurnEventCode == kTurnEventOfferSheet) {
      TView* mainView = CurrentMainView();
      if (mainView == 0 || mainView->IsKindOf(RUNTIME_CLASS(TOfferDeskPicture)) == 0) {
        WaitForScenarioTick("\"offer-sheet event did not construct TOfferDeskPicture\"");
        return;
      }
      TView* reject = mainView->ResolveControlByTag(kControlTagReje);
      if (reject != 0 && reject->IsActionable() != 0) {
        if (!RuntimeUiDriver::ClickViewThroughNativeMessages(reject)) {
          FailScenario("\"diplomatic-offer Reject control could not receive native input\"");
          return;
        }
        ++handledOffers;
        EnterScenarioStep("advancing_after_diplomatic_offer", "reject_end_turn_diplomatic_offer");
      }
      RequestScenarioTick();
      return;
    }
    if (g_pUiRuntimeContext->currentTurnEventCode == kTurnEventDealBook && !leftDealBook) {
      leftDealBook = true;
      g_pSimMgr->StartNextPhase();
      RequestScenarioTick();
      return;
    }
    if (AdvanceNewspaperIfNeeded()) {
      return;
    }
    TView* mainView = CurrentMainView();
    if (g_pUiRuntimeContext->currentTurnEventCode != kTurnEventStrategicMap || mainView == 0 ||
        mainView->IsKindOf(RUNTIME_CLASS(TMapUberPicture)) == 0 || !g_ModalViewStack.IsEmpty() ||
        g_pSimMgr->economicTurn == baselineEconomicTurn) {
      WaitForScenarioTick("\"war and trade end turn did not return to the strategic map\"");
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
  short initialBidBitmap;
  int initialSellValue;
  short initialBarValue;
  short baselineEconomicTurn;
  int handledOffers;
  bool leftDealBook;
};

TradeScreenTestCase g_test;

} // namespace

RuntimeTestCase* TradeScreenTest() {
  return &g_test;
}
