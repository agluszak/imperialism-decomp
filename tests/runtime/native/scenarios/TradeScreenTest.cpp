#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"
#include "screens/DealBookScreen.h"
#include "screens/DiplomacyScreen.h"
#include "screens/ModalScreen.h"
#include "screens/NewspaperScreen.h"
#include "screens/OfferScreen.h"
#include "screens/StrategicMapScreen.h"
#include "screens/TradeScreen.h"
#include "screens/UiAnimationRegistry.h"

#include "game/core/global_data_tables.h"
#include "game/diplomacy_domain_types.h"
#include "game/globals/military_ui_globals.h"
#include "game/globals/shared_globals.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/nation/TGreatPower.h"
#include "game/nation_domain_types.h"
#include "game/resource_domain_types.h"
#include "game/turn_event_codes.h"
#include "game/ui_screens/TSimMgr.h"

namespace {

// A tag no game animation uses, so finding it in the registry proves this scenario's own
// animation is what was found.
const int kMapAnimationRegressionTag = 0x74727374;

// The deterministic offer the scenario poses to itself: three units of food at seventeen.
const short kPosedOfferQuantity = 3;
const short kPosedOfferPrice = 17;

// The Board of Trade, from the map and back, with the two regressions that live on this path:
// opening it must discard the animations the map owned, and the buy and sell directions it
// posts must stay distinct all the way through to the Deal Book.
//
// The scenario declares war first because a war changes which offers the turn generates, and
// ends by posing an offer to itself and accepting it, which is what makes exactly one turn's
// worth of trade execute.
class TradeScreenTestCase : public EasyMapScriptScenario {
public:
  TradeScreenTestCase()
      : warTargetNation(-1), warPolicyBeforeAction(-1), sellCommodity(-1), initialSellQuantity(0),
        initialSellBar(0), baselineEconomicTurn(0), bookmarkRow(0) {}

  bool RecordsGameFlow() const override {
    return true;
  }
  bool RequiresScenarioUiSnapshot() const override {
    return true;
  }
  void ObserveScenarioUiTree(int eventCode, TView* root) override {
    if (eventCode == kTurnEventTradeOverview) {
      CaptureScenarioUiSnapshot(eventCode, root);
    }
  }

protected:
  void Script() override {
    RT_BEGIN();

    // --- Declare war, so the turn's trade happens against a live conflict. ---
    RT_OPEN_TO("open the diplomacy map", StrategicMap().OpenDiplomacy(), DiplomacyScreen);
    RT_ACTION("select the treaties topic", Diplomacy().ShowTreaties());
    RT_AWAIT(Diplomacy().TreatiesTopicIsSelected(), kObserveUiStateChanged);
    RT_ACTIVATE_AND_AWAIT("select the declare-war action", Diplomacy().SelectDeclareWarAction(),
                          Diplomacy().ActionCode() == kDipActionDeclareWar, kObserveUiStateChanged);

    warTargetNation = FirstValidWarTarget();
    RT_REQUIRE_NE(-1, warTargetNation);
    warPolicyBeforeAction = PolicyTowards(warTargetNation);
    RT_ACTION("declare war on that power", Diplomacy().SelectNation(warTargetNation));
    RT_REQUIRE_EQ(TogglePolicy(warPolicyBeforeAction, kDiplomacyProposalDeclareWar),
                  PolicyTowards(warTargetNation));
    RT_REQUIRE(!ModalScreen::AnyPresent());
    RT_CLOSE_TO_MAP("leave the diplomacy map", Diplomacy().Close());

    // --- Opening the Board of Trade must discard what the map was animating. ---
    RT_STEP("give the map an animation to own",
            StrategicMap().SeedOwnedAnimation(kMapAnimationRegressionTag));
    RT_REQUIRE(UiAnimationRegistry::Contains(kMapAnimationRegressionTag));

    RT_OPEN_TO("open the Board of Trade", StrategicMap().OpenTrade(), TradeScreen);
    RT_REQUIRE_EQ(0, UiAnimationRegistry::Count());
    RT_REQUIRE(Trade().HasCapacityAndCommodityControls());
    // Its price and availability cells are drawn per frame rather than baked into the
    // background, and their text is drawn transparently over it.
    RT_REQUIRE(Trade().RenderedDynamicCells());
    RT_REQUIRE(Trade().RenderedTransparentText());
    RT_HOLD_SCREEN("trade");

    // --- Post a bid for iron. ---
    RT_AWAIT(Trade().BuyCardIsActionable(kResourceIron) && Trade().BuyCardIsInactive(kResourceIron),
             kObserveGameStateChanged | kObserveAnimationRemoved | kObservePaintCompleted);
    RT_ACTION("select the iron bid", Trade().SelectBid(kResourceIron));
    RT_REQUIRE(Trade().BidSelected(kResourceIron));

    // --- Post a sell order for something else, and adjust its quantity. ---
    RT_AWAIT(Trade().FirstSellableCommodityOtherThan(kResourceIron) >= 0,
             kObserveGameStateChanged | kObserveAnimationRemoved | kObservePaintCompleted);
    sellCommodity = Trade().FirstSellableCommodityOtherThan(kResourceIron);
    RT_STEP("seed an adjustable merchant capacity", Trade().SeedAdjustableCapacity(sellCommodity));
    RT_ACTION("select that commodity's offer", Trade().SelectOffer(sellCommodity));

    RT_REQUIRE(Trade().SellRowIsAdjustable(sellCommodity));
    RT_REQUIRE(Trade().SellLabelHasOwnLayout(sellCommodity));
    initialSellQuantity = Trade().SellQuantity(sellCommodity);
    initialSellBar = Trade().SellBarValue(sellCommodity);
    RT_REQUIRE(initialSellQuantity > 1);

    RT_ACTION("decrease the sell quantity", Trade().DecreaseSell(sellCommodity));
    RT_REQUIRE_EQ(initialSellQuantity - 1, Trade().SellQuantity(sellCommodity));
    RT_REQUIRE(Trade().SellBarValue(sellCommodity) < initialSellBar);
    RT_REQUIRE(Trade().SellLabelHasOwnLayout(sellCommodity));

    RT_ACTION("increase the sell quantity again", Trade().IncreaseSell(sellCommodity));
    RT_REQUIRE_EQ(initialSellQuantity, Trade().SellQuantity(sellCommodity));
    RT_REQUIRE_EQ(initialSellBar, Trade().SellBarValue(sellCommodity));
    RT_REQUIRE(Trade().SellLabelHasOwnLayout(sellCommodity));

    RT_CLOSE_TO_MAP("leave the Board of Trade", Trade().Close());

    // A posted request reads -1 and a posted sale reads its quantity, so conflating the two
    // directions would show up here as the same sign on both commodities.
    RT_REQUIRE_EQ(-1, Player()->GetTradeOffersFor(kResourceIron));
    RT_REQUIRE(Player()->GetTradeOffersFor(sellCommodity) > 0);

    // --- The offer sheet's bookmarks. ---
    RT_ACTION("open the offer desk", OfferScreen::OpenForNation(ActiveNation()));
    RT_AWAIT(OfferScreen::IsCurrent(), kObserveUiStateChanged);
    RT_ACTION("pose a deterministic offer", PoseFoodOffer());
    RT_AWAIT(OfferScreen::IsCurrent(), kObserveUiStateChanged);
    RT_REQUIRE(OfferDesk().OfferTextNamesNation(ActiveNation()));
    RT_REQUIRE(OfferDesk().SeasonLabelIsWhite());
    RT_REQUIRE(OfferDesk().PurchaseDefaultsTo(kPosedOfferQuantity));
    RT_REQUIRE(OfferDesk().HasRetailBookmarkCount());

    while (bookmarkRow < OfferDesk().BookmarkCount()) {
      RT_ACTION("select an offer-sheet bookmark", OfferDesk().SelectBookmark(bookmarkRow));
      RT_REQUIRE_EQ(bookmarkRow, OfferDesk().SelectedBookmark());
      ++bookmarkRow;
    }

    RT_ACTION("return to the map", StrategicMap().ReopenByTurnEvent(ActiveNation()));
    RT_AWAIT(StrategicMapScreen::IsCurrent(), kObserveUiStateChanged);

    // --- Accept one deterministic offer, which executes the turn's trade. ---
    baselineEconomicTurn = EconomicTurn();
    RT_ACTION("open the offer desk again", OfferScreen::OpenForNation(ActiveNation()));
    RT_AWAIT(OfferScreen::IsCurrent(), kObserveUiStateChanged);
    RT_ACTION("pose the offer to accept", PoseFoodOffer());
    RT_AWAIT(OfferScreen::IsCurrent(), kObserveUiStateChanged);
    RT_ACTION("accept the offer", OfferDesk().Accept());

    // --- The Deal Book reports it, with the two directions still on their own pages. ---
    RT_AWAIT(DealBookScreen::IsCurrent(), kObserveUiStateChanged);
    RT_REQUIRE(DealBook().IsShowingHistoryPages());
    RT_ACTION("show the Deal Book's category pages", DealBook().ShowCategoryPages());
    RT_REQUIRE(DealBook().IsShowingCategoryPages());
    RT_ACTION("restore the Deal Book's history pages", DealBook().ShowHistoryPages());
    RT_REQUIRE(DealBook().IsShowingHistoryPages());
    RT_ACTION("leave the Deal Book", DealBook().Leave());

    while (!StrategicMapScreen::IsCurrent()) {
      if (NewspaperScreen::IsCurrent() && Newspaper().EndControlIsReady()) {
        RT_ACTION("close the newspaper", Newspaper().Close());
      } else {
        RT_AWAIT(StrategicMapScreen::IsCurrent() ||
                     (NewspaperScreen::IsCurrent() && Newspaper().EndControlIsReady()),
                 kObserveUiStateChanged);
      }
    }

    RT_REQUIRE_EQ(baselineEconomicTurn + 1, EconomicTurn());
    RT_PASS();

    RT_END();
  }

private:
  short ActiveNation() const {
    return g_pSimMgr->GetActiveNationId();
  }

  short EconomicTurn() const {
    return g_pSimMgr != 0 ? g_pSimMgr->economicTurn : -1;
  }

  TGreatPower* Player() const {
    return g_apNationStates[ActiveNation()];
  }

  short PolicyTowards(short nationSlot) const {
    TGreatPower* player = Player();
    return player != 0 && nationSlot >= 0 ? player->diplomacyPolicyByNation[nationSlot] : -2;
  }

  static short TogglePolicy(short previousPolicy, int proposal) {
    return previousPolicy == proposal ? -1 : static_cast<short>(proposal);
  }

  RuntimeActionResult PoseFoodOffer() {
    return OfferScreen::PoseOfferToSelf(ActiveNation(), kResourceFood, kPosedOfferQuantity,
                                        kPosedOfferPrice);
  }

  short FirstValidWarTarget() const {
    for (short nation = 0; nation < kMajorNationCount; ++nation) {
      if (nation != ActiveNation() && g_apTerrainTypeDescriptorTable[nation] != 0 &&
          g_pDiplomacyTurnStateManager->ValidateDiplomacyActionTypeAgainstTargetAndSetRejectCode(
              ActiveNation(), nation, kDipActionDeclareWar)) {
        return nation;
      }
    }
    return -1;
  }

  short warTargetNation;
  short warPolicyBeforeAction;
  short sellCommodity;
  int initialSellQuantity;
  short initialSellBar;
  short baselineEconomicTurn;
  short bookmarkRow;
};

} // namespace

RUNTIME_TEST_FACTORY(TradeScreenTestCase, TradeScreenTest)
