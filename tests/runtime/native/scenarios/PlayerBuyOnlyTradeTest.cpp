#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"
#include "flows/EndTurnFlow.h"
#include "screens/StrategicMapScreen.h"
#include "screens/TradeScreen.h"

#include "game/core/global_data_tables.h"
#include "game/globals/shared_globals.h"
#include "game/map/TMapUberPicture.h"
#include "game/nation/TGreatPower.h"
#include "game/resource_domain_types.h"
#include "game/turn_event_codes.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_widgets/TTradeScreenPicture.h"

namespace {

// Switching a commodity from sell to buy must not execute a sale in the same turn.
//
// The player starts with a seeded iron sell order, opens the Board of Trade, selects the iron
// *buy* card instead, returns to the map and ends the turn. Afterwards the iron order must be a
// posted request (-1), no other commodity may have acquired a sell order, and the player's
// trade history must contain no sale.
class PlayerBuyOnlyTradeTestCase : public EasyMapScriptScenario {
public:
  PlayerBuyOnlyTradeTestCase() : activeNationSlot(-1) {
    for (short resource = 0; resource < kResourceKindCount; ++resource) {
      baselinePurchaseAmounts[resource] = 0;
    }
  }

  bool RecordsGameFlow() const override {
    return true;
  }

protected:
  void Script() override {
    RT_BEGIN();

    activeNationSlot = g_pSimMgr->GetActiveNationId();
    RT_REQUIRE_NOT_NULL(Player());
    RT_REQUIRE_NE(0, static_cast<int>(Player()->diplomacyEligibilityA0));

    // Seed the sell order the scenario is about, and snapshot the bid state the game compares
    // against when the turn is processed.
    Player()->SetItemPotentials(kResourceIron, 1);
    Player()->RememberTradeBids();

    RT_OPEN_SCREEN("open the Board of Trade", StrategicMap().OpenTrade(), TTradeScreenPicture,
                   kTurnEventTradeOverview);

    // The seeded order has to survive entering the screen, and nothing else may have appeared.
    RT_REQUIRE(SeededIronOrderIsIntact());

    // An iron bid may already be selected, in which case there is nothing to click.
    if (!Trade().BidSelected(kResourceIron)) {
      RT_REQUIRE(Trade().BuyCardIsActionable(kResourceIron));
      // Any other bitmap means the card is in a state this scenario does not understand, which
      // is worth failing on rather than clicking blindly.
      RT_REQUIRE(Trade().BuyCardIsInactive(kResourceIron));
      RT_ACTIVATE_AND_AWAIT("select the iron bid", Trade().SelectBid(kResourceIron),
                            Trade().BidSelected(kResourceIron), kObserveGameStateChanged);
    }

    RT_CLOSE_TO_MAP("leave the Board of Trade", Trade().Close());

    // -1 is a posted request; anything above 0 would be a sell order the player never made.
    RT_REQUIRE_EQ(-1, Player()->GetTradeOffersFor(kResourceIron));
    RT_REQUIRE(NoOtherCommodityHasASellOrder());
    CapturePurchaseBaseline();

    RT_RUN(endTurn.RejectOffers().ExpectExactlyOneTurn().ToNextStrategicMap(*this));

    RT_REQUIRE(PlayerExecutedNoSales());
    RT_REQUIRE(IronHistoryContainsOnlyPurchases());
    RT_PASS();

    RT_END();
  }

private:
  TGreatPower* Player() const {
    return activeNationSlot >= 0 ? g_apNationStates[activeNationSlot] : 0;
  }

  bool SeededIronOrderIsIntact() const {
    TGreatPower* player = Player();
    if (player == 0) {
      return false;
    }
    for (short resource = 0; resource < kResourceKindCount; ++resource) {
      short expected = resource == kResourceIron ? 1 : 0;
      if (player->GetTradeOffersFor(resource) != expected) {
        return false;
      }
    }
    return true;
  }

  bool NoOtherCommodityHasASellOrder() const {
    TGreatPower* player = Player();
    if (player == 0) {
      return false;
    }
    for (short resource = 0; resource < kResourceKindCount; ++resource) {
      if (resource != kResourceIron && player->GetTradeOffersFor(resource) > 0) {
        return false;
      }
    }
    return true;
  }

  void CapturePurchaseBaseline() {
    TGreatPower* player = Player();
    for (short resource = 0; resource < kResourceKindCount; ++resource) {
      baselinePurchaseAmounts[resource] =
          player != 0 ? player->purchasedItemsByResource[resource] : 0;
    }
  }

  // A sale would reduce a purchase count below the baseline.
  bool PlayerExecutedNoSales() const {
    TGreatPower* player = Player();
    if (player == 0) {
      return false;
    }
    for (short resource = 0; resource < kResourceKindCount; ++resource) {
      if (player->purchasedItemsByResource[resource] < baselinePurchaseAmounts[resource]) {
        return false;
      }
    }
    return true;
  }

  bool IronHistoryContainsOnlyPurchases() const {
    TGreatPower* player = Player();
    if (player == 0) {
      return false;
    }
    short entryCount = player->GetTrackedSlotEntryCountLow(kResourceIron);
    for (short ordinal = 1; ordinal <= entryCount; ++ordinal) {
      short kind = 0;
      short value = 0;
      short targetNation = 0;
      int payload = 0;
      player->ReadTrackedSlotEntryFields(kResourceIron, ordinal, &kind, &value, &targetNation,
                                         &payload);
      if (kind != kTrackedSlotOfferEntry) {
        return false;
      }
    }
    return true;
  }

  EndTurnFlow endTurn;
  short activeNationSlot;
  short baselinePurchaseAmounts[kResourceKindCount];
};

} // namespace

RUNTIME_TEST_FACTORY(PlayerBuyOnlyTradeTestCase, PlayerBuyOnlyTradeTest)
