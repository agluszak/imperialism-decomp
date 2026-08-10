#include "JsonArray.h"
#include "JsonObject.h"
#include "RuntimeGameStateCapture.h"
#include "RuntimeRun.h"
#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"
#include "screens/OfferScreen.h"

#include "game/globals/shared_globals.h"
#include "game/globals/trade_ui_globals.h"
#include "game/trade_ui/TOfferDeskPicture.h"
#include "game/turn_event_codes.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_widgets/TTradeMgr.h"

#include "parson.h"

namespace {

// Observe reconstructed phase 7 from the retail-produced beginning-of-game save. The phase-6
// setup is executed first so before-state is the exact trade entry state reached by retail rules.
class FirstTurnTradePhaseTestCase : public LoadedMapScriptScenario {
protected:
  void Script() override {
    RT_BEGIN();

    RT_DO("advance the first-turn trade phase once", AdvanceTradePhaseOnce());
    RT_PASS();

    RT_END();
  }

private:
  RuntimeActionResult AdvanceTradePhaseOnce() {
    if (g_pSimMgr == 0 || g_pTradeMgr == 0 || g_pSimMgr->economicTurn != 1 ||
        g_pSimMgr->turnStateCode != 5) {
      return RuntimeActionResult::Failure("the loaded fixture is not at first-turn phase 5");
    }

    // Phase 5 has no first-turn alert work. Execute phase 6 to reach the same phase-7 trade
    // boundary that normal turn progression reaches after diplomacy application and replies.
    g_pSimMgr->turnStateCode = 6;
    g_pSimMgr->AdvanceGlobalTurnStateMachine();
    if (g_pSimMgr->turnStateCode != 7) {
      return RuntimeActionResult::Failure("the diplomacy phase did not advance to phase 7");
    }
    if (CurrentTurnEvent() != kTurnEventDiplomacyMap) {
      return RuntimeActionResult::Failure("the trade phase did not begin from the diplomacy map");
    }

    if (!CaptureGameState(RunState(), "before")) {
      return RuntimeActionResult::Failure("the before game-state capture is unavailable");
    }
    RunState().SetCapture("case", json_value_init_null());
    if (!RunState().HasCapture("case")) {
      return RuntimeActionResult::Failure("the void case capture is unavailable");
    }

    g_pSimMgr->AdvanceGlobalTurnStateMachine();
    if (g_pSimMgr->turnStateCode != 9) {
      return RuntimeActionResult::Failure("the trade phase did not advance to phase 9");
    }
    if (CurrentTurnEvent() != kTurnEventOfferSheet) {
      return RuntimeActionResult::Failure("the trade phase did not dispatch its offer-sheet event");
    }
    if (!OfferScreen::IsCurrent()) {
      return RuntimeActionResult::Failure(
          "the beginning-save trade phase did not present the offer desk");
    }
    OfferScreen offerScreen;
    TOfferDeskPicture* offer = offerScreen.View();
    if (offer == 0) {
      return RuntimeActionResult::Failure("the presented offer desk is unavailable");
    }
    // DoTrade opens the offer-desk presentation before constructing deals. No retail offer is
    // posed for this fixture: the desk retains its zero-initialized payload and the deal cursor
    // runs past all seventeen commodity categories.
    if (offer->respondingNationSlot != 0 || offer->offeringNationSlot != 0 ||
        offer->commodityType != 0 || offer->proposedAmount != 0 || offer->maxAmount != 0) {
      return RuntimeActionResult::Failure(
          "the beginning-save trade phase unexpectedly posed a concrete offer");
    }
    if (g_pTradeMgr->categoryRows[0].dealCategoryOrderIndex != 0x11 ||
        g_pTradeMgr->categoryRows[0].dealEntryOrdinal != 1) {
      return RuntimeActionResult::Failure("the beginning-save trade deals did not finish");
    }

    JsonObject effect;
    effect.Set("kind", "show_offer_sheet");
    effect.Set("nation", static_cast<int>(g_pSimMgr->activeNationSlot));
    JsonArray effects;
    effects.Add(effect.Release());
    JsonObject result;
    result.Set("kind", "continues");
    result.Set("from", 7);
    result.Set("to", 9);
    result.Set("effects", effects.Release());
    RunState().SetCapture("result", result.Release());
    if (!RunState().HasCapture("result")) {
      return RuntimeActionResult::Failure("the turn outcome capture is unavailable");
    }
    if (!CaptureGameState(RunState(), "after")) {
      return RuntimeActionResult::Failure("the after game-state capture is unavailable");
    }
    return RuntimeActionResult::Success();
  }
};

} // namespace

RUNTIME_TEST_FACTORY(FirstTurnTradePhaseTestCase, FirstTurnTradePhaseTest)
