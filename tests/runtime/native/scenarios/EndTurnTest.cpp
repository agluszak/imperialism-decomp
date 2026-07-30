#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"
#include "screens/StrategicMapScreen.h"

#include "game/core/global_data_tables.h"
#include "game/map/TMapUberPicture.h"
#include "game/turn_event_codes.h"
#include "game/ui_screens/TSimMgr.h"

namespace {

// One end turn on Easy. The economic turn must advance by exactly one and the game must come
// back to the strategic map, rather than into the game-over/opening-cinematic path.
class EndTurnTestCase : public EasyMapScriptScenario {
public:
  EndTurnTestCase() : baselineEconomicTurn(0), leftDealBook(false) {}

  bool RecordsGameFlow() const override {
    return true;
  }

protected:
  void Script() override {
    RT_BEGIN();

    RT_AWAIT_SCREEN(TMapUberPicture, kTurnEventStrategicMap);
    baselineEconomicTurn = g_pSimMgr->economicTurn;
    leftDealBook = false;
    ResetNewspaperAdvance();

    RT_ACTION("end the turn", StrategicMap().EndTurn());

    // Ending a turn walks through the Deal Book and the newspaper before the map comes back.
    // Leaving the Deal Book is one-shot: StartNextPhase twice would advance two phases.
    //
    // Every branch either yields or awaits. Handling a step and then falling through to a
    // condition like "the Deal Book is showing" would spin, because the event does not change
    // until the game gets a turn to process what was just done.
    while (!TurnAdvancedBackOnMap()) {
      RT_REQUIRE_NE(kTurnEventOpeningCinematic, CurrentTurnEvent());
      if (CurrentTurnEvent() == kTurnEventDealBook && !leftDealBook) {
        leftDealBook = true;
        g_pSimMgr->StartNextPhase();
        RT_YIELD();
      } else if (AdvanceNewspaperIfNeeded()) {
        // The helper armed its own wait. The program counter still points into this loop, so
        // the next observation re-enters and re-tests every branch. RuntimeScriptFragment and
        // EndTurnFlow replace this borrowed helper (bd imperialism-decomp-rfcp.5).
        return;
      } else {
        RT_AWAIT(ATurnStepIsReady(), kObserveUiStateChanged);
      }
    }

    RT_REQUIRE_EQ(baselineEconomicTurn + 1, g_pSimMgr->economicTurn);
    RT_PASS();

    RT_END();
  }

private:
  bool TurnAdvancedBackOnMap() const {
    return StrategicMapScreen::IsCurrent() && g_pSimMgr->economicTurn != baselineEconomicTurn;
  }

  // "One of the branches above would now do something." Waiting on this rather than on "an
  // expected screen is showing" is what keeps the loop from spinning after it has already
  // handled the screen that is still on display.
  bool ATurnStepIsReady() const {
    return TurnAdvancedBackOnMap() || CurrentTurnEvent() == kTurnEventOpeningCinematic ||
           CurrentTurnEvent() == kTurnEventNewspaperStatus ||
           (CurrentTurnEvent() == kTurnEventDealBook && !leftDealBook);
  }

  short baselineEconomicTurn;
  bool leftDealBook;
};

} // namespace

RUNTIME_TEST_FACTORY(EndTurnTestCase, EndTurnTest)
