#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"
#include "flows/EndTurnFlow.h"

#include "game/core/global_data_tables.h"
#include "game/globals/ui_core_globals.h"
#include "game/ui_core/THelpMgr.h"
#include "game/ui_screens/TSimMgr.h"

namespace {

// End the turn several times in a row on Easy and require the game to come back to a playable
// strategic map each time, with the economic turn advancing by exactly one and no unexpected
// modal left behind. One end turn (easy_turns_advance) only proves the first hop; later turns
// exercise the alert-modals-then-Done-again path before the state machine advances, which is
// what this scenario is for -- and which EndTurnFlow now owns for every caller.
const short kTurnsToAdvance = 3;

class MultiTurnAdvanceTestCase : public EasyMapScriptScenario {
public:
  MultiTurnAdvanceTestCase() : turnsDone(0), startEconomicTurn(0) {}

  bool RecordsGameFlow() const override {
    return true;
  }

protected:
  void Script() override {
    RT_BEGIN();

    turnsDone = 0;
    startEconomicTurn = g_pSimMgr->economicTurn;
    ResetCapitolDangerWarningObservationForRuntimeTest();

    // A loop around the shared sequence, instead of a second copy of it. turnsDone is a member
    // because it has to survive the yields inside EndTurnFlow.
    while (turnsDone < kTurnsToAdvance) {
      RT_RUN(endTurn.RejectOffers().ExpectExactlyOneTurn().ToNextStrategicMap(*this));
      RT_REQUIRE_EQ(endTurn.StartingTurn() + 1, endTurn.EndingTurn());
      ++turnsDone;
    }

    RT_REQUIRE_EQ(startEconomicTurn + kTurnsToAdvance, g_pSimMgr->economicTurn);

    // The capitol-danger warning must have been evaluated on the peaceful path, and what it
    // decided to threaten must be what it displayed. A mismatch here is the warning firing on
    // state the player was never shown.
    RT_REQUIRE_NE(0, CapitolDangerWarningEvaluationCountForRuntimeTest());
    RT_REQUIRE(WasCapitolDangerWarningEvaluatedAtPeaceForRuntimeTest());
    RT_REQUIRE_EQ(CapitolDangerThreatMaskForRuntimeTest(),
                  CapitolDangerDisplayedMaskForRuntimeTest());

    RT_PASS();

    RT_END();
  }

private:
  EndTurnFlow endTurn;
  short turnsDone;
  short startEconomicTurn;
};

} // namespace

RUNTIME_TEST_FACTORY(MultiTurnAdvanceTestCase, MultiTurnAdvanceTest)
