#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"
#include "flows/EndTurnFlow.h"

#include "game/turn_event_codes.h"

namespace {

// One end turn on Easy. The economic turn must advance by exactly one and the game must come
// back to a playable strategic map, rather than into the game-over/opening-cinematic path.
class EndTurnTestCase : public EasyMapScriptScenario {
public:
protected:
  void Script() override {
    RT_BEGIN();

    RT_RUN(endTurn.RejectOffers().ExpectExactlyOneTurn().ToNextStrategicMap(*this));
    RT_REQUIRE_EQ(endTurn.StartingTurn() + 1, endTurn.EndingTurn());
    RT_PASS();

    RT_END();
  }

private:
  EndTurnFlow endTurn;
};

} // namespace

RUNTIME_TEST_FACTORY(EndTurnTestCase, EndTurnTest)
