#include "RuntimeGameStateCapture.h"
#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"

namespace {

// Normal difficulty parks at capital selection (event 0x3b8 / TCitySiteView) with the
// capital-selection prompt dismissed and no human capital placed yet. Capturing game_state
// here is the Rust create_random_game start-boundary oracle.
class RandomGameNormalStartTestCase : public CapitalSelectionScriptScenario {
protected:
  void Script() override {
    RT_BEGIN();
    // Arrival at kRuntimeCapitalSelectionReady is the assertion; CaptureGameStateIfRequested
    // would otherwise publish the two bytes retail leaves undefined on these fresh objects.
    RT_REQUIRE(CaptureFreshRandomGameState(RunState(), "game_state"));
    RT_PASS();
    RT_END();
  }
};

} // namespace

RUNTIME_TEST_FACTORY(RandomGameNormalStartTestCase, RandomGameNormalStartTest)
