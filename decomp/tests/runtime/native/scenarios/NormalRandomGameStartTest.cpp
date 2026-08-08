#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"

namespace {

// CapitalSelectionScriptScenario starts this script only after the setup has
// been accepted and the city-site selector is active.  Stop before selecting a
// capital so the captured state is the random-game start boundary itself.
class NormalRandomGameStartTestCase : public CapitalSelectionScriptScenario {
protected:
  void Script() override {
    RT_BEGIN();
    RT_PASS();
    RT_END();
  }
};

} // namespace

RUNTIME_TEST_FACTORY(NormalRandomGameStartTestCase, NormalRandomGameStartTest)
