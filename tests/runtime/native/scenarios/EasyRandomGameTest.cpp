#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"

namespace {

// A random game on Easy reaches the map without a capital-selection step. The assertion is the
// arrival itself: EasyMapScriptScenario only starts the script once the flow has reported
// kRuntimeMapReadyWithoutCapitalSelection, and the base fails the run if event 0x3b8 (the
// capital-site selector) fires at this difficulty at all.
class EasyRandomGameTestCase : public EasyMapScriptScenario {
public:
  bool RecordsGameFlow() const override {
    return true;
  }

protected:
  void Script() override {
    RT_BEGIN();
    RT_PASS();
    RT_END();
  }
};

} // namespace

RUNTIME_TEST_FACTORY(EasyRandomGameTestCase, EasyRandomGameTest)
