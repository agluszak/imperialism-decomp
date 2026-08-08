#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"

namespace {

// The floor of the suite: the game's managers come up. No window, no navigation, no screen --
// if this fails, nothing else can be believed.
class BootManagersTestCase : public ManagersReadyScriptScenario {
protected:
  void Script() override {
    RT_BEGIN();
    RT_PASS();
    RT_END();
  }
};

} // namespace

RUNTIME_TEST_FACTORY(BootManagersTestCase, BootManagersTest)
