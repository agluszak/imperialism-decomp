#include "NativeCases.h"

#include "flows/LoadGameFlow.h"
#include "scenarios/RuntimeScenario.h"
#include "scenarios/RuntimeTestFactory.h"

#include <stdlib.h>

namespace {

class NativeTransitionOracleCase : public RuntimeScenario {
public:
  bool RequiresFixture() const {
    return true;
  }

protected:
  RuntimeFlow* NavigationFlow() {
    return &loadGameFlow;
  }

  void OnCombinedMapReady() {
    const char* name = getenv("IMPERIALISM_NATIVE_CASE");
    if (name == 0 || name[0] == '\0') {
      FailScenario("IMPERIALISM_NATIVE_CASE is unset");
      return;
    }

    NativeTransition transition(RunState());
    const NativeCase* nativeCase = FindNativeCase(name);
    if (nativeCase == 0) {
      FailScenario("unknown native transition case");
      return;
    }

    RuntimeActionResult result = nativeCase->run(transition);
    if (!result.Succeeded()) {
      FailScenarioText((LPCSTR)result.FailureMessage());
      return;
    }

    Pass();
  }

private:
  LoadGameFlow loadGameFlow;
};

} // namespace

RUNTIME_TEST_FACTORY(NativeTransitionOracleCase, NativeTransitionOracle)
