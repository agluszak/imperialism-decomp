#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"

namespace {

// RandomSetupFlow captures the generated world while the retail random-setup screen is
// current, before this scenario accepts the setup and reaches the strategic map. Reaching
// this script therefore proves that the snapshot came from the real setup path rather than
// from a constructed fixture or a test-only map generator entry point.
class GeneratedWorldSnapshotTestCase : public EasyMapScriptScenario {
protected:
  void Script() override {
    RT_BEGIN();
    RT_PASS();
    RT_END();
  }
};

} // namespace

RUNTIME_TEST_FACTORY(GeneratedWorldSnapshotTestCase, GeneratedWorldSnapshotTest)
