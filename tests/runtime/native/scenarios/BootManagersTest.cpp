#include "RuntimeScenario.h"

namespace {

const RuntimeScenarioConfig kConfig = {"boot_managers", kCompleteOnManagers, false, false, false};
RuntimeScenario g_test(kConfig);

} // namespace

RuntimeTestCase* BootManagersTest() {
  return &g_test;
}
