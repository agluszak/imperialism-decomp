#include "RuntimeScenario.h"

namespace {

const RuntimeScenarioConfig kConfig = {"easy_turns_advance", kCompleteAfterTurns, true, true, true};
RuntimeScenario g_test(kConfig);

} // namespace

RuntimeTestCase* EndTurnTest() {
  return &g_test;
}
