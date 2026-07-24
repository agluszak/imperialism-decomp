#include "RuntimeScenario.h"

namespace {

const RuntimeScenarioConfig kConfig = {"random_game_easy_skips_capital", kCompleteOnEasyMap, true,
                                       true, true};
RuntimeScenario g_test(kConfig);

} // namespace

RuntimeTestCase* EasyRandomGameTest() {
  return &g_test;
}
