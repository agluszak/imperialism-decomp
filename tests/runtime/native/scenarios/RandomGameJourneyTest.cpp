#include "RuntimeScenario.h"

namespace {

const RuntimeScenarioConfig kConfig = {"random_game_enters_map", kCompleteAfterNormalJourney, true,
                                       false, true};
RuntimeScenario g_test(kConfig);

} // namespace

RuntimeTestCase* RandomGameJourneyTest() {
  return &g_test;
}
