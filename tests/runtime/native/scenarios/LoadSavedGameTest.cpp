#include "RuntimeScenario.h"

namespace {

const RuntimeScenarioConfig kConfig = {"load_saved_game", kCompleteAfterLoadedMap, false, false,
                                       true};
const RuntimeScenarioConfig kUnknownConfig = {"unknown", kCompleteOnManagers, false, false, false};
RuntimeScenario g_test(kConfig);
RuntimeScenario g_unknownTest(kUnknownConfig);

} // namespace

RuntimeTestCase* LoadSavedGameTest() {
  return &g_test;
}

RuntimeTestCase* UnknownRuntimeTest() {
  return &g_unknownTest;
}
