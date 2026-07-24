#include "RuntimeScenario.h"

namespace {

const RuntimeScenarioConfig kConfig = {"city_screen_opens", kCompleteOnCityScreen, true, true,
                                       true};
RuntimeScenario g_test(kConfig);

} // namespace

RuntimeTestCase* CityScreenTest() {
  return &g_test;
}
