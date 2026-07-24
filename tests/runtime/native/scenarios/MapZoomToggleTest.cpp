#include "RuntimeScenario.h"

namespace {

const RuntimeScenarioConfig kConfig = {"map_zoom_toggle_remains_responsive",
                                       kCompleteAfterMapZoomToggle, true, false, true};
RuntimeScenario g_test(kConfig);

} // namespace

RuntimeTestCase* MapZoomToggleTest() {
  return &g_test;
}
