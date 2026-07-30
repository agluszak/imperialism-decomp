#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"
#include "screens/StrategicMapScreen.h"

#include "game/map/TMapUberPicture.h"
#include "game/map_ui/TMapDialog.h"
#include "game/turn_event_codes.h"

namespace {

// Toggling the map zoom twice must leave the strategic map fully responsive: the alternate
// mode entered and left cleanly both times, and scrolling still moves the viewport afterwards.
class MapZoomToggleTestCase : public CombinedMapScriptScenario {
public:
  MapZoomToggleTestCase() : toggleCycles(0), previousViewportX(0) {}

  bool RecordsGameFlow() const override {
    return true;
  }

protected:
  void Script() override {
    RT_BEGIN();

    // The combined-map checkpoint is supposed to hand over an idle map, so a modal still up
    // here is a defect to report, not something to wait out.
    RT_REQUIRE(StrategicMapScreen::IsCurrent());

    // toggleCycles is a member because it has to survive the yields inside the loop; the
    // compiler enforces that (a local here would be C2360). See RuntimeScriptMacros.h.
    while (toggleCycles < 2) {
      RT_ACTIVATE_AND_AWAIT("zoom the map out", StrategicMap().ZoomOut(),
                            StrategicMap().IsZoomedOut(), kObserveUiStateChanged);
      RT_ACTIVATE_AND_AWAIT("zoom the map in", StrategicMap().ZoomIn(), StrategicMap().IsZoomedIn(),
                            kObserveUiStateChanged);
      ++toggleCycles;
    }

    // Repeated toggling used to leave the map unable to scroll, which is the regression this
    // scenario exists for: a zoom cycle that leaves the viewport pinned looks fine on screen.
    RT_ACTION("centre the viewport", StrategicMap().SetViewportCell(10, 10));
    previousViewportX = StrategicMap().ViewportOriginX();
    RT_ACTION("scroll the map", StrategicMap().ScrollBy(kScrollEast));
    RT_REQUIRE_NE(previousViewportX, StrategicMap().ViewportOriginX());

    RT_PASS();

    RT_END();
  }

private:
  // TMapUberPicture::Scroll takes an edge mask; 4 is the eastward edge.
  enum { kScrollEast = 4 };

  short toggleCycles;
  int previousViewportX;
};

} // namespace

RUNTIME_TEST_FACTORY(MapZoomToggleTestCase, MapZoomToggleTest)
