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
  MapZoomToggleTestCase()
      : toggleCycles(0), previousViewportX(0), detailedCenter(0), oceanCenter(0) {}

protected:
  void Script() override {
    RT_BEGIN();

    // The combined-map checkpoint is supposed to hand over an idle map, so a modal still up
    // here is a defect to report, not something to wait out.
    RT_REQUIRE(StrategicMapScreen::IsCurrent());

    RT_DO("position the detailed map", StrategicMap().SetViewportCell(10, 10));
    detailedCenter = StrategicMap().DetailedCenterTile();
    RT_ACTIVATE_AND_AWAIT("zoom the map out", StrategicMap().ZoomOut(),
                          StrategicMap().IsZoomedOut(), kObserveUiStateChanged);
    RT_REQUIRE_EQ(detailedCenter, StrategicMap().OceanCenterTile());
    RT_REQUIRE_EQ(0x20, StrategicMap().MiniMapMarkerWidth());
    RT_REQUIRE_EQ(0x1c, StrategicMap().MiniMapMarkerHeight());

    RT_DO("position a wrapping overview beyond the northwest edge",
          StrategicMap().SetOceanViewportCellForTopology(-4, -4, true));
    RT_REQUIRE_EQ(104, StrategicMap().OceanOriginColumn());
    RT_REQUIRE_EQ(0, StrategicMap().OceanOriginRow());
    RT_DO("position a bounded overview beyond the southeast edge",
          StrategicMap().SetOceanViewportCellForTopology(100, 60, false));
    RT_REQUIRE_EQ(0x4c, StrategicMap().OceanOriginColumn());
    RT_REQUIRE_EQ(0x20, StrategicMap().OceanOriginRow());
    RT_DO("restore the overview center", StrategicMap().CenterOceanOn(detailedCenter));

    RT_DO("scroll the overview", StrategicMap().ScrollBy(kScrollEast));
    oceanCenter = StrategicMap().OceanCenterTile();
    RT_ACTIVATE_AND_AWAIT("zoom the map in", StrategicMap().ZoomIn(), StrategicMap().IsZoomedIn(),
                          kObserveUiStateChanged);
    // TMapDialog::CenterOn places its target three rows below the origin while
    // TMapDialog::GetCenterTile observes origin+4. Preserve that retail one-row visual
    // offset instead of silently treating the two dialog projections as identical.
    RT_REQUIRE_EQ(oceanCenter + kMapWidth, StrategicMap().DetailedCenterTile());
    RT_REQUIRE_EQ(9, StrategicMap().MiniMapMarkerWidth());
    RT_REQUIRE_EQ(8, StrategicMap().MiniMapMarkerHeight());

    // Retail zooms in on a mode *change* into civilian mode. An explicit Zoom Out while the
    // map is already in civilian mode remains zoomed out.
    RT_DO("enter army mode", StrategicMap().ShowArmyToolbar());
    RT_ACTIVATE_AND_AWAIT("zoom the army map out", StrategicMap().ZoomOut(),
                          StrategicMap().IsZoomedOut(), kObserveUiStateChanged);
    RT_DO("change into civilian mode", StrategicMap().ShowCivilianToolbar());
    RT_REQUIRE(StrategicMap().IsZoomedIn());
    RT_ACTIVATE_AND_AWAIT("zoom the civilian map out", StrategicMap().ZoomOut(),
                          StrategicMap().IsZoomedOut(), kObserveUiStateChanged);
    RT_DO("select civilian mode again", StrategicMap().ShowCivilianToolbar());
    RT_REQUIRE(StrategicMap().IsZoomedOut());
    RT_ACTIVATE_AND_AWAIT("return to the detailed map", StrategicMap().ZoomIn(),
                          StrategicMap().IsZoomedIn(), kObserveUiStateChanged);

    RT_DO("inspect the turn summary", StrategicMap().ActivateZoomWithControl());
    RT_REQUIRE(StrategicMap().IsZoomedIn());

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
    RT_DO("centre the viewport", StrategicMap().SetViewportCell(10, 10));
    previousViewportX = StrategicMap().ViewportOriginX();
    RT_DO("scroll the map", StrategicMap().ScrollBy(kScrollEast));
    RT_REQUIRE_NE(previousViewportX, StrategicMap().ViewportOriginX());

    RT_PASS();

    RT_END();
  }

private:
  // TMapUberPicture::Scroll takes an edge mask; 4 is the eastward edge.
  enum { kScrollEast = 4, kMapWidth = 108 };

  short toggleCycles;
  int previousViewportX;
  int detailedCenter;
  int oceanCenter;
};

} // namespace

RUNTIME_TEST_FACTORY(MapZoomToggleTestCase, MapZoomToggleTest)
