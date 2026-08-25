#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"
#include "screens/StrategicMapScreen.h"

#include "game/globals/game_session_globals.h"
#include "game/navy/TOcean.h"
#include "game/navy/TShip.h"
#include "game/navy/TTaskForce.h"
#include "game/map/TZone.h"
#include "game/ui_screens/TSimMgr.h"

namespace {

// Selecting the player's port zone with a spawned fleet arms the navy menu: class counts
// match the selected ships, aggression radios rewrite the force, and the class arrows move
// one ship out of and back into the selection. Opening the roster is PoseModally, so the
// screen queues the okay dismiss before activating bomb.
//
// Starting games have no player fleet. Spawning through TShip::IShip is the same model path
// NativeNavyOrderCases uses; SetActiveMapOrderEntry then builds the task force.
class NavyMenuTestCase : public EasyMapScriptScenario {
public:
  NavyMenuTestCase() : portZone(0), initialSelected(0) {}

protected:
  void Script() override {
    RT_BEGIN();

    RT_REQUIRE(StrategicMapScreen::IsCurrent());
    RT_REQUIRE(StrategicMap().HasDialog());

    portZone = PlayerPortZone();
    RT_REQUIRE(portZone != 0);
    SpawnTwoFrigates(portZone);

    RT_DO("select the navy port zone", StrategicMap().SelectNavyZone(portZone));
    RT_REQUIRE(StrategicMap().NavyMenuIsActiveForZone(portZone));
    RT_REQUIRE_EQ(2, StrategicMap().NavyClassAvailableCount(kFrigateClass));
    initialSelected = StrategicMap().NavyClassSelectedCount(kFrigateClass);
    RT_REQUIRE_EQ(2, initialSelected);
    RT_REQUIRE_EQ(1, StrategicMap().NavySelectedAggression());

    RT_DO("deselect one frigate", StrategicMap().DeselectOneNavyClassShip(kFrigateClass));
    RT_REQUIRE_EQ(initialSelected - 1, StrategicMap().NavyClassSelectedCount(kFrigateClass));
    RT_DO("select the frigate again", StrategicMap().SelectOneNavyClassShip(kFrigateClass));
    RT_REQUIRE_EQ(initialSelected, StrategicMap().NavyClassSelectedCount(kFrigateClass));

    RT_DO("set aggressive stance", StrategicMap().SetNavyAggression(kAggressive));
    RT_REQUIRE_EQ(kAggressive, StrategicMap().NavySelectedAggression());
    RT_REQUIRE_EQ(kAggressive, SelectedForceAggression());

    RT_DO("open and dismiss the navy roster", StrategicMap().OpenNavyRoster());
    RT_REQUIRE(StrategicMapScreen::IsCurrent());
    RT_REQUIRE(StrategicMap().NavyMenuIsActiveForZone(portZone));

    RT_PASS();

    RT_END();
  }

private:
  enum { kFrigateType = 3, kFrigateClass = 1, kAggressive = 2 };

  TZone* PlayerPortZone() const {
    if (g_pActiveMapOrderContext == 0 || g_pSimMgr == 0) {
      return 0;
    }
    return g_pActiveMapOrderContext->FindFirstPortZoneContextByNation(g_pSimMgr->GetActiveNationId());
  }

  void SpawnTwoFrigates(TZone* zone) {
    const short nation = g_pSimMgr->GetActiveNationId();
    TShip* first = new TShip();
    first->IShip(kFrigateType, zone, nation, "navy-menu-a");
    TShip* second = new TShip();
    second->IShip(kFrigateType, zone, nation, "navy-menu-b");
  }

  short SelectedForceAggression() const {
    if (g_pActiveMapOrderContext == 0 || g_pActiveMapOrderContext->selectedTaskForce14 == 0) {
      return -1;
    }
    return static_cast<short>(g_pActiveMapOrderContext->selectedTaskForce14->aggression);
  }

  TZone* portZone;
  short initialSelected;
};

} // namespace

RUNTIME_TEST_FACTORY(NavyMenuTestCase, NavyMenuTest)
