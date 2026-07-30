#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"
#include "probes/StrategicMapProbe.h"
#include "screens/CapitalSelectionScreen.h"
#include "screens/MainMenuScreen.h"
#include "screens/RandomSetupScreen.h"
#include "screens/StrategicMapScreen.h"

namespace {

// Hard, which is not the difficulty the flow started with -- so the reopened setup accepting it is
// observable rather than a no-op.
const int kHardDifficulty = 3;

// Leaving the new-game flow and coming back into it.
//
// From capital selection: cancel back to setup, cancel out to the main menu, start a random game
// again, pick a different difficulty, accept, and let the flow carry on to the map. The map is then
// held to the same rendering, hover-cache and scrolling checks as a first-time entry, because the
// point of the journey is that a re-entered game is not a degraded one.
//
// This is the only scenario that hands navigation back mid-script, which is what
// CapitalSelectionScriptScenario exists for: the script pauses at RestartRandomGameAtStrategicMapEntry()
// and resumes at the same statement once the flow reports the map.
class RandomGameJourneyTestCase : public CapitalSelectionScriptScenario {
public:
protected:
  void Script() override {
    RT_BEGIN();

    RT_DO("cancel back to the random setup", CapitalSelection().CancelToSetup());
    RT_AWAIT(RandomSetupScreen::IsCurrent(), kObserveUiStateChanged);

    RT_DO("cancel out to the main menu", RandomSetup().Cancel());
    RT_AWAIT(MainMenuScreen::IsCurrent(), kObserveUiStateChanged);

    RT_DO("start a random game again", MainMenu().StartRandomGame());
    RT_AWAIT(RandomSetupScreen::IsCurrent(), kObserveUiStateChanged);

    // The reopened screen picks its own nation; the run records which, so its artifacts name the
    // nation the rest of the journey is about.
    SetSelectedNation(RandomSetup().SelectedNationSlot());
    RT_DO("select the hard difficulty", RandomSetup().SelectDifficulty(kHardDifficulty));
    RT_REQUIRE(RandomSetup().DifficultyIsSelected(kHardDifficulty));
    RT_DO("accept the reopened setup", RandomSetup().Accept());

    // Hand navigation back. The script continues below once the flow reports the map, which is why
    // the wait after this is not reached until then.
    RestartRandomGameAtStrategicMapEntry();
    RT_AWAIT(StrategicMapScreen::IsCurrent(), kObserveUiStateChanged);

    RT_DO("verify the map renders", StrategicMapProbe::VerifyRendering());
    RT_DO("verify the map's hover cache", StrategicMapProbe::VerifyHoverCache());
    RT_DO("verify the map scrolls", StrategicMapProbe::VerifyScrolling());
    RT_PASS();

    RT_END();
  }
};

} // namespace

RUNTIME_TEST_FACTORY(RandomGameJourneyTestCase, RandomGameJourneyTest)
