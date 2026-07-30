#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"
#include "probes/StartingCiviliansProbe.h"
#include "screens/NewspaperScreen.h"
#include "screens/StrategicMapScreen.h"

#include "game/city_ui/TCivMgr.h"
#include "game/core/global_data_tables.h"
#include "game/globals/shared_globals.h"
#include "game/military/TCivUnit.h"
#include "game/ui_screens/TNewsMgr.h"
#include "game/ui_screens/TSimMgr.h"

namespace {

// The civilian portraits are consecutive artwork from this base, indexed by order type.
const short kCivilianPortraitGlyphBase = 0x438;

// A newspaper page is a three-by-three grid of story slots.
const int kNewspaperStoryColumns = 3;
const int kNewspaperStoryRows = 3;

// The headline and at least one story: fewer than two populated text controls means the page was
// laid out but never filled.
const int kMinimumPopulatedTextEntries = 2;

// An Introductory game: the opening newspaper is generated, and the map hands the player five
// civilians whose toolbar shows the one they select.
//
// The newspaper is only up while the navigation flow is still running, so its contents are checked
// from BeforeInitialNewspaperExit -- the hook the flow calls before dismissing it -- rather than
// from the script, which does not begin until the map is ready.
class IntroductoryRandomGameTestCase : public IntroductoryMapScriptScenario {
public:
  bool BeforeInitialNewspaperExit() override {
    RuntimeActionResult civilians = StartingCiviliansProbe::VerifyForNation(ActiveNation());
    if (!civilians.Succeeded()) {
      FailScenarioText(static_cast<LPCSTR>(civilians.FailureMessage()));
      return false;
    }
    const int page = Newspaper().SummaryPageIndex();
    if (PopulatedStoryCount(page) == 0) {
      CString failure;
      failure.Format("Introductory newspaper page %d has no generated stories (active nation %d, "
                     "template count %d)",
                     page, static_cast<int>(ActiveNation()), g_pNewsMgr->storyTemplateCount);
      FailScenarioText(static_cast<LPCSTR>(failure));
      return false;
    }
    if (Newspaper().NonEmptyTextChildCount() < kMinimumPopulatedTextEntries) {
      FailScenarioText("Introductory newspaper did not populate its headline and story text");
      return false;
    }
    return true;
  }

protected:
  void Script() override {
    RT_BEGIN();

    RT_DO("verify the starting civilians", StartingCiviliansProbe::VerifyForNation(ActiveNation()));
    RT_DO("show the civilian toolbar", StrategicMap().ShowCivilianToolbar());
    RT_REQUIRE(StrategicMap().CivilianToolbarIsPlaced());

    RT_REQUIRE_NOT_NULL(FirstCivilian());
    // Selecting through the order state is what a map click resolves to; the toolbar is expected
    // to follow it with that civilian's own portrait.
    g_pSelectedCivilianOrderState->SetActiveCivilianSelection(FirstCivilian(), 1);
    RT_REQUIRE_EQ(static_cast<short>(FirstCivilian()->orderType + kCivilianPortraitGlyphBase),
                  StrategicMap().CivilianPortraitGlyph());
    RT_REQUIRE(StrategicMap().CivilianPortraitIsLoaded());
    RT_PASS();

    RT_END();
  }

private:
  short ActiveNation() const {
    return g_pSimMgr->activeNationSlot;
  }

  TCivUnit* FirstCivilian() const {
    return StartingCiviliansProbe::CivilianForNation(ActiveNation(), 1);
  }

  int PopulatedStoryCount(int page) const {
    if (page < 0) {
      return 0;
    }
    int populated = 0;
    for (int column = 0; column < kNewspaperStoryColumns; ++column) {
      for (int row = 0; row < kNewspaperStoryRows; ++row) {
        if (g_pNewsMgr->stories[page][column][row].entry.storyId != 0) {
          ++populated;
        }
      }
    }
    return populated;
  }
};

} // namespace

RUNTIME_TEST_FACTORY(IntroductoryRandomGameTestCase, IntroductoryRandomGameTest)
