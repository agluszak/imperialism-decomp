#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"
#include "screens/ArmyBookScreen.h"
#include "screens/StrategicMapScreen.h"

#include "game/core/global_data_tables.h"
#include "game/globals/shared_globals.h"
#include "game/map/TMapMgr.h"
#include "game/map/TMapUberPicture.h"
#include "game/map_ui/TMapDialog.h"
#include "game/turn_event_codes.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_core/TView.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_military.h"

namespace {

// Selecting the player's capital province arms the army menu: every unit-category placard is
// populated, the ratio arrows move an idle unit out and back, and opening the army book neither
// leaves the garrison page empty nor disturbs map ownership.
//
// Deliberately Normal difficulty rather than Easy. TCountry's starting-army setup gives every
// garrison unit SetOrders(2) when difficultyLevel < 2, so on Easy no unit is idle on turn 1 and the
// ratio arrows -- whose value is the idle count -- can only ever read zero. At difficulty 2 and
// above the same units keep the idle order RegisterUnitOrderWithOwnerManager gave them, which is
// the state this scenario is about. (imperialism-decomp-5tf4: that mismatch, not a toolbar defect,
// is why this test failed when its body first ran.)
//
// The whole sequence is synchronous, so the script has no waits.
class ArmyMenuTestCase : public CombinedMapScriptScenario {
public:
  ArmyMenuTestCase() : capitalProvince(-1), arrowCategory(-1), initialIdleCount(0) {}

protected:
  void Script() override {
    RT_BEGIN();

    RT_REQUIRE(StrategicMapScreen::IsCurrent());
    RT_REQUIRE(StrategicMap().HasDialog());

    capitalProvince = CapitalProvince();
    RT_REQUIRE_NE(-1, capitalProvince);

    RT_DO("select the capital province", StrategicMap().SelectArmyProvince(capitalProvince));
    RT_REQUIRE(StrategicMap().ArmyMenuIsActiveForProvince(capitalProvince));

    RT_REQUIRE(StrategicMap().AllArmyPlacardsPopulated());

    // Moving a unit out of the idle pool and returning it must be exactly reversible. Asserted
    // as two RT_REQUIRE_EQs rather than one predicate so a failure reports the counts, not just
    // that they disagreed.
    arrowCategory = StrategicMap().FirstActionableArmyCategory();
    RT_REQUIRE_NE(-1, arrowCategory);
    initialIdleCount = StrategicMap().ArmyIdleCount(arrowCategory);

    RT_DO("select an idle unit", StrategicMap().MoveOneIdleUnitOut(arrowCategory));
    RT_REQUIRE_EQ(initialIdleCount - 1, StrategicMap().ArmyIdleCount(arrowCategory));

    RT_DO("return the selected unit", StrategicMap().ReturnOneUnit(arrowCategory));
    RT_REQUIRE_EQ(initialIdleCount, StrategicMap().ArmyIdleCount(arrowCategory));

    CaptureOwnership();
    RT_DO("open the army book", armyBook.Open());
    RT_DO("show the capital garrison", armyBook.ShowProvince(capitalProvince));
    RT_REQUIRE(armyBook.HasUnitSpritePage());
    RT_DO("close the army book", armyBook.Close());
    RT_REQUIRE(OwnershipIsUnchanged());

    RT_PASS();

    RT_END();
  }

private:
  enum { kCityRecordCount = 0x180 };

  short CapitalProvince() const {
    const short activeNation = g_pSimMgr->GetActiveNationId();
    if (g_apTerrainTypeDescriptorTable[activeNation] == 0) {
      return -1;
    }
    const short capitalTile =
        static_cast<short>(g_apTerrainTypeDescriptorTable[activeNation]->homeTileIndex);
    return g_pGlobalMapState->terrainStateTable[capitalTile].cityRecordIndex;
  }

  void CaptureOwnership() {
    for (int index = 0; index < kCityRecordCount; ++index) {
      ownerBefore[index] = g_pGlobalMapState->cityScoreTable[index].ownerNationCode00;
    }
  }

  // Opening and closing the book must not touch province ownership; it is a read-only view, and
  // a change here would mean the book's teardown is writing through stale state.
  bool OwnershipIsUnchanged() const {
    // MSVC500 predates per-loop `for` scope, so a second `int index` in this function would be a
    // redefinition; this loop names its own counter.
    for (int verified = 0; verified < kCityRecordCount; ++verified) {
      if (g_pGlobalMapState->cityScoreTable[verified].ownerNationCode00 != ownerBefore[verified]) {
        return false;
      }
    }
    return true;
  }

  ArmyBookScreen armyBook;
  short ownerBefore[kCityRecordCount];
  short capitalProvince;
  short arrowCategory;
  short initialIdleCount;
};

} // namespace

RUNTIME_TEST_FACTORY(ArmyMenuTestCase, ArmyMenuTest)
