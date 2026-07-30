#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"
#include "screens/StrategicMapScreen.h"

#include "game/assets/TAssetMgr.h"
#include "game/core/global_data_tables.h"
#include "game/globals/shared_globals.h"
#include "game/map/TMapMgr.h"
#include "game/map/TMapUberPicture.h"
#include "game/map_ui/TMapDialog.h"
#include "game/military/TArmyMgr.h"
#include "game/ui_widgets/TArmyPlacard.h"
#include "game/ui_widgets/TArmyToolbar.h"
#include "game/military/TGarrisonView.h"
#include "game/turn_event_codes.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TWindow.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_military.h"
#include "game/ui_widgets/TNumberedArrowButton.h"

namespace {

// Selecting the player's capital province arms the army menu: every unit-category placard is
// populated, the ratio arrows move an idle unit out and back, and opening the army book neither
// leaves the garrison page empty nor disturbs map ownership.
//
// The whole sequence is synchronous, so the script has no waits.
class ArmyMenuTestCase : public EasyMapScriptScenario {
public:
  ArmyMenuTestCase() : capitalProvince(-1), arrowCategory(-1), initialIdleCount(0) {}

protected:
  void Script() override {
    RT_BEGIN();

    RT_REQUIRE(StrategicMapScreen::IsCurrent());
    RT_REQUIRE_NOT_NULL(StrategicMap().Dialog());

    capitalProvince = CapitalProvince();
    RT_REQUIRE_NE(-1, capitalProvince);

    RT_STEP("select the capital province", StrategicMap().SelectArmyProvince(capitalProvince));
    RT_REQUIRE(StrategicMap().ArmyMenuIsActiveForProvince(capitalProvince));

    RT_REQUIRE(EveryPlacardIsPopulated());

    // The arrow's lower half moves an idle unit into the selection and its upper half returns
    // it, so the pair must be exactly reversible. Asserted as two RT_REQUIRE_EQs rather than one
    // predicate so a failure reports the counts, not just that they disagreed.
    arrowCategory = FirstActionableRatioArrowCategory();
    RT_REQUIRE_NE(-1, arrowCategory);
    initialIdleCount = RatioArrowValue();

    RT_STEP("select an idle unit", StrategicMap().ClickArrowLowerHalf(RatioArrow()));
    RT_REQUIRE_EQ(initialIdleCount - 1, RatioArrowValue());

    RT_STEP("return the selected unit", StrategicMap().ClickArrowUpperHalf(RatioArrow()));
    RT_REQUIRE_EQ(initialIdleCount, RatioArrowValue());

    RT_REQUIRE(ArmyBookBuildsItsGarrisonPageWithoutDisturbingOwnership());

    g_pMapContextActionManager->DoOwnershipChanges();
    RT_PASS();

    RT_END();
  }

private:
  enum { kUnitCategoryCount = 10, kCityRecordCount = 0x180 };

  short CapitalProvince() const {
    const short activeNation = g_pSimMgr->GetActiveNationId();
    if (g_apTerrainTypeDescriptorTable[activeNation] == 0) {
      return -1;
    }
    const short capitalTile =
        static_cast<short>(g_apTerrainTypeDescriptorTable[activeNation]->homeTileIndex);
    return g_pGlobalMapState->terrainStateTable[capitalTile].cityRecordIndex;
  }

  bool EveryPlacardIsPopulated() const {
    TArmyToolbar* toolbar = StrategicMap().ArmyToolbar();
    if (toolbar == 0) {
      return false;
    }
    for (int category = 0; category < kUnitCategoryCount; ++category) {
      TArmyPlacard* placard = StrategicMap().ArmyPlacard(category);
      if (placard == 0 || placard->glyph90 < 0) {
        return false;
      }
    }
    return true;
  }

  // Only the first actionable arrow is exercised: which categories a random capital garrisons is
  // not this scenario's subject. -1 when the capital's menu offers no selectable unit at all.
  short FirstActionableRatioArrowCategory() const {
    for (short category = 1; category < kUnitCategoryCount; ++category) {
      TNumberedArrowButton* arrow = StrategicMap().ArmyRatioArrow(category);
      if (arrow != 0 && arrow->IsActionable() != 0 && arrow->value84 > 0) {
        return category;
      }
    }
    return -1;
  }

  TNumberedArrowButton* RatioArrow() const {
    return StrategicMap().ArmyRatioArrow(arrowCategory);
  }

  short RatioArrowValue() const {
    TNumberedArrowButton* arrow = RatioArrow();
    return arrow != 0 ? arrow->value84 : -1;
  }

  bool ArmyBookBuildsItsGarrisonPageWithoutDisturbingOwnership() {
    short ownerBefore[kCityRecordCount];
    for (int index = 0; index < kCityRecordCount; ++index) {
      ownerBefore[index] = g_pGlobalMapState->cityScoreTable[index].ownerNationCode00;
    }

    TWindow* book = static_cast<TWindow*>(
        g_pAssetMgr->ResolveTurnEventDialogNodeByMessageContext(kTurnEventGarrison));
    if (book == 0) {
      return false;
    }
    TGarrisonView* garrison = GarrisonPageOf(book);
    if (garrison == 0) {
      return false;
    }
    garrison->StuffValues(capitalProvince);
    const bool populated = garrison->primaryUnitAtlas84 != 0;
    book->Close();
    book->Free();
    if (!populated) {
      return false;
    }

    // MSVC500 predates per-loop `for` scope: a second `int index` in this function would be a
    // redefinition, so the check loop names its own counter.
    for (int verified = 0; verified < kCityRecordCount; ++verified) {
      if (g_pGlobalMapState->cityScoreTable[verified].ownerNationCode00 != ownerBefore[verified]) {
        return false;
      }
    }
    return true;
  }

  // The army book is a standalone TWindow rather than the current main view, so it is resolved
  // here rather than through a MainViewScreen.
  TGarrisonView* GarrisonPageOf(TWindow* book) const {
    TView* page = book->ResolveControlByTag(kControlTagPage);
    return page != 0 && page->IsKindOf(RUNTIME_CLASS(TGarrisonView)) != 0
               ? static_cast<TGarrisonView*>(page)
               : 0;
  }

  short capitalProvince;
  short arrowCategory;
  short initialIdleCount;
};

} // namespace

RUNTIME_TEST_FACTORY(ArmyMenuTestCase, ArmyMenuTest)
