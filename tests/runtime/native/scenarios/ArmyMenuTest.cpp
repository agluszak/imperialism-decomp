#include "RuntimeScenario.h"
#include "flows/RandomGameFlow.h"

#include "game/globals/global_types.h"
#include "game/globals/assets_globals.h"
#include "game/globals/game_session_globals.h"
#include "game/globals/military_globals.h"
#include "game/globals/nation_globals.h"
#include "game/globals/ui_core_globals.h"
#include "game/assets/TAssetMgr.h"
#include "game/city_ui/TCountry.h"
#include "game/map/TMapMgr.h"
#include "game/map/TMapUberPicture.h"
#include "game/map_ui/TMapDialog.h"
#include "game/military/TArmyMgr.h"
#include "game/military/TGarrisonView.h"
#include "game/ui_core/TWindow.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/turn_event_codes.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_widgets.h"
#include "game/ui_widgets/TArmyPlacard.h"
#include "game/ui_widgets/TArmyToolbar.h"
#include "game/ui_widgets/TNumberedArrowButton.h"
#include "game/globals/view_registries.h"

namespace {

class ArmyMenuTestCase : public RandomGameScenario {
public:
  int DifficultyLevel() const override {
    return 1;
  }

  void OnCombinedMapReady() override {
    TMapUberPicture* mapView = g_pViewMgr->mapUberPictureF0;
    short activeNation = g_pSimMgr->GetActiveNationId();
    short capitalTile =
        static_cast<short>(g_apTerrainTypeDescriptorTable[activeNation]->homeTileIndex);
    short capitalProvince = g_pGlobalMapState->terrainStateTable[capitalTile].cityRecordIndex;
    if (mapView == 0 || mapView->subview2A8 == 0 || capitalProvince == -1) {
      FailScenario("\"combined map has no selectable capital province\"");
      return;
    }

    mapView->SetMapInteractionMode(1);
    g_pMapContextActionManager->SetActiveProvinceSelection(capitalProvince);
    if (mapView->activeUnitCategoryIndex96 != 1 ||
        g_pMapContextActionManager->pendingMapActionIndex != capitalProvince) {
      FailScenario("\"capital click did not activate the army menu\"");
      return;
    }

    TArmyToolbar* toolbar = static_cast<TArmyToolbar*>(mapView->categoryPages[1]);
    for (int category = 0; category < 10; ++category) {
      TArmyPlacard* placard = static_cast<TArmyPlacard*>(
          toolbar->ResolveControlByTag(kControlTagArmyPlacardFirst + category));
      if (placard == 0 || placard->glyph90 < 0) {
        FailScenario("\"army menu placards were not populated after the capital click\"");
        return;
      }
    }

    for (int arrowCategory = 1; arrowCategory < 10; ++arrowCategory) {
      TNumberedArrowButton* arrow = static_cast<TNumberedArrowButton*>(
          toolbar->ResolveControlByTag(kControlTagArmyRatioFirst + arrowCategory));
      if (arrow == 0 || arrow->IsActionable() == 0 || arrow->value84 <= 0) {
        continue;
      }

      short initialIdleCount = arrow->value84;
      CRect bounds;
      arrow->QueryContentBounds(&bounds);
      CPoint lowerHalf(bounds.left + 1, bounds.top + arrow->frameHeight38 * 3 / 4);
      arrow->TrackMouse(kTrackPhaseBegin, lowerHalf, lowerHalf, lowerHalf, 1);
      arrow->TrackMouse(kTrackPhaseEnd, lowerHalf, lowerHalf, lowerHalf, 1);
      if (arrow->value84 != initialIdleCount - 1) {
        FailScenario("\"army menu lower arrow did not select an idle unit\"");
        return;
      }

      CPoint upperHalf(bounds.left + 1, bounds.top + arrow->frameHeight38 / 4);
      arrow->TrackMouse(kTrackPhaseBegin, upperHalf, upperHalf, upperHalf, 1);
      arrow->TrackMouse(kTrackPhaseEnd, upperHalf, upperHalf, upperHalf, 1);
      if (arrow->value84 != initialIdleCount) {
        FailScenario("\"army menu upper arrow did not return the selected unit\"");
        return;
      }
      VerifyArmyBookAndOwnership(capitalProvince);
      return;
    }
    FailScenario("\"capital army menu has no actionable unit-selection arrow\"");
    return;
  }

private:
  void VerifyArmyBookAndOwnership(short capitalProvince) {
    short ownerBefore[0x180];
    for (int cityRecordIndex = 0; cityRecordIndex < 0x180; ++cityRecordIndex) {
      ownerBefore[cityRecordIndex] =
          g_pGlobalMapState->cityScoreTable[cityRecordIndex].ownerNationCode00;
    }

    TWindow* book = static_cast<TWindow*>(
        g_pAssetMgr->ResolveTurnEventDialogNodeByMessageContext(kTurnEventGarrison));
    TView* page = book == 0 ? 0 : book->ResolveControlByTag(kControlTagPage);
    if (page == 0 || page->IsKindOf(RUNTIME_CLASS(TGarrisonView)) == 0) {
      FailScenario("\"capital army book did not construct its garrison page\"");
      return;
    }
    TGarrisonView* garrison = static_cast<TGarrisonView*>(page);
    garrison->StuffValues(capitalProvince);
    if (garrison->primaryUnitAtlas84 == 0) {
      FailScenario("\"capital army book did not populate its unit sprite page\"");
      return;
    }
    book->Close();
    book->Free();

    for (int verifiedCityRecordIndex = 0; verifiedCityRecordIndex < 0x180;
         ++verifiedCityRecordIndex) {
      short owner = g_pGlobalMapState->cityScoreTable[verifiedCityRecordIndex].ownerNationCode00;
      if (owner != ownerBefore[verifiedCityRecordIndex]) {
        FailScenario("\"capital army book corrupted map ownership state\"");
        return;
      }
    }
    g_pMapContextActionManager->DoOwnershipChanges();
    Pass();
  }
};

ArmyMenuTestCase g_test;

} // namespace

RuntimeTestCase* ArmyMenuTest() {
  return &g_test;
}
