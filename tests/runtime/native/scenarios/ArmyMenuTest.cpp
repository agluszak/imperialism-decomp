#include "RuntimeScenario.h"
#include "flows/RandomGameFlow.h"

#include "game/core/global_data_tables.h"
#include "game/map/TMapMgr.h"
#include "game/map/TMapUberPicture.h"
#include "game/map_ui/TMapDialog.h"
#include "game/military/TArmyMgr.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_tags_widgets.h"
#include "game/ui_widgets/TArmyPlacard.h"
#include "game/ui_widgets/TArmyToolbar.h"

namespace {

class ArmyMenuTestCase : public RandomGameScenario {
public:
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
    Pass();
  }
};

ArmyMenuTestCase g_test;

} // namespace

RuntimeTestCase* ArmyMenuTest() {
  return &g_test;
}
