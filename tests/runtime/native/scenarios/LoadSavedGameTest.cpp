#include "RuntimeScenario.h"
#include "flows/LoadGameFlow.h"

#include "game/assets/TAssetMgr.h"
#include "game/core/global_data_tables.h"
#include "game/map/TMapMgr.h"
#include "game/map/TMapUberPicture.h"
#include "game/map_ui/TMapDialog.h"
#include "game/nation/TGreatPower.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_tags_map.h"

namespace {

class LoadSavedGameTestCase : public LoadGameScenario {
public:
  bool RequiresFixture() const override {
    return true;
  }
  bool RecordsGameFlow() const override {
    return true;
  }

  void OnCombinedMapReady() override {
    EnterScenarioStep("verifying_loaded_map", "loaded_map_ready");
    ContinueAfterAction();
  }

  void AdvanceScenario() override {
    VerifyLoadedMap();
  }

private:
  void VerifyLoadedMap() {
    TView* mainView = CurrentMainView();
    if (g_pSimMgr->economicTurn < 0) {
      FailScenario("\"loaded game has a negative economic turn\"");
      return;
    }
    // The map view can exist a tick before its children do, so these wait rather than
    // failing outright -- a genuinely absent child still fails, just as a timeout on the
    // specific condition instead of a spurious first-tick failure. The two are reported
    // separately because they are built by different paths.
    TMapUberPicture* mapView = static_cast<TMapUberPicture*>(mainView);
    if (mapView->miniMapViewC0 == 0) {
      AwaitUiChange("\"loaded strategic map never built its mini-map\"");
      return;
    }
    if (mapView->ResolveControlByTag(kControlTagSend) == 0) {
      AwaitUiChange("\"loaded strategic map never built its end-turn control\"");
      return;
    }
    TMapDialog* mapDialog = mapView->subview2A8;
    if (mapDialog == 0) {
      FailScenario("\"loaded strategic map has no scrollable map dialog\"");
      return;
    }
    mapDialog->SetMapDialogCellCoordinatesAndRefresh(2, 2, 0);
    if (mapDialog->viewportOrigin.x < 0 || mapDialog->viewportOrigin.y < 0 ||
        (mapDialog->viewportOrigin.x & 0x3f) != 0) {
      FailScenario("\"loaded map viewport did not land on a tile-aligned position\"");
      return;
    }
    TGreatPower* player = g_apNationStates[g_pSimMgr->GetActiveNationId()];
    for (short resource = 0; resource < 0x11; ++resource) {
      bool sawPurchase = false;
      bool sawSale = false;
      short entryCount = player->GetTrackedSlotEntryCountLow(resource);
      for (short ordinal = 1; ordinal <= entryCount; ++ordinal) {
        short kind;
        short value;
        short targetNation;
        int payload;
        player->ReadTrackedSlotEntryFields(resource, ordinal, &kind, &value, &targetNation,
                                           &payload);
        sawPurchase = sawPurchase || kind == kTrackedSlotOfferEntry;
        sawSale = sawSale || kind == kTrackedSlotAcceptEntry;
      }
      if (sawPurchase && sawSale) {
        char failure[256];
        wsprintfA(failure,
                  "\"loaded player has mixed trade history for resource %d: current %d remembered "
                  "%d entries %d\"",
                  resource, player->itemPotentials[resource],
                  player->rememberedTradeOffersByResource[resource], entryCount);
        FailScenario(failure);
        return;
      }
    }
    Pass();
  }
};

class UnknownRuntimeTestCase : public RuntimeScenario {
public:
  void OnManagersReady() override {
    FailScenario("\"unknown compiled runtime test\"");
  }
};

LoadSavedGameTestCase g_test;
UnknownRuntimeTestCase g_unknownTest;

} // namespace

RuntimeTestCase* LoadSavedGameTest() {
  return &g_test;
}

RuntimeTestCase* UnknownRuntimeTest() {
  return &g_unknownTest;
}
