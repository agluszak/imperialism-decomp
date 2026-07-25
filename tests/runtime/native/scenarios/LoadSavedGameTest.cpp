#include "RuntimeScenario.h"

#include "game/assets/TAssetMgr.h"
#include "game/core/global_data_tables.h"
#include "game/map/TMapMgr.h"
#include "game/map/TMapUberPicture.h"
#include "game/map_ui/TMapDialog.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_tags_map.h"

namespace {

class LoadSavedGameTestCase : public RuntimeScenario {
public:
  LoadSavedGameTestCase() : phase(kLoadFixture) {}

  const char* Name() const override {
    return "load_saved_game";
  }
  bool RequiresFixture() const override {
    return true;
  }
  bool RecordsGameFlow() const override {
    return true;
  }

  void OnManagersReady() override {
    phase = kLoadFixture;
    EnterScenarioStep("loading_saved_game", "open_saved_game_fixture");
    RequestScenarioTick();
  }

  void RunScenarioStep() override {
    if (phase == kLoadFixture) {
      LoadFixture();
    } else {
      WaitForLoadedMap();
    }
  }

private:
  enum Phase { kLoadFixture, kWaitForLoadedMap };

  void LoadFixture() {
    CString fixturePath(FixturePath());
    if (g_pUiViewManager->OpenMainDocumentFromPathAndMarkLoaded(fixturePath) == 0) {
      FailScenario("\"saved-game fixture failed to open through the document path\"");
      return;
    }
    phase = kWaitForLoadedMap;
    EnterScenarioStep("waiting_for_loaded_map", "opened_saved_game_fixture");
    RequestScenarioTick();
  }

  void WaitForLoadedMap() {
    if (AdvanceNewspaperIfNeeded()) {
      return;
    }
    TView* mainView = CurrentMainView();
    if (g_pUiRuntimeContext->currentTurnEventCode != 0x7dd || mainView == 0 ||
        mainView->IsKindOf(RUNTIME_CLASS(TMapUberPicture)) == 0 || !g_ModalViewStack.IsEmpty()) {
      WaitForScenarioTick("\"loaded game did not reach the combined strategic map\"");
      return;
    }
    if (g_pGlobalMapState == 0) {
      FailScenario("\"loaded game has no global map state\"");
      return;
    }
    short activeNation = g_pSimMgr->activeNationSlot;
    if (activeNation < 0 || activeNation >= 7) {
      FailScenario("\"loaded game has no valid active nation\"");
      return;
    }
    SetSelectedNation(activeNation);
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
      WaitForScenarioTick("\"loaded strategic map never built its mini-map\"");
      return;
    }
    if (mapView->ResolveControlByTag(kControlTagSend) == 0) {
      WaitForScenarioTick("\"loaded strategic map never built its end-turn control\"");
      return;
    }
    TMapDialog* mapDialog = mapView->subview2A8;
    if (mapDialog == 0) {
      FailScenario("\"loaded strategic map has no scrollable map dialog\"");
      return;
    }
    mapDialog->SetMapDialogCellCoordinatesAndRefresh(2, 2, 0);
    if (mapDialog->viewportOrigin60.x < 0 || mapDialog->viewportOrigin60.y < 0 ||
        (mapDialog->viewportOrigin60.x & 0x3f) != 0) {
      FailScenario("\"loaded map viewport did not land on a tile-aligned position\"");
      return;
    }
    Pass();
  }

  Phase phase;
};

class UnknownRuntimeTestCase : public RuntimeScenario {
public:
  const char* Name() const override {
    return "unknown";
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
