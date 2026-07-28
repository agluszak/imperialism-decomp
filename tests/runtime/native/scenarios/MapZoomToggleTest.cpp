#include "RuntimeScenario.h"
#include "flows/RandomGameFlow.h"
#include "RuntimeUiDriver.h"

#include "game/core/global_data_tables.h"
#include "game/map/TMapUberPicture.h"
#include "game/map_ui/TMapDialog.h"
#include "game/navy_ui/TOceanDialog.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_widgets/TWorldView.h"
#include "game/ui_tags_map.h"
#include "game/globals/view_registries.h"

namespace {

class MapZoomToggleTestCase : public RandomGameScenario {
public:
  MapZoomToggleTestCase() : phase(kActivateZoomOut), toggleCycles(0) {}
  bool RecordsGameFlow() const override {
    return true;
  }

  void OnCombinedMapReady() override {
    phase = kActivateZoomOut;
    EnterScenarioStep("activating_map_zoom_out", "combined_map_ready_for_zoom_toggle");
    RequestScenarioTick();
  }

  void TickScenario() override {
    if (phase == kActivateZoomOut) {
      ActivateZoomOut();
    } else if (phase == kVerifyZoomOut) {
      VerifyZoomOut();
    } else {
      VerifyZoomIn();
    }
  }

private:
  enum Phase { kActivateZoomOut, kVerifyZoomOut, kVerifyZoomIn };

  void ActivateZoomOut() {
    TView* mainView = CurrentMainView();
    TMapUberPicture* mapView =
        mainView != 0 && mainView->IsKindOf(RUNTIME_CLASS(TMapUberPicture)) != 0
            ? static_cast<TMapUberPicture*>(mainView)
            : 0;
    TView* zoom = mapView != 0 ? mapView->ResolveControlByTag(kControlTagZmOt) : 0;
    if (g_pUiRuntimeContext->currentTurnEventCode != 0x7dd || mapView == 0 || zoom == 0 ||
        !g_ModalViewStack.IsEmpty()) {
      FailScenario("\"combined-map zoom-out control is missing or the map is not idle\"");
      return;
    }
    phase = kVerifyZoomOut;
    EnterScenarioStep("verifying_map_zoom_out", "click_map_zoom_out");
    if (!RuntimeUiDriver::ClickViewThroughNativeMessages(zoom)) {
      FailScenario("\"combined-map zoom-out control has no native host\"");
      return;
    }
    RequestScenarioTick();
  }

  void VerifyZoomOut() {
    TMapUberPicture* mapView = g_pUiRuntimeContext->mapUberPictureF0;
    if (mapView == 0 || mapView->ResolveControlByTag(kControlTagZmIn) == 0 ||
        mapView->invalidationFlag94 != 0 || mapView->subviewAc != mapView->goodGoldTagControlA4) {
      FailScenario("\"zoom-out release did not enter the alternate map mode\"");
      return;
    }
    phase = kVerifyZoomIn;
    EnterScenarioStep("verifying_map_zoom_in", "click_map_zoom_in");
    if (!RuntimeUiDriver::ClickViewThroughNativeMessages(
            mapView->ResolveControlByTag(kControlTagZmIn))) {
      FailScenario("\"combined-map zoom-in control has no native host\"");
      return;
    }
    RequestScenarioTick();
  }

  void VerifyZoomIn() {
    TMapUberPicture* mapView = g_pUiRuntimeContext->mapUberPictureF0;
    if (mapView == 0 || mapView->ResolveControlByTag(kControlTagZmOt) == 0 ||
        mapView->invalidationFlag94 == 0 || mapView->subviewAc != mapView->subview2A8) {
      FailScenario("\"zoom-in release did not restore the strategic map mode\"");
      return;
    }
    ++toggleCycles;
    if (toggleCycles < 2) {
      phase = kActivateZoomOut;
      EnterScenarioStep("activating_map_zoom_out_again", "repeat_map_zoom_toggle");
      RequestScenarioTick();
      return;
    }
    TMapDialog* mapDialog = mapView->subview2A8;
    mapDialog->SetMapDialogCellCoordinatesAndRefresh(10, 10, 0);
    int previousX = mapDialog->viewportOrigin60.x;
    mapView->Scroll(4);
    if (mapDialog->viewportOrigin60.x == previousX) {
      FailScenario("\"combined-map scrolling stopped after repeated zoom toggles\"");
      return;
    }
    Pass();
  }

  Phase phase;
  short toggleCycles;
};

MapZoomToggleTestCase g_test;

} // namespace

RuntimeTestCase* MapZoomToggleTest() {
  return &g_test;
}
