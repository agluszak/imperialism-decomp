#include "RuntimeScenario.h"
#include "RuntimeUiDriver.h"
#include "screens/StrategicMapDriver.h"

#include "game/city/TCity.h"
#include "game/city_ui/TBuildingView.h"
#include "game/city_ui/TCityProductionView.h"
#include "game/core/global_data_tables.h"
#include "game/map/TMapUberPicture.h"
#include "game/nation/TGreatPower.h"
#include "game/turn_event_codes.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_core/TWindow.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_tags_city.h"

namespace {

class CityScreenTestCase : public RuntimeScenario {
public:
  CityScreenTestCase() : phase(kActivateCityScreen) {}

  const char* Name() const override {
    return "city_screen_opens";
  }
  bool UsesRandomGameFlow() const override {
    return true;
  }
  int DifficultyLevel() const override {
    return 1;
  }
  bool RecordsGameFlow() const override {
    return true;
  }
  bool RequiresScenarioUiSnapshot() const override {
    return true;
  }

  void OnMapReadyWithoutCapitalSelection() override {
    phase = kActivateCityScreen;
    EnterScenarioStep("activating_city_screen", "easy_combined_map_ready_for_city_screen");
    RequestScenarioTick();
  }

  void RunScenarioStep() override {
    if (phase == kActivateCityScreen) {
      ActivateCityScreen();
    } else if (phase == kWaitForCityScreen) {
      WaitForCityScreen();
    } else if (phase == kActivateBuilding) {
      ActivateBuilding();
    } else if (phase == kWaitForBuilding) {
      WaitForBuilding();
    } else if (phase == kWaitForBuildingClose) {
      WaitForBuildingClose();
    } else if (phase == kReturnToMap) {
      ReturnToMap();
    } else {
      WaitForMap();
    }
  }

  void ObserveScenarioUiTree(int eventCode, TView* root) override {
    if (eventCode == kTurnEventCityProduction) {
      CaptureScenarioUiSnapshot(eventCode, root);
    }
  }

private:
  enum Phase {
    kActivateCityScreen,
    kWaitForCityScreen,
    kActivateBuilding,
    kWaitForBuilding,
    kWaitForBuildingClose,
    kReturnToMap,
    kWaitForMap
  };

  enum { kInteractiveBuildingSlot = 6 };

  void ActivateCityScreen() {
    if (ScenarioPhaseTicks() < 60) {
      RequestScenarioTick();
      return;
    }
    TView* mainView = CurrentMainView();
    if (g_pUiRuntimeContext->currentTurnEventCode != kTurnEventStrategicMap || mainView == 0 ||
        mainView->IsKindOf(RUNTIME_CLASS(TMapUberPicture)) == 0 || !g_ModalViewStack.IsEmpty()) {
      WaitForScenarioTick("\"combined map was not idle before opening the city screen\"");
      return;
    }
    TGreatPower* activeNation = g_apNationStates[g_pSimMgr->GetActiveNationId()];
    if (activeNation == 0 || activeNation->city == 0) {
      FailScenario("\"active nation has no city state before opening the city screen\"");
      return;
    }
    // The deterministic Easy fixture can restore the oil-refinery window while its
    // capacity is still zero. Seed only that proven-invalid slot; replacing the
    // complete table makes the first city paint synchronously load every building
    // and no longer represents the game's generated state.
    activeNation->city->productionOrderTable1dc[6] = 1;
    phase = kWaitForCityScreen;
    EnterScenarioStep("waiting_for_city_screen", "activate_city_toolbar_control");
    StrategicMapDriver map(mainView);
    if (!map.ActivateCity()) {
      FailScenario("\"city toolbar control is missing or disabled\"");
      return;
    }
    RequestScenarioTick();
  }

  void WaitForCityScreen() {
    TView* mainView = CurrentMainView();
    if (g_pUiRuntimeContext->currentTurnEventCode != kTurnEventCityProduction || mainView == 0 ||
        mainView->IsKindOf(RUNTIME_CLASS(TCityProductionView)) == 0) {
      WaitForScenarioTick("\"city toolbar action did not activate the city production view\"");
      return;
    }
    if (!g_ModalViewStack.IsEmpty()) {
      RecordUnexpectedModalView(static_cast<TView*>(g_ModalViewStack.GetHead()));
      FailScenario("\"city toolbar action opened an unexpected modal\"");
      return;
    }
    TCityProductionView* cityView = static_cast<TCityProductionView*>(mainView);
    if (cityView->ResolveControlByTag(kControlTagLabP) == 0 ||
        cityView->ResolveControlByTag(kControlTagMeat) == 0) {
      FailScenario("\"city production view is missing required production controls\"");
      return;
    }
    if (!HasScenarioUiSnapshot()) {
      WaitForScenarioTick("\"city production UI tree was not captured\"");
      return;
    }
    // Keep the production view live long enough to expose repaint/invalidation loops.
    // A tick-only wait completes in a few milliseconds because the driver posts its
    // own messages, which previously let TPlacard::Draw self-invalidation escape.
    if (ScenarioPhaseTicks() < 20 || ScenarioPhaseElapsedMs() < 1000) {
      RequestScenarioTick();
      return;
    }
    phase = kActivateBuilding;
    EnterScenarioStep("activating_city_building", "activate_oil_refinery_building_slot");
    RequestScenarioTick();
  }

  void ActivateBuilding() {
    TView* mainView = CurrentMainView();
    if (g_pUiRuntimeContext->currentTurnEventCode != kTurnEventCityProduction || mainView == 0 ||
        mainView->IsKindOf(RUNTIME_CLASS(TCityProductionView)) == 0) {
      FailScenario("\"city production view disappeared before building activation\"");
      return;
    }
    TCityProductionView* cityView = static_cast<TCityProductionView*>(mainView);
    phase = kWaitForBuilding;
    EnterScenarioStep("waiting_for_city_building", "activate_city_building_hit_region");
    if (!cityView->ActivateBuildingSlotForRuntimeTest(kInteractiveBuildingSlot)) {
      FailScenario("\"oil-refinery building hit region is missing or inactive\"");
      return;
    }
    RequestScenarioTick();
  }

  void WaitForBuilding() {
    TView* mainView = CurrentMainView();
    if (g_pUiRuntimeContext->currentTurnEventCode != kTurnEventCityProduction || mainView == 0 ||
        mainView->IsKindOf(RUNTIME_CLASS(TCityProductionView)) == 0) {
      FailScenario("\"city production view disappeared after building activation\"");
      return;
    }
    TCityProductionView* cityView = static_cast<TCityProductionView*>(mainView);
    TBuildingView* buildingView = cityView->BuildingViewForRuntimeTest(kInteractiveBuildingSlot);
    if (buildingView == 0) {
      WaitForScenarioTick("\"oil-refinery building control did not open its production view\"");
      return;
    }
    TGreatPower* activeNation = g_apNationStates[g_pSimMgr->GetActiveNationId()];
    if (activeNation == 0 || buildingView->city94 != activeNation->city ||
        buildingView->isEmbeddedPage9C ||
        buildingView->embeddedPageIndex9E != kInteractiveBuildingSlot) {
      FailScenario("\"city building control opened the wrong production slot\"");
      return;
    }
    TWindow* buildingWindow = buildingView->GetWindow();
    if (buildingWindow == 0 || buildingWindow->nativeWindow50 == 0 ||
        buildingWindow->nativeWindow50->m_hWnd == 0) {
      FailScenario("\"city building production view has no native window\"");
      return;
    }
    HWND buildingHwnd = buildingWindow->nativeWindow50->m_hWnd;
    LONG style = GetWindowLongA(buildingHwnd, GWL_STYLE);
    LONG extendedStyle = GetWindowLongA(buildingHwnd, GWL_EXSTYLE);
    if (buildingWindow->windowStyleType != 0x1f40 || buildingWindow->windowFlags != 0x80 ||
        !buildingWindow->useCaptionedFrameFlag6d || !buildingWindow->topmostFlag70 ||
        (style & (WS_CAPTION | WS_SYSMENU)) != (WS_CAPTION | WS_SYSMENU) ||
        (extendedStyle & WS_EX_TOOLWINDOW) == 0) {
      CString failure;
      failure.Format("\"city building native window is missing its retail floating frame: "
                     "descriptor_style=0x%x descriptor_flags=0x%x caption=%d topmost=%d "
                     "style=0x%lx exstyle=0x%lx\"",
                     buildingWindow->windowStyleType, buildingWindow->windowFlags,
                     buildingWindow->useCaptionedFrameFlag6d, buildingWindow->topmostFlag70, style,
                     extendedStyle);
      FailScenario(failure);
      return;
    }
    CWnd* mainWindow = AfxGetMainWnd();
    if (mainWindow == 0 || GetParent(buildingHwnd) != mainWindow->m_hWnd) {
      FailScenario("\"city building native window is not owned by the main game window\"");
      return;
    }
    RECT windowRect;
    POINT clientOrigin;
    clientOrigin.x = 0;
    clientOrigin.y = 0;
    if (!GetWindowRect(buildingHwnd, &windowRect) || !ClientToScreen(buildingHwnd, &clientOrigin) ||
        clientOrigin.y <= windowRect.top) {
      FailScenario("\"city building native window has no non-client caption area\"");
      return;
    }
    POINT captionPoint;
    captionPoint.x = (windowRect.left + windowRect.right) / 2;
    captionPoint.y = (windowRect.top + clientOrigin.y) / 2;
    LPARAM hitPoint =
        MAKELPARAM(static_cast<short>(captionPoint.x), static_cast<short>(captionPoint.y));
    if (SendMessageA(buildingHwnd, WM_NCHITTEST, 0, hitPoint) != HTCAPTION) {
      FailScenario("\"city building native frame does not expose a movable caption\"");
      return;
    }
    if (ScenarioPhaseTicks() < 5) {
      RequestScenarioTick();
      return;
    }
    phase = kWaitForBuildingClose;
    EnterScenarioStep("closing_city_building", "activate_native_system_close");
    SendMessageA(buildingHwnd, WM_SYSCOMMAND, SC_CLOSE, 0);
    RequestScenarioTick();
  }

  void WaitForBuildingClose() {
    TView* mainView = CurrentMainView();
    if (g_pUiRuntimeContext->currentTurnEventCode != kTurnEventCityProduction || mainView == 0 ||
        mainView->IsKindOf(RUNTIME_CLASS(TCityProductionView)) == 0) {
      FailScenario("\"city production view disappeared while closing a building window\"");
      return;
    }
    TCityProductionView* cityView = static_cast<TCityProductionView*>(mainView);
    if (cityView->BuildingViewForRuntimeTest(kInteractiveBuildingSlot) != 0) {
      WaitForScenarioTick("\"native system close did not close the city building window\"");
      return;
    }
    phase = kReturnToMap;
    EnterScenarioStep("returning_to_strategic_map", "click_city_end_control");
    RequestScenarioTick();
  }

  void ReturnToMap() {
    TView* mainView = CurrentMainView();
    if (mainView == 0 || mainView->IsKindOf(RUNTIME_CLASS(TCityProductionView)) == 0) {
      FailScenario("\"city production view disappeared before back navigation\"");
      return;
    }
    phase = kWaitForMap;
    EnterScenarioStep("waiting_for_strategic_map_return", "activate_city_end_control");
    if (!RuntimeUiDriver::ClickControl(mainView, kControlTagEnd)) {
      FailScenario("\"city back control is missing or cannot receive native input\"");
      return;
    }
    RequestScenarioTick();
  }

  void WaitForMap() {
    TView* mainView = CurrentMainView();
    if (g_pUiRuntimeContext->currentTurnEventCode != kTurnEventStrategicMap || mainView == 0 ||
        mainView->IsKindOf(RUNTIME_CLASS(TMapUberPicture)) == 0) {
      WaitForScenarioTick("\"city back control did not restore the strategic map\"");
      return;
    }
    if (!g_ModalViewStack.IsEmpty()) {
      RecordUnexpectedModalView(static_cast<TView*>(g_ModalViewStack.GetHead()));
      FailScenario("\"city back navigation left an unexpected modal\"");
      return;
    }
    if (ScenarioPhaseTicks() < 20) {
      RequestScenarioTick();
      return;
    }
    Pass();
  }

  Phase phase;
};

CityScreenTestCase g_test;

} // namespace

RuntimeTestCase* CityScreenTest() {
  return &g_test;
}
