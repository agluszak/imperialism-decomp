#include "RuntimeScenario.h"
#include "RuntimeUiDriver.h"
#include "screens/StrategicMapDriver.h"

#include "game/city/TCity.h"
#include "game/city/TProductionOrder.h"
#include "game/city/TUnitOrder.h"
#include "game/city_ui/TBuildingView.h"
#include "game/city_ui/TCityProductionView.h"
#include "game/city_ui/TIndustryView.h"
#include "game/city_ui/TUniversityView.h"
#include "game/core/global_data_tables.h"
#include "game/map/TMapUberPicture.h"
#include "game/nation/TGreatPower.h"
#include "game/turn_event_codes.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_core/TWindow.h"
#include "game/ui_core/TNumberText.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_tags_city.h"
#include "game/ui_tags_common.h"
#include "game/ui_widgets/TRailCluster.h"

namespace {

class CityScreenTestCase : public RuntimeScenario {
public:
  CityScreenTestCase() : phase(kActivateCityScreen), activeBuildingSlot(kUniversityBuildingSlot) {}

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

  enum {
    kUniversityBuildingSlot = kTurnEventUniversity - kTurnEventTextileMill,
    kRailyardBuildingSlot = kTurnEventRailyard - kTurnEventTextileMill
  };

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
    EnterScenarioStep("activating_city_building", "activate_university_building_slot");
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
    if (!cityView->ActivateBuildingSlotForRuntimeTest(activeBuildingSlot)) {
      FailScenario("\"city production building hit region is missing or inactive\"");
      return;
    }
    RequestScenarioTick();
  }

  bool HasCorrectNumberTextPresentationState(TNumberText* numberText, short fontSize,
                                             COLORREF textColor) {
    return numberText->field04 == 0 && numberText->field08 != 0 &&
           numberText->stylePayload48 == 0 && numberText->textStyle78.fontFamily == 3 &&
           numberText->textStyle78.fontStyleFlags == 0 &&
           numberText->textStyle78.fontSize == fontSize &&
           numberText->textStyle78.textColor == textColor &&
           numberText->absoluteX == numberText->ownerContext->absoluteX + numberText->ownerLocalX &&
           numberText->absoluteY == numberText->ownerContext->absoluteY + numberText->ownerLocalY &&
           numberText->frameWidth34 > 0 && numberText->frameHeight38 > 0;
  }

  bool ValidateUniversityQuantities(TBuildingView* buildingView) {
    if (buildingView->IsKindOf(RUNTIME_CLASS(TUniversityView)) == 0) {
      FailScenario("\"university building control opened the wrong view class\"");
      return false;
    }
    bool foundLiveRecruitmentCount = false;
    for (short category = 0; category < 9; ++category) {
      if (category == 6 || category == 7) {
        continue;
      }
      TView* recruitmentRow = buildingView->ResolveControlByTag(kControlTagClu0 + category);
      TNumberText* recruitmentQuantity =
          recruitmentRow == 0
              ? 0
              : static_cast<TNumberText*>(recruitmentRow->ResolveControlByTag(kControlTagNumb));
      if (recruitmentQuantity == 0) {
        FailScenario("\"university recruitment count control is missing\"");
        return false;
      }
      if (recruitmentQuantity->textStyle78.textColor != PALETTEINDEX(0xd2)) {
        continue;
      }
      foundLiveRecruitmentCount = true;
      TUnitOrder* order = buildingView->city94->buildOrderSlots[category + 9];
      CString quantityText;
      CString expectedText;
      recruitmentQuantity->GetCurrentText(&quantityText);
      expectedText.Format("%d", order->quantityField04);
      if (quantityText != expectedText || recruitmentQuantity->value != order->quantityField04 ||
          !HasCorrectNumberTextPresentationState(recruitmentQuantity, 10, PALETTEINDEX(0xd2))) {
        FailScenario("\"university recruitment count state does not match its live order\"");
        return false;
      }
    }
    if (!foundLiveRecruitmentCount) {
      FailScenario("\"university has no styled live recruitment count\"");
      return false;
    }
    return true;
  }

  bool ValidateRailyardQuantity(TBuildingView* buildingView) {
    if (buildingView->IsKindOf(RUNTIME_CLASS(TIndustryView)) == 0) {
      FailScenario("\"railyard building control opened the wrong view class\"");
      return false;
    }
    TRailCluster* railCluster =
        static_cast<TRailCluster*>(buildingView->ResolveControlByTag(kSummaryTagRail));
    TNumberText* railQuantity =
        railCluster == 0
            ? 0
            : static_cast<TNumberText*>(railCluster->ResolveControlByTag(kControlTagMove));
    if (railQuantity == 0 || railCluster->selectedMetricOrder == 0) {
      FailScenario("\"railyard production count control is missing\"");
      return false;
    }
    CString quantityText;
    CString expectedText;
    railQuantity->GetCurrentText(&quantityText);
    expectedText.Format("%d", railCluster->selectedMetricOrder->quantityField04);
    if (quantityText != expectedText ||
        railQuantity->value != railCluster->selectedMetricOrder->quantityField04 ||
        !HasCorrectNumberTextPresentationState(railQuantity, 10, PALETTEINDEX(0))) {
      FailScenario("\"railyard production count state does not match its live order\"");
      return false;
    }
    return true;
  }

  void WaitForBuilding() {
    TView* mainView = CurrentMainView();
    if (g_pUiRuntimeContext->currentTurnEventCode != kTurnEventCityProduction || mainView == 0 ||
        mainView->IsKindOf(RUNTIME_CLASS(TCityProductionView)) == 0) {
      FailScenario("\"city production view disappeared after building activation\"");
      return;
    }
    TCityProductionView* cityView = static_cast<TCityProductionView*>(mainView);
    TBuildingView* buildingView = cityView->BuildingViewForRuntimeTest(activeBuildingSlot);
    if (buildingView == 0) {
      WaitForScenarioTick("\"city building control did not open its production view\"");
      return;
    }
    TGreatPower* activeNation = g_apNationStates[g_pSimMgr->GetActiveNationId()];
    if (activeNation == 0 || buildingView->city94 != activeNation->city ||
        buildingView->isEmbeddedPage9C || buildingView->embeddedPageIndex9E != activeBuildingSlot) {
      FailScenario("\"city building control opened the wrong production slot\"");
      return;
    }
    bool quantitiesAreValid = activeBuildingSlot == kUniversityBuildingSlot
                                  ? ValidateUniversityQuantities(buildingView)
                                  : ValidateRailyardQuantity(buildingView);
    if (!quantitiesAreValid) {
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
    if (cityView->BuildingViewForRuntimeTest(activeBuildingSlot) != 0) {
      WaitForScenarioTick("\"native system close did not close the city building window\"");
      return;
    }
    if (activeBuildingSlot == kUniversityBuildingSlot) {
      activeBuildingSlot = kRailyardBuildingSlot;
      phase = kActivateBuilding;
      EnterScenarioStep("activating_railyard_building", "activate_railyard_building_slot");
      RequestScenarioTick();
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
  short activeBuildingSlot;
};

CityScreenTestCase g_test;

} // namespace

RuntimeTestCase* CityScreenTest() {
  return &g_test;
}
