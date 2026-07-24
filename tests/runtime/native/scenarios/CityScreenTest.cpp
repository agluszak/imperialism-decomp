#include "RuntimeScenario.h"
#include "screens/StrategicMapDriver.h"

#include "game/city/TCity.h"
#include "game/city_ui/TCityProductionView.h"
#include "game/core/global_data_tables.h"
#include "game/map/TMapUberPicture.h"
#include "game/nation/TGreatPower.h"
#include "game/turn_event_codes.h"
#include "game/ui_core/TView.h"
#include "game/ui_core/TViewMgr.h"
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
  bool UsesEasyDifficulty() const override {
    return true;
  }
  bool RecordsGameFlow() const override {
    return true;
  }
  bool RequiresCityUiSnapshot() const override {
    return true;
  }

  void OnEasyMapReady() override {
    phase = kActivateCityScreen;
    EnterScenarioStep("activating_city_screen", "easy_combined_map_ready_for_city_screen");
    RequestScenarioTick();
  }

  void RunScenarioStep() override {
    if (phase == kActivateCityScreen) {
      ActivateCityScreen();
    } else {
      WaitForCityScreen();
    }
  }

  void ObserveScenarioUiTree(int eventCode, TView* root) override {
    if (eventCode == kTurnEventCityProduction) {
      CaptureCityUiSnapshot(eventCode, root);
    }
  }

private:
  enum Phase { kActivateCityScreen, kWaitForCityScreen };

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
    for (short buildingSlot = 0; buildingSlot < 16; ++buildingSlot) {
      activeNation->city->productionOrderTable1dc[buildingSlot] = 1;
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
    if (!HasCityUiSnapshot()) {
      WaitForScenarioTick("\"city production UI tree was not captured\"");
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
