#include "RuntimeScenario.h"

#include "game/city/TCity.h"
#include "game/city/TUnitOrder.h"
#include "game/city_ui/TCivMgr.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/map/TMapMgr.h"
#include "game/map/TMapUberPicture.h"
#include "game/military/TCivUnit.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_core/TSortedList.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_screens/TSimMgr.h"

namespace {

class CivilianRecruitmentTestCase : public RuntimeScenario {
public:
  CivilianRecruitmentTestCase() : spawnedCivilian(0), selectionTicks(0) {}

  const char* Name() const override {
    return "civilian_recruitment_selection";
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

  void OnEasyMapReady() override {
    spawnedCivilian = 0;
    selectionTicks = 0;
    EnterScenarioStep("recruiting_civilian", "produce_and_select_recruited_civilian");
    RequestScenarioTick();
  }

  void RunScenarioStep() override {
    if (spawnedCivilian == 0) {
      RecruitCivilian();
      return;
    }

    ++selectionTicks;
    if (selectionTicks < 20) {
      RequestScenarioTick();
      return;
    }
    Pass();
  }

private:
  enum { kGlobalMapTileCount = 0x1950 };

  void RecruitCivilian() {
    if (ScenarioPhaseTicks() < 60) {
      RequestScenarioTick();
      return;
    }
    TView* mainView = CurrentMainView();
    if (g_pUiRuntimeContext->currentTurnEventCode != kTurnEventStrategicMap || mainView == 0 ||
        mainView->IsKindOf(RUNTIME_CLASS(TMapUberPicture)) == 0) {
      WaitForScenarioTick("\"combined map was not idle before civilian recruitment\"");
      return;
    }

    short nationSlot = g_pSimMgr->GetActiveNationId();
    TGreatPower* nation = g_apNationStates[nationSlot];
    if (nation == 0 || nation->city == 0 || nation->trackedObjectList == 0) {
      FailScenario("\"active nation has no civilian recruitment state\"");
      return;
    }

    int oldCount = nation->trackedObjectList->GetCount();
    TUnitOrder recruitOrder;
    recruitOrder.IUnitOrder(nation->city, 0, 0, 0, -1, 0, 0, kLowSkillWorkforceMode, 0);
    recruitOrder.quantityField04 = 1;
    recruitOrder.Produce();

    if (nation->trackedObjectList->GetCount() != oldCount + 1) {
      FailScenario("\"civilian production did not register exactly one recruit\"");
      return;
    }
    spawnedCivilian = static_cast<TCivUnit*>(
        nation->trackedObjectList->GetEntryByOrdinal(nation->trackedObjectList->GetCount()));
    if (spawnedCivilian == 0 || spawnedCivilian->tileIndex06 < 0 ||
        spawnedCivilian->tileIndex06 >= kGlobalMapTileCount) {
      FailScenario("\"recruited civilian has an invalid strategic-map tile\"");
      return;
    }

    signed char ownerTag =
        g_pGlobalMapState->terrainStateTable[spawnedCivilian->tileIndex06].ownerNationTag04;
    if (ownerTag < 0 || ownerTag >= kTerrainTypeDescriptorTableCount ||
        g_apTerrainTypeDescriptorTable[ownerTag] == 0) {
      FailScenario("\"recruited civilian tile has no terrain-owner descriptor\"");
      return;
    }

    g_pSelectedCivilianOrderState->SetActiveCivilianSelection(spawnedCivilian, 1);
    EnterScenarioStep("waiting_after_civilian_selection",
                      "selected_recruited_civilian_and_refreshed_command_panel");
    RequestScenarioTick();
  }

  TCivUnit* spawnedCivilian;
  unsigned long selectionTicks;
};

CivilianRecruitmentTestCase g_test;

} // namespace

RuntimeTestCase* CivilianRecruitmentTest() {
  return &g_test;
}
