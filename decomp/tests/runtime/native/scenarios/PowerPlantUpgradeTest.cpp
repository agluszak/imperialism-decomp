#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"
#include "RuntimeGameStateCapture.h"
#include "RuntimeRun.h"

#include "game/city/TCity.h"
#include "game/globals/shared_globals.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_screens/TSimMgr.h"

namespace {

// Queue the city power-plant upgrade from a deliberately small economic state.
// Captured input and result GameState values are the differential oracle.
class PowerPlantUpgradeTestCase : public LoadedMapScriptScenario {
protected:
  void Script() override {
    RT_BEGIN();

    RT_DO("queue the power-plant upgrade", QueuePowerPlantUpgrade());
    RT_PASS();

    RT_END();
  }

private:
  RuntimeActionResult QueuePowerPlantUpgrade() {
    const short nationSlot = g_pSimMgr->GetActiveNationId();
    TGreatPower* nation = g_apNationStates[nationSlot];
    if (nation == 0 || nation->city == 0) {
      return RuntimeActionResult::Failure("the loaded player has no city economy state");
    }

    TCity* city = nation->city;
    city->powerPlantUpgradeQueuedFlag04 = 0;
    nation->treasuryValue10 = 10000;

    JSON_Value* inputState = 0;
    if (!BuildRuntimeGameState(RunState(), &inputState)) {
      return RuntimeActionResult::Failure(
          "the semantic power-plant-upgrade input capture is unavailable");
    }
    RunState().SetCapture("power_plant_upgrade_input", inputState);

    city->BuildPowerPlant(1);

    if (city->powerPlantUpgradeQueuedFlag04 == 0 || nation->treasuryValue10 != 5000) {
      return RuntimeActionResult::Failure("retail did not queue the power-plant upgrade");
    }
    return RuntimeActionResult::Success();
  }
};

} // namespace

RUNTIME_TEST_FACTORY(PowerPlantUpgradeTestCase, PowerPlantUpgradeTest)
