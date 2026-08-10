#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"
#include "JsonObject.h"
#include "RuntimeDifferentialCapture.h"
#include "RuntimeGameStateCapture.h"
#include "RuntimeRun.h"

#include "game/city/TCity.h"
#include "game/globals/shared_globals.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_screens/TSimMgr.h"

namespace {

// Queue the city power-plant upgrade from a deliberately small economic state.
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

    JsonObject caseCapture;
    caseCapture.Set("nation", static_cast<int>(nationSlot));
    caseCapture.Set("enabled", true);

    RuntimeDifferentialCapture capture(RunState());
    RuntimeActionResult started = capture.Begin(caseCapture.Release());
    if (!started.Succeeded()) {
      return started;
    }

    city->BuildPowerPlant(1);
    return capture.Finish();
  }
};

} // namespace

RUNTIME_TEST_FACTORY(PowerPlantUpgradeTestCase, PowerPlantUpgradeTest)
