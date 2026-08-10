#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"
#include "JsonObject.h"
#include "RuntimeDifferentialCapture.h"
#include "RuntimeGameStateCapture.h"
#include "RuntimeRun.h"

#include "game/city_ui/TCityInteriorMinister.h"
#include "game/globals/shared_globals.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_screens/TSimMgr.h"

namespace {

// Allocate the active nation's transport capacity to its city-resource needs.
class TransportNeedAllocationTestCase : public LoadedMapScriptScenario {
protected:
  void Script() override {
    RT_BEGIN();

    RT_DO("allocate city transport needs", AllocateTransportNeeds());
    RT_PASS();

    RT_END();
  }

private:
  RuntimeActionResult AllocateTransportNeeds() {
    const short nationSlot = g_pSimMgr->GetActiveNationId();
    TGreatPower* nation = g_apNationStates[nationSlot];
    if (nation == 0 || nation->interiorMinister == 0) {
      return RuntimeActionResult::Failure("the loaded player has no interior minister");
    }

    JsonObject caseCapture;
    caseCapture.Set("nation", static_cast<int>(nationSlot));

    RuntimeDifferentialCapture capture(RunState());
    RuntimeActionResult started = capture.Begin(caseCapture.Release());
    if (!started.Succeeded()) {
      return started;
    }

    nation->interiorMinister->SetCityPolicies();
    return capture.Finish();
  }
};

} // namespace

RUNTIME_TEST_FACTORY(TransportNeedAllocationTestCase, TransportNeedAllocationTest)
