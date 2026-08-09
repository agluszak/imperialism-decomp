#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"
#include "JsonObject.h"
#include "RuntimeGameStateCapture.h"
#include "RuntimeRun.h"
#include "RuntimeSemanticCapture.h"

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

    if (!CaptureGameState(RunState(), "before")) {
      return RuntimeActionResult::Failure("the before game-state capture is unavailable");
    }

    JsonObject caseCapture;
    caseCapture.Set("nation", static_cast<int>(nationSlot));
    RunState().SetCapture("case", caseCapture.Release());

    nation->interiorMinister->SetCityPolicies();
    if (!CaptureVoidOpResult(RunState())) {
      return RuntimeActionResult::Failure("the void operation result capture is unavailable");
    }

    if (!CaptureGameState(RunState(), "after")) {
      return RuntimeActionResult::Failure("the after game-state capture is unavailable");
    }
    return RuntimeActionResult::Success();
  }
};

} // namespace

RUNTIME_TEST_FACTORY(TransportNeedAllocationTestCase, TransportNeedAllocationTest)
