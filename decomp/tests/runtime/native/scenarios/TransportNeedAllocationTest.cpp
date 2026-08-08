#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"

#include "game/city_ui/TCityInteriorMinister.h"
#include "game/globals/shared_globals.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_screens/TSimMgr.h"

namespace {

// Allocate the active nation's transport capacity to its city-resource needs from the
// retail-produced beginning-of-game save. The direct game-state capture is the oracle.
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

    nation->interiorMinister->SetCityPolicies();
    return RuntimeActionResult::Success();
  }
};

} // namespace

RUNTIME_TEST_FACTORY(TransportNeedAllocationTestCase, TransportNeedAllocationTest)
