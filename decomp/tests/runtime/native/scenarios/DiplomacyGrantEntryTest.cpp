#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"
#include "JsonObject.h"
#include "RuntimeDifferentialCapture.h"
#include "RuntimeGameStateCapture.h"
#include "RuntimeRun.h"

#include "game/globals/shared_globals.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_screens/TSimMgr.h"

namespace {

// Set one semantic grant on the retail-produced beginning-of-game save.
class DiplomacyGrantEntryTestCase : public LoadedMapScriptScenario {
protected:
  void Script() override {
    RT_BEGIN();

    RT_DO("set diplomacy grant", SetGrantEntry());
    RT_PASS();

    RT_END();
  }

private:
  RuntimeActionResult SetGrantEntry() {
    const short activeNationSlot = g_pSimMgr->GetActiveNationId();
    const short targetNationSlot = 0;
    const short grantAmount = 10000;
    TGreatPower* nation = g_apNationStates[activeNationSlot];
    if (nation == 0 || activeNationSlot == targetNationSlot) {
      return RuntimeActionResult::Failure("the loaded player cannot make the grant-target check");
    }

    JsonObject caseCapture;
    caseCapture.Set("nation", static_cast<int>(activeNationSlot));
    caseCapture.Set("target", static_cast<int>(targetNationSlot));
    caseCapture.Set("amount", static_cast<int>(grantAmount));

    RuntimeDifferentialCapture capture(RunState());
    RuntimeActionResult started = capture.Begin(caseCapture.Release());
    if (!started.Succeeded()) {
      return started;
    }

    return capture.Finish(
        nation->SetDiplomacyGrantEntryForTargetAndUpdateTreasury(targetNationSlot, grantAmount));
  }
};

} // namespace

RUNTIME_TEST_FACTORY(DiplomacyGrantEntryTestCase, DiplomacyGrantEntryTest)
