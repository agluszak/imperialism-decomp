#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"
#include "JsonObject.h"
#include "RuntimeDifferentialCapture.h"
#include "RuntimeGameStateCapture.h"
#include "RuntimeRun.h"

#include "game/civilian_domain_types.h"
#include "game/globals/shared_globals.h"
#include "game/map/TMapMgr.h"
#include "game/military/TCivUnit.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_screens/TSimMgr.h"

namespace {

bool FindUnoccupiedTile(StrategicTileIndex* tileIndex) {
  for (StrategicTileIndex candidate = 0; candidate < 0x1950; ++candidate) {
    if (g_pGlobalMapState->terrainStateTable[candidate].firstCivilianOrder20 == 0) {
      *tileIndex = candidate;
      return true;
    }
  }
  return false;
}

// Finish both resource-development channels. The complete semantic game-state captures are the
// oracle for per-major resource disclosure and each civilian's idle transition.
class CompletedResourceDevelopmentTestCase : public LoadedMapScriptScenario {
protected:
  void Script() override {
    RT_BEGIN();

    RT_DO("complete resource development", CompleteResourceDevelopment());
    RT_PASS();

    RT_END();
  }

private:
  RuntimeActionResult CompleteResourceDevelopment() {
    const NationSlot nationSlot = g_pSimMgr->GetActiveNationId();
    TGreatPower* nation = g_apNationStates[nationSlot];
    if (nation == 0 || nation->trackedObjectList == 0 || g_pGlobalMapState == 0 ||
        g_pGlobalMapState->terrainStateTable == 0) {
      return RuntimeActionResult::Failure("the loaded game has no civilian development state");
    }

    StrategicTileIndex extractiveTile = -1;
    if (!FindUnoccupiedTile(&extractiveTile)) {
      return RuntimeActionResult::Failure("the loaded map has no unoccupied tile");
    }

    g_pGlobalMapState->SetCivilianDevelopmentClassNibble(extractiveTile, 0, 2, 0);
    g_pGlobalMapState->SetCivilianDevelopmentClassNibble(extractiveTile, 1, 0, 0);
    g_pGlobalMapState->terrainStateTable[extractiveTile].pendingDevelopmentFlag0d = 0;

    TCivUnit* extractiveWorker = new TCivUnit();
    extractiveWorker->ICivUnit(kCivilianUnitMiner, extractiveTile, nationSlot);
    extractiveWorker->SetOrders(kUnitOrderDevelopResource, extractiveTile);
    extractiveWorker->remainingTurns24 = 1;

    StrategicTileIndex surfaceTile = -1;
    if (!FindUnoccupiedTile(&surfaceTile)) {
      return RuntimeActionResult::Failure("the loaded map has only one unoccupied tile");
    }
    g_pGlobalMapState->SetCivilianDevelopmentClassNibble(surfaceTile, 0, 2, 0);
    g_pGlobalMapState->SetCivilianDevelopmentClassNibble(surfaceTile, 1, 0, 0);
    g_pGlobalMapState->terrainStateTable[surfaceTile].pendingDevelopmentFlag0d = 1 << 3;

    TCivUnit* surfaceWorker = new TCivUnit();
    surfaceWorker->ICivUnit(kCivilianUnitEngineer, surfaceTile, nationSlot);
    surfaceWorker->SetOrders(kUnitOrderDevelopResource, surfaceTile);
    surfaceWorker->remainingTurns24 = 1;

    JsonObject caseCapture;
    caseCapture.Set("extractive_worker", extractiveWorker->persistentUnitId20);
    caseCapture.Set("surface_worker", surfaceWorker->persistentUnitId20);

    RuntimeDifferentialCapture capture(RunState());
    RuntimeActionResult started = capture.Begin(caseCapture.Release());
    if (!started.Succeeded()) {
      return started;
    }

    extractiveWorker->ContinueOrders();
    surfaceWorker->ContinueOrders();
    return capture.Finish();
  }
};

} // namespace

RUNTIME_TEST_FACTORY(CompletedResourceDevelopmentTestCase, CompletedResourceDevelopmentTest)
