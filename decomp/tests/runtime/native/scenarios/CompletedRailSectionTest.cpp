#include "RuntimeScriptBases.h"
#include "RuntimeScriptMacros.h"
#include "RuntimeTestFactory.h"
#include "JsonObject.h"
#include "RuntimeGameStateCapture.h"
#include "RuntimeRun.h"
#include "RuntimeSemanticCapture.h"

#include "game/civilian_domain_types.h"
#include "game/globals/shared_globals.h"
#include "game/map/TMapMgr.h"
#include "game/military/TCivUnit.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_screens/TSimMgr.h"

namespace {

bool FindUnoccupiedRailSection(StrategicTileIndex* sourceTile,
                               StrategicTileIndex* destinationTile) {
  for (StrategicTileIndex candidate = 0; candidate < 0x1950; ++candidate) {
    const TTerrainStateRecord& source = g_pGlobalMapState->terrainStateTable[candidate];
    if (source.firstCivilianOrder20 != 0 || source.adjacencyBits06 != 0 ||
        source.railFlags17 != 0) {
      continue;
    }

    StrategicTileIndex neighbor =
        g_pGlobalMapState->GetNeighborTileID(candidate, kStrategicHexDirectionEast);
    if (neighbor == -1 || neighbor == candidate) {
      continue;
    }

    const TTerrainStateRecord& destination = g_pGlobalMapState->terrainStateTable[neighbor];
    if (destination.firstCivilianOrder20 == 0 && destination.adjacencyBits06 == 0 &&
        destination.railFlags17 == 0) {
      *sourceTile = candidate;
      *destinationTile = neighbor;
      return true;
    }
  }
  return false;
}

// Finish a rail section through TCivUnit's normal completion path. The whole semantic game-state
// captures verify the directional transport link, the retained pending rail link, and idle reset.
class CompletedRailSectionTestCase : public LoadedMapScriptScenario {
protected:
  void Script() override {
    RT_BEGIN();

    RT_DO("complete rail section", CompleteRailSection());
    RT_PASS();

    RT_END();
  }

private:
  RuntimeActionResult CompleteRailSection() {
    const NationSlot nationSlot = g_pSimMgr->GetActiveNationId();
    TGreatPower* nation = g_apNationStates[nationSlot];
    if (nation == 0 || nation->trackedObjectList == 0 || g_pGlobalMapState == 0 ||
        g_pGlobalMapState->terrainStateTable == 0) {
      return RuntimeActionResult::Failure("the loaded game has no civilian rail state");
    }

    StrategicTileIndex sourceTile = -1;
    StrategicTileIndex destinationTile = -1;
    if (!FindUnoccupiedRailSection(&sourceTile, &destinationTile)) {
      return RuntimeActionResult::Failure("the loaded map has no clear rail section");
    }

    TCivUnit* civilian = new TCivUnit();
    civilian->ICivUnit(kCivilianUnitEngineer, sourceTile, nationSlot);
    g_pGlobalMapState->ApplyRailSectionEndpointDirectionFlags(sourceTile, destinationTile,
                                                              nationSlot);
    civilian->SetOrders(kUnitOrderLayRail, sourceTile);
    civilian->MoveTo(destinationTile);
    civilian->remainingTurns24 = 1;

    if (!CaptureGameState(RunState(), "before")) {
      return RuntimeActionResult::Failure("the before game-state capture is unavailable");
    }

    JsonObject caseCapture;
    caseCapture.Set("civilian", civilian->persistentUnitId20);
    RunState().SetCapture("case", caseCapture.Release());

    civilian->ContinueOrders();
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

RUNTIME_TEST_FACTORY(CompletedRailSectionTestCase, CompletedRailSectionTest)
