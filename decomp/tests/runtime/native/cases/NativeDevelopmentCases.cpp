#include "NativeTransition.h"
#include "JsonObject.h"

#include "game/civilian_domain_types.h"
#include "game/globals/shared_globals.h"
#include "game/map/TMapMgr.h"
#include "game/military/TCivUnit.h"
#include "game/nation/TGreatPower.h"
#include "game/strategic_terrain.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/unit_domain_types.h"

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

bool TerrainAllowsStartingRail(StrategicTerrainKind kind) {
  return kind == kStrategicTerrainPlains || kind == kStrategicTerrainForest ||
         kind == kStrategicTerrainDesert || kind == kStrategicTerrainFarmland;
}

bool FindIssuableRailSection(NationSlot nationSlot, StrategicTileIndex* sourceTile,
                             StrategicTileIndex* destinationTile) {
  for (StrategicTileIndex candidate = 0; candidate < 0x1950; ++candidate) {
    short column = candidate % 0x6c;
    if (column < 2 || column > 0x69) {
      continue;
    }

    const TTerrainStateRecord& source = g_pGlobalMapState->terrainStateTable[candidate];
    if (source.ownerNationTag04 != nationSlot || source.firstCivilianOrder20 != 0 ||
        source.adjacencyBits06 != 0 || source.railFlags17 != 0 ||
        !TerrainAllowsStartingRail(source.GetTerrainKind())) {
      continue;
    }

    StrategicTileIndex neighbor =
        g_pGlobalMapState->GetNeighborTileID(candidate, kStrategicHexDirectionEast);
    if (neighbor == -1 || neighbor == candidate) {
      continue;
    }

    const TTerrainStateRecord& destination = g_pGlobalMapState->terrainStateTable[neighbor];
    if (destination.ownerNationTag04 == nationSlot && destination.firstCivilianOrder20 == 0 &&
        destination.adjacencyBits06 == 0 && destination.railFlags17 == 0 &&
        TerrainAllowsStartingRail(destination.GetTerrainKind())) {
      *sourceTile = candidate;
      *destinationTile = neighbor;
      return true;
    }
  }
  return false;
}

bool FindUnoccupiedTile(StrategicTileIndex* tileIndex) {
  for (StrategicTileIndex candidate = 0; candidate < 0x1950; ++candidate) {
    if (g_pGlobalMapState->terrainStateTable[candidate].firstCivilianOrder20 == 0) {
      *tileIndex = candidate;
      return true;
    }
  }
  return false;
}

} // namespace

RuntimeActionResult RunCompletedRailSection(NativeTransition& transition) {
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

  JsonObject operation;
  operation.Set("civilian", civilian->persistentUnitId20);
  RuntimeActionResult started = transition.Begin(operation.Release());
  if (!started.Succeeded()) {
    return started;
  }

  civilian->ContinueOrders();
  return transition.Finish();
}

RuntimeActionResult RunIssuedRailSection(NativeTransition& transition) {
  const NationSlot nationSlot = g_pSimMgr->GetActiveNationId();
  TGreatPower* nation = g_apNationStates[nationSlot];
  if (nation == 0 || nation->trackedObjectList == 0 || g_pGlobalMapState == 0 ||
      g_pGlobalMapState->terrainStateTable == 0) {
    return RuntimeActionResult::Failure("the loaded game has no civilian rail state");
  }

  StrategicTileIndex sourceTile = -1;
  StrategicTileIndex destinationTile = -1;
  if (!FindIssuableRailSection(nationSlot, &sourceTile, &destinationTile)) {
    return RuntimeActionResult::Failure("the loaded map has no issuable rail section");
  }

  TCivUnit* civilian = new TCivUnit();
  civilian->ICivUnit(kCivilianUnitEngineer, sourceTile, nationSlot);
  if (nation->ComputeAvailableDiplomacyBudget() < 400) {
    nation->treasuryValue10 = 10000;
  }

  JsonObject operation;
  operation.Set("civilian", civilian->persistentUnitId20);
  operation.Set("destination", static_cast<int>(destinationTile));
  RuntimeActionResult started = transition.Begin(operation.Release());
  if (!started.Succeeded()) {
    return started;
  }

  // HandleEngineerConstructionAction also plays UI feedback; these are the
  // state mutations it performs for an adjacent rail click.
  const StrategicTerrainKind terrainKind =
      g_pGlobalMapState->terrainStateTable[destinationTile].GetTerrainKind();
  nation->treasuryValue10 -= g_adwEngineerRailBuildCostByTerrainType[terrainKind];
  g_pGlobalMapState->ApplyRailSectionEndpointDirectionFlags(sourceTile, destinationTile,
                                                            nationSlot);
  civilian->SetOrders(kUnitOrderLayRail, sourceTile);
  civilian->MoveTo(destinationTile);
  return transition.Finish();
}

RuntimeActionResult RunCompletedResourceDevelopment(NativeTransition& transition) {
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

  JsonObject operation;
  operation.Set("extractive_worker", extractiveWorker->persistentUnitId20);
  operation.Set("surface_worker", surfaceWorker->persistentUnitId20);
  RuntimeActionResult started = transition.Begin(operation.Release());
  if (!started.Succeeded()) {
    return started;
  }

  extractiveWorker->ContinueOrders();
  surfaceWorker->ContinueOrders();
  return transition.Finish();
}
