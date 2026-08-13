#include "NativeCases.h"
#include "JsonObject.h"

#include "game/civilian_domain_types.h"
#include "game/globals/shared_globals.h"
#include "game/map/TMapMgr.h"
#include "game/military/TCivUnit.h"
#include "game/nation/TGreatPower.h"
#include "game/strategic_terrain.h"
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

bool FindUnoccupiedProvinceTile(StrategicTileIndex* tileIndex) {
  for (StrategicTileIndex candidate = 0; candidate < 0x1950; ++candidate) {
    const TTerrainStateRecord& tile = g_pGlobalMapState->terrainStateTable[candidate];
    if (tile.firstCivilianOrder20 != 0) {
      continue;
    }
    short province = tile.cityRecordIndex;
    if (province < 0 || province >= 0x180) {
      continue;
    }
    if (g_pGlobalMapState->cityScoreTable[province].cityTileIndex04 < 0) {
      continue;
    }
    *tileIndex = candidate;
    return true;
  }
  return false;
}

bool FindOwnedConstructionTile(NationSlot nationSlot, unsigned short requiredFlags,
                               unsigned short forbiddenFlags, StrategicTileIndex* tileIndex) {
  for (StrategicTileIndex candidate = 0; candidate < 0x1950; ++candidate) {
    const TTerrainStateRecord& tile = g_pGlobalMapState->terrainStateTable[candidate];
    if (tile.firstCivilianOrder20 != 0 || tile.ownerNationTag04 != nationSlot) {
      continue;
    }
    if ((tile.activeFlags1c & requiredFlags) != requiredFlags) {
      continue;
    }
    if ((tile.activeFlags1c & forbiddenFlags) != 0) {
      continue;
    }
    *tileIndex = candidate;
    return true;
  }
  return false;
}

} // namespace

RuntimeActionResult RunCompletedRailSection(NativeTransition& transition) {
  const NationSlot nationSlot = ActiveNationSlot();

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

  JsonObject args;
  args.Set("civilian", civilian->persistentUnitId20);
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }

  civilian->ContinueOrders();
  return transition.Finish();
}

RuntimeActionResult RunIssuedRailSection(NativeTransition& transition) {
  const NationSlot nationSlot = ActiveNationSlot();
  TGreatPower* nation = ActiveNation();

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

  JsonObject args;
  args.Set("civilian", civilian->persistentUnitId20);
  args.Set("destination", static_cast<int>(destinationTile));
  RuntimeActionResult started = transition.Begin(args.Release());
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
  const NationSlot nationSlot = ActiveNationSlot();

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

  JsonObject args;
  args.Set("extractive_worker", extractiveWorker->persistentUnitId20);
  args.Set("surface_worker", surfaceWorker->persistentUnitId20);
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }

  extractiveWorker->ContinueOrders();
  surfaceWorker->ContinueOrders();
  return transition.Finish();
}

RuntimeActionResult RunCiviliansPhase(NativeTransition& transition) {
  const NationSlot nationSlot = g_pSimMgr->GetActiveNationId();
  TGreatPower* nation = g_apNationStates[nationSlot];
  if (nation == 0 || nation->trackedObjectList == 0 || g_pGlobalMapState == 0 ||
      g_pGlobalMapState->terrainStateTable == 0) {
    return RuntimeActionResult::Failure("the loaded game has no civilian state");
  }

  StrategicTileIndex sourceTile = -1;
  StrategicTileIndex destinationTile = -1;
  if (!FindUnoccupiedRailSection(&sourceTile, &destinationTile)) {
    return RuntimeActionResult::Failure("the loaded map has no clear rail section");
  }
  TCivUnit* engineer = new TCivUnit();
  engineer->ICivUnit(kCivilianUnitEngineer, sourceTile, nationSlot);
  g_pGlobalMapState->ApplyRailSectionEndpointDirectionFlags(sourceTile, destinationTile,
                                                            nationSlot);
  engineer->SetOrders(kUnitOrderLayRail, sourceTile);
  engineer->MoveTo(destinationTile);
  engineer->remainingTurns24 = 1;

  StrategicTileIndex prospectTile = -1;
  if (!FindUnoccupiedTile(&prospectTile)) {
    return RuntimeActionResult::Failure("the loaded map has no unoccupied prospecting tile");
  }
  TCivUnit* prospector = new TCivUnit();
  prospector->ICivUnit(kCivilianUnitProspector, prospectTile, nationSlot);
  prospector->SetOrders(kUnitOrderProspect, prospectTile);
  prospector->remainingTurns24 = 1;

  StrategicTileIndex developTile = -1;
  if (!FindUnoccupiedTile(&developTile)) {
    return RuntimeActionResult::Failure("the loaded map has no unoccupied development tile");
  }
  TCivUnit* miner = new TCivUnit();
  miner->ICivUnit(kCivilianUnitMiner, developTile, nationSlot);
  miner->SetOrders(kUnitOrderDevelopResource, developTile);
  miner->remainingTurns24 = 1;

  StrategicTileIndex fortTile = -1;
  if (!FindUnoccupiedProvinceTile(&fortTile)) {
    return RuntimeActionResult::Failure("the loaded map has no unoccupied province tile");
  }
  TCivUnit* fortEngineer = new TCivUnit();
  fortEngineer->ICivUnit(kCivilianUnitEngineer, fortTile, nationSlot);
  fortEngineer->SetOrders(kUnitOrderBuildFort, fortTile);
  fortEngineer->remainingTurns24 = 1;

  StrategicTileIndex purchaseTile = -1;
  if (!FindUnoccupiedTile(&purchaseTile)) {
    return RuntimeActionResult::Failure("the loaded map has no unoccupied purchase tile");
  }
  TCivUnit* developer = new TCivUnit();
  developer->ICivUnit(kCivilianUnitDeveloper, purchaseTile, nationSlot);
  developer->SetOrders(kUnitOrderPurchaseLand, purchaseTile);
  developer->remainingTurns24 = 1;

  StrategicTileIndex sleepTile = -1;
  if (!FindUnoccupiedTile(&sleepTile)) {
    return RuntimeActionResult::Failure("the loaded map has no unoccupied sleep tile");
  }
  TCivUnit* sleeper = new TCivUnit();
  sleeper->ICivUnit(kCivilianUnitFarmer, sleepTile, nationSlot);
  sleeper->SetOrders(kUnitOrderSleep, sleepTile);

  StrategicTileIndex redeployTile = -1;
  if (!FindUnoccupiedTile(&redeployTile)) {
    return RuntimeActionResult::Failure("the loaded map has no unoccupied redeploy tile");
  }
  TCivUnit* traveler = new TCivUnit();
  traveler->ICivUnit(kCivilianUnitRancher, redeployTile, nationSlot);
  traveler->SetOrders(kUnitOrderRedeploy, redeployTile);
  traveler->remainingTurns24 = 1;

  StrategicTileIndex depotTile = -1;
  if (!FindOwnedConstructionTile(nationSlot, 0, 0x24, &depotTile)) {
    return RuntimeActionResult::Failure("the loaded map has no owned depot construction tile");
  }
  TCivUnit* depotEngineer = new TCivUnit();
  depotEngineer->ICivUnit(kCivilianUnitEngineer, depotTile, nationSlot);
  depotEngineer->SetOrders(kUnitOrderBuildDepot, depotTile);
  depotEngineer->remainingTurns24 = 1;

  StrategicTileIndex portTile = -1;
  if (!FindOwnedConstructionTile(nationSlot, 1, 0x30, &portTile)) {
    return RuntimeActionResult::Failure("the loaded map has no owned port construction tile");
  }
  TCivUnit* portEngineer = new TCivUnit();
  portEngineer->ICivUnit(kCivilianUnitEngineer, portTile, nationSlot);
  portEngineer->SetOrders(kUnitOrderBuildPort, portTile);
  portEngineer->remainingTurns24 = 1;

  RuntimeActionResult started = transition.Begin(JsonNullValue());
  if (!started.Succeeded()) {
    return started;
  }

  g_pSimMgr->DoCivilians();
  return transition.Finish();
}
