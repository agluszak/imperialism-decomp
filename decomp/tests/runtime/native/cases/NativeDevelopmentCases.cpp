#include "NativeCases.h"
#include "JsonArray.h"
#include "JsonObject.h"

#include <stdlib.h>

#include "game/civilian_domain_types.h"
#include "game/city/TTown.h"
#include "game/globals/shared_globals.h"
#include "game/map/TMapMgr.h"
#include "game/military/TCivUnit.h"
#include "game/nation/TGreatPower.h"
#include "game/strategic_terrain.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_core/TSortedList.h"
#include "game/unit_domain_types.h"

namespace {

bool FindUnoccupiedRailSection(StrategicTileIndex* sourceTile,
                               StrategicTileIndex* destinationTile) {
  for (StrategicTileIndex candidate = 0; candidate < kStrategicTileCount; ++candidate) {
    const TTerrainStateRecord& source = g_pGlobalMapState->terrainStateTable[candidate];
    if (source.firstCivilianOrder != 0 || source.adjacencyBits != 0 ||
        source.railFlags != 0) {
      continue;
    }

    StrategicTileIndex neighbor =
        g_pGlobalMapState->GetNeighborTileID(candidate, kStrategicHexDirectionEast);
    if (neighbor == -1 || neighbor == candidate) {
      continue;
    }

    const TTerrainStateRecord& destination = g_pGlobalMapState->terrainStateTable[neighbor];
    if (destination.firstCivilianOrder == 0 && destination.adjacencyBits == 0 &&
        destination.railFlags == 0) {
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
  for (StrategicTileIndex candidate = 0; candidate < kStrategicTileCount; ++candidate) {
    short column = candidate % 0x6c;
    if (column < 2 || column > 0x69) {
      continue;
    }

    const TTerrainStateRecord& source = g_pGlobalMapState->terrainStateTable[candidate];
    if (source.ownerNationTag != nationSlot || source.firstCivilianOrder != 0 ||
        source.adjacencyBits != 0 || source.railFlags != 0 ||
        !TerrainAllowsStartingRail(source.GetTerrainKind())) {
      continue;
    }

    StrategicTileIndex neighbor =
        g_pGlobalMapState->GetNeighborTileID(candidate, kStrategicHexDirectionEast);
    if (neighbor == -1 || neighbor == candidate) {
      continue;
    }

    const TTerrainStateRecord& destination = g_pGlobalMapState->terrainStateTable[neighbor];
    if (destination.ownerNationTag == nationSlot && destination.firstCivilianOrder == 0 &&
        destination.adjacencyBits == 0 && destination.railFlags == 0 &&
        TerrainAllowsStartingRail(destination.GetTerrainKind())) {
      *sourceTile = candidate;
      *destinationTile = neighbor;
      return true;
    }
  }
  return false;
}

bool FindUnoccupiedTile(StrategicTileIndex* tileIndex) {
  for (StrategicTileIndex candidate = 0; candidate < kStrategicTileCount; ++candidate) {
    if (g_pGlobalMapState->terrainStateTable[candidate].firstCivilianOrder == 0) {
      *tileIndex = candidate;
      return true;
    }
  }
  return false;
}

bool FindUnoccupiedProvinceTile(StrategicTileIndex* tileIndex) {
  for (StrategicTileIndex candidate = 0; candidate < kStrategicTileCount; ++candidate) {
    const TTerrainStateRecord& tile = g_pGlobalMapState->terrainStateTable[candidate];
    if (tile.firstCivilianOrder != 0) {
      continue;
    }
    short province = tile.cityRecordIndex;
    if (province < 0 || province >= 0x180) {
      continue;
    }
    if (g_pGlobalMapState->cityScoreTable[province].cityTileIndex < 0) {
      continue;
    }
    *tileIndex = candidate;
    return true;
  }
  return false;
}

bool FindOwnedConstructionTile(NationSlot nationSlot, unsigned short requiredFlags,
                               unsigned short forbiddenFlags, StrategicTileIndex* tileIndex) {
  for (StrategicTileIndex candidate = 0; candidate < kStrategicTileCount; ++candidate) {
    const TTerrainStateRecord& tile = g_pGlobalMapState->terrainStateTable[candidate];
    if (tile.firstCivilianOrder != 0 || tile.ownerNationTag != nationSlot) {
      continue;
    }
    if ((tile.activeFlags & requiredFlags) != requiredFlags) {
      continue;
    }
    if ((tile.activeFlags & forbiddenFlags) != 0) {
      continue;
    }
    *tileIndex = candidate;
    return true;
  }
  return false;
}

bool FindOwnedCoastalConstructionTile(NationSlot nationSlot, unsigned short forbiddenFlags,
                                      StrategicTileIndex* tileIndex) {
  for (StrategicTileIndex candidate = 0; candidate < kStrategicTileCount; ++candidate) {
    const TTerrainStateRecord& tile = g_pGlobalMapState->terrainStateTable[candidate];
    if (tile.firstCivilianOrder != 0 || tile.ownerNationTag != nationSlot) {
      continue;
    }
    if ((tile.activeFlags & forbiddenFlags) != 0) {
      continue;
    }
    for (int direction = 0; direction < 6; ++direction) {
      StrategicTileIndex neighbor =
          g_pGlobalMapState->GetNeighborTileID(candidate, static_cast<short>(direction));
      if (neighbor == -1) {
        continue;
      }
      if (g_pGlobalMapState->terrainStateTable[neighbor].GetTerrainKind() ==
          kStrategicTerrainWater) {
        *tileIndex = candidate;
        return true;
      }
    }
  }
  return false;
}

JSON_Value* CaptureTouchedTiles(const StrategicTileIndex* tiles, int count) {
  JsonArray array;
  for (int index = 0; index < count; ++index) {
    const TTerrainStateRecord& tile = g_pGlobalMapState->terrainStateTable[tiles[index]];
    JsonObject object;
    object.Set("tile", static_cast<int>(tiles[index]));
    object.Set("owner", static_cast<int>(tile.ownerNationTag));
    object.Set("adjacency", static_cast<int>(tile.adjacencyBits));
    object.Set("dev_nibbles",
               static_cast<int>(
                   static_cast<unsigned char>(tile.developmentClassNibbles)));
    object.Set("pending", static_cast<int>(tile.pendingDevelopmentFlag));
    object.Set("rail_flags", static_cast<int>(tile.railFlags));
    object.Set("active_flags", static_cast<int>(tile.activeFlags));
    object.Set("province", static_cast<int>(tile.cityRecordIndex));
    array.Add(object.Release());
  }
  return array.Release();
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
  civilian->remainingTurns = 1;

  JsonObject args;
  args.Set("civilian", civilian->persistentUnitId);
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }

  civilian->ContinueOrders();
  JsonObject result;
  const StrategicTileIndex touched[2] = {sourceTile, destinationTile};
  result.Set("tiles", CaptureTouchedTiles(touched, 2));
  return transition.Finish(result.Release());
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
    nation->treasuryValue = 10000;
  }

  JsonObject args;
  args.Set("civilian", civilian->persistentUnitId);
  args.Set("destination", static_cast<int>(destinationTile));
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }

  // HandleEngineerConstructionAction also plays UI feedback; these are the
  // state mutations it performs for an adjacent rail click.
  const StrategicTerrainKind terrainKind =
      g_pGlobalMapState->terrainStateTable[destinationTile].GetTerrainKind();
  nation->treasuryValue -= g_adwEngineerRailBuildCostByTerrainType[terrainKind];
  g_pGlobalMapState->ApplyRailSectionEndpointDirectionFlags(sourceTile, destinationTile,
                                                            nationSlot);
  civilian->SetOrders(kUnitOrderLayRail, sourceTile);
  civilian->MoveTo(destinationTile);
  JsonObject result;
  const StrategicTileIndex touched[2] = {sourceTile, destinationTile};
  result.Set("tiles", CaptureTouchedTiles(touched, 2));
  return transition.Finish(result.Release());
}

RuntimeActionResult RunCompletedResourceDevelopment(NativeTransition& transition) {
  const NationSlot nationSlot = ActiveNationSlot();

  StrategicTileIndex extractiveTile = -1;
  if (!FindUnoccupiedTile(&extractiveTile)) {
    return RuntimeActionResult::Failure("the loaded map has no unoccupied tile");
  }

  g_pGlobalMapState->SetDevelopmentLevel(extractiveTile, 0, 2, 0);
  g_pGlobalMapState->SetDevelopmentLevel(extractiveTile, 1, 0, 0);
  g_pGlobalMapState->terrainStateTable[extractiveTile].pendingDevelopmentFlag = 0;

  TCivUnit* extractiveWorker = new TCivUnit();
  extractiveWorker->ICivUnit(kCivilianUnitMiner, extractiveTile, nationSlot);
  extractiveWorker->SetOrders(kUnitOrderDevelopResource, extractiveTile);
  extractiveWorker->remainingTurns = 1;

  StrategicTileIndex surfaceTile = -1;
  if (!FindUnoccupiedTile(&surfaceTile)) {
    return RuntimeActionResult::Failure("the loaded map has only one unoccupied tile");
  }
  g_pGlobalMapState->SetDevelopmentLevel(surfaceTile, 0, 2, 0);
  g_pGlobalMapState->SetDevelopmentLevel(surfaceTile, 1, 0, 0);
  g_pGlobalMapState->terrainStateTable[surfaceTile].pendingDevelopmentFlag = 1 << 3;

  TCivUnit* surfaceWorker = new TCivUnit();
  surfaceWorker->ICivUnit(kCivilianUnitEngineer, surfaceTile, nationSlot);
  surfaceWorker->SetOrders(kUnitOrderDevelopResource, surfaceTile);
  surfaceWorker->remainingTurns = 1;

  JsonObject args;
  args.Set("extractive_worker", extractiveWorker->persistentUnitId);
  args.Set("surface_worker", surfaceWorker->persistentUnitId);
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }

  extractiveWorker->ContinueOrders();
  surfaceWorker->ContinueOrders();
  JsonObject result;
  const StrategicTileIndex touched[2] = {extractiveTile, surfaceTile};
  result.Set("tiles", CaptureTouchedTiles(touched, 2));
  return transition.Finish(result.Release());
}

RuntimeActionResult RunCiviliansPhaseCase(NativeTransition& transition, bool secondTurn) {
  if (secondTurn) {
    g_pSimMgr->economicTurn = 2;
  }
  const NationSlot nationSlot = ActiveNationSlot();
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
  engineer->remainingTurns = 1;

  StrategicTileIndex prospectTile = -1;
  if (!FindUnoccupiedTile(&prospectTile)) {
    return RuntimeActionResult::Failure("the loaded map has no unoccupied prospecting tile");
  }
  TCivUnit* prospector = new TCivUnit();
  prospector->ICivUnit(kCivilianUnitProspector, prospectTile, nationSlot);
  prospector->SetOrders(kUnitOrderProspect, prospectTile);
  prospector->remainingTurns = 1;

  StrategicTileIndex developTile = -1;
  if (!FindUnoccupiedTile(&developTile)) {
    return RuntimeActionResult::Failure("the loaded map has no unoccupied development tile");
  }
  TCivUnit* miner = new TCivUnit();
  miner->ICivUnit(kCivilianUnitMiner, developTile, nationSlot);
  miner->SetOrders(kUnitOrderDevelopResource, developTile);
  miner->remainingTurns = 1;

  StrategicTileIndex fortTile = -1;
  if (!FindUnoccupiedProvinceTile(&fortTile)) {
    return RuntimeActionResult::Failure("the loaded map has no unoccupied province tile");
  }
  TCivUnit* fortEngineer = new TCivUnit();
  fortEngineer->ICivUnit(kCivilianUnitEngineer, fortTile, nationSlot);
  fortEngineer->SetOrders(kUnitOrderBuildFort, fortTile);
  fortEngineer->remainingTurns = 1;

  StrategicTileIndex purchaseTile = -1;
  if (!FindUnoccupiedTile(&purchaseTile)) {
    return RuntimeActionResult::Failure("the loaded map has no unoccupied purchase tile");
  }
  TCivUnit* developer = new TCivUnit();
  developer->ICivUnit(kCivilianUnitDeveloper, purchaseTile, nationSlot);
  developer->SetOrders(kUnitOrderPurchaseLand, purchaseTile);
  developer->remainingTurns = 1;

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
  traveler->remainingTurns = 1;

  StrategicTileIndex depotTile = -1;
  if (!FindOwnedConstructionTile(nationSlot, 0, 0x24, &depotTile)) {
    return RuntimeActionResult::Failure("the loaded map has no owned depot construction tile");
  }
  TCivUnit* depotEngineer = new TCivUnit();
  depotEngineer->ICivUnit(kCivilianUnitEngineer, depotTile, nationSlot);
  depotEngineer->SetOrders(kUnitOrderBuildDepot, depotTile);
  depotEngineer->remainingTurns = 1;

  StrategicTileIndex portTile = -1;
  if (!FindOwnedCoastalConstructionTile(nationSlot, 0x30, &portTile)) {
    return RuntimeActionResult::Failure(
        "the loaded map has no owned coastal port construction tile");
  }
  // beginning_of_game.imp has no owned BASE_TRANSPORT tiles that are not cities.
  // Ordinary port orders run on a connected coastal tile; stamp that flag so
  // EnsurePortZoneForTile takes the live path instead of the early-out.
  g_pGlobalMapState->terrainStateTable[portTile].activeFlags |= 1;
  TCivUnit* portEngineer = new TCivUnit();
  portEngineer->ICivUnit(kCivilianUnitEngineer, portTile, nationSlot);
  portEngineer->SetOrders(kUnitOrderBuildPort, portTile);
  portEngineer->remainingTurns = 1;

  int townCountsBefore[7];
  for (int slot = 0; slot < 7; ++slot) {
    townCountsBefore[slot] = g_apNationStates[slot]->townMarkerList->GetCount();
  }

  RuntimeActionResult started = transition.Begin(JsonNullValue());
  if (!started.Succeeded()) {
    return started;
  }

  // Deterministic CRT seed so retail-vs-recomp differentials see identical
  // rand() streams (civilian dispute resolution and ministers consume rand()).
  srand(0x1234);
  g_pSimMgr->DoCivilians();

  // TTown::ITown leaves this serialized byte uninitialized. Normalize only
  // markers created by this action to the semantic default used by the Rust
  // state; existing marker state remains part of the differential.
  for (int nationIndex = 0; nationIndex < 7; ++nationIndex) {
    TSortedList* towns = g_apNationStates[nationIndex]->townMarkerList;
    for (int ordinal = townCountsBefore[nationIndex] + 1; ordinal <= towns->GetCount();
         ++ordinal) {
      static_cast<TTown*>(towns->GetEntryByOrdinal(ordinal))->hasAdjacentCity = 0;
    }
  }
  return transition.Finish();
}

RuntimeActionResult RunCiviliansPhase(NativeTransition& transition) {
  return RunCiviliansPhaseCase(transition, false);
}

RuntimeActionResult RunSecondTurnCiviliansPhase(NativeTransition& transition) {
  return RunCiviliansPhaseCase(transition, true);
}
