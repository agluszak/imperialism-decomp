#include "NativeCases.h"
#include "JsonArray.h"
#include "JsonObject.h"
#include "RuntimeGameStateCapture.h"
#include "parson.h"

#include <stdlib.h>

#include "game/city/TCity.h"
#include "game/city/TUnitOrder.h"
#include "game/city_ui/TCityInteriorMinister.h"
#include "game/city_ui/TCountry.h"
#include "game/diplomacy_domain_types.h"
#include "game/globals/navy_globals.h"
#include "game/globals/shared_globals.h"
#include "game/map/TMapMgr.h"
#include "game/map/TZone.h"
#include "game/map/map_records.h"
#include "game/military/TArmyMgr.h"
#include "game/military/TArmyStack.h"
#include "game/military/TArmyStackList.h"
#include "game/military/TMilitaryUnit.h"
#include "game/military/TUnit.h"
#include "game/military_domain_types.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/map/TControlSeaZoneMission.h"
#include "game/map/TMission.h"
#include "game/nation/TAutoGreatPower.h"
#include "game/nation/TGreatPower.h"
#include "game/nation/TGreatPower_internal.h"
#include "game/nation_domain_types.h"
#include "game/navy/TAdmiral.h"
#include "game/navy/TNavyMgr.h"
#include "game/navy/TOcean.h"
#include "game/navy/TShip.h"
#include "game/navy/TNavyMgr.h"
#include "game/navy/TOcean.h"
#include "game/navy/TTaskForce.h"
#include "game/tactical/TArmyBattle.h"
#include "game/tactical/TArmyPlayer.h"
#include "game/tactical/TArmyTacUnit.h"
#include "game/tactical/TNavyAutoPlayer.h"
#include "game/tactical/TNavyBattle.h"
#include "game/tactical/TNavyHumanPlayer.h"
#include "game/tactical/TNavyPlayer.h"
#include "game/tactical/TNavyTacUnit.h"
#include "game/tactical/TTacticalUnit.h"
#include "game/TList.h"
#include "game/tactical/hex_tile_distance.h"
#include "game/ui_core/CIterator.h"
#include "game/ui_core/TSortedPtrList.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/unit_domain_types.h"
#include "game/globals/nation_globals.h"

#include <string.h>
#include <stdio.h>

namespace {

unsigned int FloatBits(float value) {
  unsigned int bits = 0;
  memcpy(&bits, &value, sizeof(bits));
  return bits;
}

struct StrategicBattleMatrixCase {
  const char* name;
  unsigned int seed;
  short leftTypes[4];
  short leftCount;
  int leftAggression;
  short leftStrength;
  short leftExperience;
  short leftAdmiralExperience;
  short rightTypes[4];
  short rightCount;
  int rightAggression;
  short rightStrength;
  short rightExperience;
  short rightAdmiralExperience;
  const char* convergence;
  const char* resolution;
};

// clang-format off
const StrategicBattleMatrixCase kStrategicBattleMatrix[] = {
    {"left_fails_admiral_boundary", 0x1234, {3, 0, 0, 0}, 1, 0, 100, 0, 0,
     {3, 0, 0, 0}, 1, 0, 100, 0, 100, "only_left_fails", "tier_exhaustion"},
    {"left_fails_tier_gap", 0x1234, {3, 0, 0, 0}, 1, 0, 500, 0, 0, {7, 0, 0, 0}, 1,
     0, 500, 0, 0, "only_left_fails", "tier_exhaustion"},
    {"left_fails_fleet_size", 50, {4, 0, 0, 0}, 1, 1, 1600, 0, 400, {4, 4, 7, 0}, 3,
     0, 500, 0, 0, "only_left_fails", "tier_exhaustion"},
    {"left_fails_mixed_tiers", 1, {7, 11, 0, 0}, 2, 0, 500, 0, 200, {7, 8, 11, 0}, 3,
     1, 500, 0, 100, "only_left_fails", "tier_exhaustion"},
    {"right_fails_admiral_boundary", 0x1234, {3, 0, 0, 0}, 1, 0, 100, 0, 400,
     {3, 0, 0, 0}, 1, 0, 100, 0, 200, "only_right_fails", "tier_exhaustion"},
    {"right_fails_tier_gap", 0x1234, {7, 0, 0, 0}, 1, 0, 500, 0, 0, {3, 0, 0, 0}, 1,
     0, 500, 0, 0, "only_right_fails", "tier_exhaustion"},
    {"right_fails_mixed_tiers", 10, {8, 9, 13, 0}, 3, 1, 500, 0, 100,
     {9, 11, 11, 0}, 3, 2, 1000, 0, 100, "only_right_fails", "tier_exhaustion"},
    {"right_fails_fleet_size", 999, {4, 7, 7, 7}, 4, 2, 500, 0, 200,
     {8, 0, 0, 0}, 1, 1, 500, 0, 200, "only_right_fails", "tier_exhaustion"},
    {"both_fail_tier_one", 999, {3, 0, 0, 0}, 1, 0, 100, 0, 0, {3, 0, 0, 0}, 1, 0,
     100, 0, 0, "both_fail", "tier_exhaustion"},
    {"both_fail_tier_two", 10, {8, 0, 0, 0}, 1, 0, 500, 0, 0, {8, 0, 0, 0}, 1, 0,
     500, 0, 0, "both_fail", "tier_exhaustion"},
    {"both_fail_admiral_boundary", 4, {4, 0, 0, 0}, 1, 0, 100, 0, 200,
     {4, 0, 0, 0}, 1, 0, 100, 0, 100, "both_fail", "tier_exhaustion"},
    {"both_fail_top_tiers", 2, {11, 11, 12, 0}, 3, 0, 500, 0, 100,
     {11, 11, 13, 0}, 3, 0, 500, 0, 200, "both_fail", "tier_exhaustion"},
    {"left_eliminated_tier_one", 0x1234, {3, 0, 0, 0}, 1, 0, 1, 0, 200,
     {3, 3, 0, 0}, 2, 0, 1, 0, 400, "only_left_fails", "left_eliminated"},
    {"left_eliminated_tier_two", 0x1234, {7, 0, 0, 0}, 1, 0, 1, 0, 0,
     {7, 7, 0, 0}, 2, 0, 1, 0, 0, "only_left_fails", "left_eliminated"},
    {"left_eliminated_weight_boundary", 999, {8, 0, 0, 0}, 1, 0, 1, 0, 0,
     {8, 8, 0, 0}, 2, 0, 1, 0, 0, "only_left_fails", "left_eliminated"},
    {"right_eliminated_tier_one", 0x1234, {3, 3, 0, 0}, 2, 0, 1, 0, 0,
     {3, 0, 0, 0}, 1, 0, 1, 0, 0, "only_right_fails", "right_eliminated"},
    {"right_eliminated_tier_two", 0x1234, {7, 7, 0, 0}, 2, 0, 1, 0, 0,
     {7, 0, 0, 0}, 1, 0, 1, 0, 0, "only_right_fails", "right_eliminated"},
    {"right_eliminated_weight_boundary", 2, {8, 8, 0, 0}, 2, 0, 1, 0, 0,
     {8, 0, 0, 0}, 1, 0, 1, 0, 0, "only_right_fails", "right_eliminated"},
    {"both_eliminated_admiral_boundary", 0x1234, {3, 0, 0, 0}, 1, 0, 1, 0, 100,
     {3, 0, 0, 0}, 1, 0, 1, 0, 0, "only_right_fails", "both_eliminated"},
    {"both_eliminated_neither_fails", 0x1234, {3, 0, 0, 0}, 1, 2, 1, 0, 0,
     {3, 0, 0, 0}, 1, 2, 1, 0, 0, "neither_fails", "both_eliminated"},
};
// clang-format on

struct StrategicBattleFleet {
  TTaskForce* force;
  TShip* ships[4];
  short count;
};

bool FleetContainsShip(const StrategicBattleFleet& fleet, TShip* ship) {
  for (TMapOrderChildLinkNode* node = fleet.force->shipList; node != 0; node = node->next) {
    if (node->payload == ship) {
      return true;
    }
  }
  return false;
}

StrategicBattleFleet CreateStrategicBattleFleet(TZone* zone, short nation, const short* types,
                                                short count, int aggression, short strength,
                                                short experience, short admiralExperience,
                                                int caseIndex, char side) {
  StrategicBattleFleet fleet;
  int index;
  fleet.force = new TTaskForce(zone, nation);
  fleet.force->defeated = 0;
  fleet.force->SetAggression(aggression);
  fleet.count = count;
  for (index = 0; index < 4; ++index) {
    fleet.ships[index] = 0;
  }
  for (index = 0; index < count; ++index) {
    char name[32];
    sprintf(name, "matrix-%02d-%c%d", caseIndex, side, index);
    TShip* ship = new TShip();
    ship->IShip(types[index], zone, nation, name);
    ship->strength = strength;
    ship->experience = experience;
    fleet.force->Add(ship);
    fleet.ships[index] = ship;
  }
  fleet.force->ElectFlagship();
  TAdmiral* admiral = new TAdmiral(nation);
  admiral->experiencePoints = admiralExperience;
  admiral->AssignToShip(fleet.force->flagship);
  return fleet;
}

JSON_Value* CaptureStrategicBattleFleet(const StrategicBattleFleet& fleet, const short* types,
                                        int aggression, short initialStrength,
                                        short initialExperience, short initialAdmiralExperience) {
  JsonObject object;
  JsonArray ships;
  object.Set("aggression", aggression);
  object.Set("initial_strength", initialStrength);
  object.Set("initial_experience", initialExperience);
  object.Set("initial_admiral_experience", initialAdmiralExperience);
  object.Set("defeated", fleet.force->defeated != 0);
  TAdmiral* liveAdmiral = 0;
  for (int index = 0; index < fleet.count; ++index) {
    JsonObject ship;
    bool alive = FleetContainsShip(fleet, fleet.ships[index]);
    ship.Set("type", static_cast<int>(types[index]));
    ship.Set("alive", alive);
    if (alive) {
      ship.Set("strength", static_cast<int>(fleet.ships[index]->strength));
      ship.Set("experience", static_cast<int>(fleet.ships[index]->experience));
      if (fleet.ships[index]->admiral != 0) {
        liveAdmiral = fleet.ships[index]->admiral;
      }
    } else {
      ship.SetNull("strength");
      ship.SetNull("experience");
    }
    ships.Add(ship.Release());
  }
  if (liveAdmiral != 0) {
    object.Set("admiral_experience", static_cast<int>(liveAdmiral->experiencePoints));
  } else {
    object.SetNull("admiral_experience");
  }
  object.Set("ships", ships.Release());
  return object.Release();
}

void FreeStrategicBattleFleet(StrategicBattleFleet& fleet) {
  bool alive[4];
  int index;
  for (index = 0; index < fleet.count; ++index) {
    alive[index] = FleetContainsShip(fleet, fleet.ships[index]);
  }
  fleet.force->Free();
  fleet.force = 0;
  for (index = 0; index < fleet.count; ++index) {
    if (alive[index]) {
      fleet.ships[index]->Free();
    }
    fleet.ships[index] = 0;
  }
}

JSON_Value* CaptureArmyBattleSnapshot(TArmyBattle* battle) {
  TArmyTacUnit* units[256];
  int count = battle->recordList20->GetCount();
  int index;
  int scan;
  JsonObject snapshot;
  JsonArray unitArray;
  JsonArray fortStrength;

  if (count > 256) {
    count = 256;
  }
  for (index = 0; index < count; ++index) {
    units[index] = static_cast<TArmyTacUnit*>(battle->recordList20->GetEntryByOrdinal(index + 1));
  }
  for (index = 0; index < count; ++index) {
    for (scan = index + 1; scan < count; ++scan) {
      if (units[scan]->sourceUnit38->persistentUnitId20 <
          units[index]->sourceUnit38->persistentUnitId20) {
        TArmyTacUnit* swap = units[index];
        units[index] = units[scan];
        units[scan] = swap;
      }
    }
  }
  for (index = 0; index < count; ++index) {
    TArmyTacUnit* unit = units[index];
    JsonObject record;
    record.Set("source", unit->sourceUnit38->persistentUnitId20);
    record.Set("side", unit->side20);
    record.Set("tile", unit->tileIndex8);
    record.Set("action_points", unit->actionPoints28);
    record.Set("strength", unit->strength4);
    record.Set("morale", unit->morale34);
    record.Set("state", unit->state1c);
    unitArray.Add(record.Release());
  }
  snapshot.SetOptional(
      "selected",
      battle->selectedUnit1c != 0
          ? static_cast<TArmyTacUnit*>(battle->selectedUnit1c)->sourceUnit38->persistentUnitId20
          : -1);
  snapshot.Set("current_side", battle->currentSideC);
  snapshot.Set("round", battle->roundCounter74);
  snapshot.Set("outcome", battle->battleOutcome44);
  snapshot.Set("units", unitArray.Release());
  for (index = 0; index < 8; ++index) {
    fortStrength.Add(battle->fortStrengthPoints54[index]);
  }
  snapshot.Set("fort_strength", fortStrength.Release());
  snapshot.Set("crt_rand", RuntimeCrtRandStateForTests());
  return snapshot.Release();
}

void StopActiveNationArmyPlayerForInput(TArmyBattle* battle) {
  TArmyPlayer* ourPlayer = static_cast<TArmyPlayer*>(battle->tacticalPlayer14);
  TArmyPlayer* enemyPlayer = static_cast<TArmyPlayer*>(battle->tacticalPlayer18);
  ourPlayer->notWatchedFlagE = (ourPlayer->nationIndex1C == ActiveNationSlot()) ? 0 : 1;
  enemyPlayer->notWatchedFlagE = (enemyPlayer->nationIndex1C == ActiveNationSlot()) ? 0 : 1;
}

bool PumpArmyBattleToActiveNationInput(TArmyBattle* battle) {
  int guard = 20000;
  while (battle->battleOutcome44 == kTacticalBattleInProgress) {
    TArmyPlayer* player = static_cast<TArmyPlayer*>(
        battle->currentSideC == 0 ? battle->tacticalPlayer14 : battle->tacticalPlayer18);
    if (battle->pendingEndOfActionFlag48 != 0 && player->nationIndex1C == ActiveNationSlot() &&
        player->notWatchedFlagE == 0) {
      return true;
    }
    if (guard-- <= 0) {
      return false;
    }
    battle->NextMove();
  }
  return true;
}

bool AutoArmyBattleToCommit(TArmyBattle* battle) {
  TArmyPlayer* ourPlayer = static_cast<TArmyPlayer*>(battle->tacticalPlayer14);
  TArmyPlayer* enemyPlayer = static_cast<TArmyPlayer*>(battle->tacticalPlayer18);
  int guard = 20000;
  ourPlayer->notWatchedFlagE = 1;
  enemyPlayer->notWatchedFlagE = 1;
  if (battle->pendingEndOfActionFlag48 != 0) {
    TArmyPlayer* current = battle->currentSideC == 0 ? ourPlayer : enemyPlayer;
    current->AdvanceTacticalTurnPulse();
  }
  while (battle->battleOutcome44 == kTacticalBattleInProgress) {
    if (guard-- <= 0) {
      return false;
    }
    battle->NextMove();
  }
  battle->NextMove();
  return true;
}

void ClearAllMilitaryOrders() {
  int slot;
  for (slot = 0; slot < kNationSlotCount; ++slot) {
    TCountry* country = g_apTerrainTypeDescriptorTable[slot];
    if (country == 0 || country->militaryUnitList44 == 0) {
      continue;
    }
    CIterator cursor(country->militaryUnitList44);
    TMilitaryUnit* unit = static_cast<TMilitaryUnit*>(cursor.Reset());
    while (cursor.More() != 0) {
      unit->SetOrders(kUnitOrderIdle, -1);
      unit = static_cast<TMilitaryUnit*>(cursor.Advance());
    }
  }
}

void CollectStackUnitIds(TArmyStack* stack, JsonArray* ids) {
  TArmyStackUnitNode* node;
  for (node = stack->head14; node != 0; node = node->next) {
    if (node->unit != 0) {
      ids->Add(node->unit->persistentUnitId20);
    }
  }
}

// Reads the army manager's cached battle stacks after ResolveNextMove stops on
// a battle view. Returns 0 when no battle is active.
JSON_Value* CaptureActiveBattleJson() {
  TArmyMgr* army = g_pMapContextActionManager;
  TArmyStack* ours = army->ourStackBattle39c;
  TArmyStack* enemy = army->enemyStackBattle3a0;
  JsonObject result;
  JsonArray attackerUnits;
  JsonArray defenderUnits;
  if (army->activeBattleView3a4 == 0 || ours == 0 || enemy == 0) {
    return 0;
  }
  CollectStackUnitIds(ours, &attackerUnits);
  CollectStackUnitIds(enemy, &defenderUnits);
  result.Set("province", static_cast<int>(enemy->tileIndex10));
  result.Set("attacker_nation", static_cast<int>(ours->categoryFlag8));
  result.Set("defender_nation", static_cast<int>(enemy->categoryFlag8));
  result.Set("attacker_units", attackerUnits.Release());
  result.Set("defender_units", defenderUnits.Release());
  return result.Release();
}

// Post-pass roster: every nation's military unit persistent id and tile.
JSON_Value* CaptureMilitaryUnitPositions() {
  JsonArray units;
  int slot;
  for (slot = 0; slot < kNationSlotCount; ++slot) {
    TCountry* country = g_apTerrainTypeDescriptorTable[slot];
    CIterator cursor(country == 0 ? 0 : country->militaryUnitList44);
    TMilitaryUnit* unit;
    if (country == 0 || country->militaryUnitList44 == 0) {
      continue;
    }
    unit = static_cast<TMilitaryUnit*>(cursor.Reset());
    while (cursor.More() != 0) {
      JsonObject entry;
      entry.Set("id", unit->persistentUnitId20);
      entry.Set("tile", static_cast<int>(unit->tileIndex06));
      units.Add(entry.Release());
      unit = static_cast<TMilitaryUnit*>(cursor.Advance());
    }
  }
  return units.Release();
}

bool IssueUncontestedRedeploys(TMilitaryUnit* skip, int* issued) {
  int slot;
  *issued = 0;
  for (slot = 0; slot < kNationSlotCount; ++slot) {
    TCountry* country = g_apTerrainTypeDescriptorTable[slot];
    CIterator cursor(country == 0 ? 0 : country->militaryUnitList44);
    TMilitaryUnit* unit;
    if (country == 0 || country->militaryUnitList44 == 0) {
      continue;
    }
    unit = static_cast<TMilitaryUnit*>(cursor.Reset());
    while (cursor.More() != 0) {
      const short source = unit->tileIndex06;
      Province* record;
      int adj;
      if (unit != skip && source >= 0 && source < 0x180) {
        record = &g_pGlobalMapState->cityScoreTable[source];
        for (adj = 0; adj < record->adjacentRegionCount08; ++adj) {
          const short dest = record->adjacentRegionIds0A[adj];
          if (dest >= 0 && dest < 0x180 &&
              g_pGlobalMapState->cityScoreTable[dest].ownerNationCode00 ==
                  record->ownerNationCode00) {
            unit->SetOrders(kUnitOrderRedeploy, dest);
            *issued += 1;
            break;
          }
        }
      }
      unit = static_cast<TMilitaryUnit*>(cursor.Advance());
    }
  }
  return *issued != 0;
}

bool FindUncontestedRedeploy(TMilitaryUnit** outUnit, short* outDest, TMilitaryUnit* skip) {
  int slot;
  for (slot = 0; slot < kNationSlotCount; ++slot) {
    TCountry* country = g_apTerrainTypeDescriptorTable[slot];
    CIterator cursor(country == 0 ? 0 : country->militaryUnitList44);
    TMilitaryUnit* unit;
    if (country == 0 || country->militaryUnitList44 == 0) {
      continue;
    }
    unit = static_cast<TMilitaryUnit*>(cursor.Reset());
    while (cursor.More() != 0) {
      const short source = unit->tileIndex06;
      Province* record;
      int adj;
      if (unit != skip && source >= 0 && source < 0x180) {
        record = &g_pGlobalMapState->cityScoreTable[source];
        for (adj = 0; adj < record->adjacentRegionCount08; ++adj) {
          const short dest = record->adjacentRegionIds0A[adj];
          if (dest >= 0 && dest < 0x180 &&
              g_pGlobalMapState->cityScoreTable[dest].ownerNationCode00 ==
                  record->ownerNationCode00) {
            *outUnit = unit;
            *outDest = dest;
            return true;
          }
        }
      }
      unit = static_cast<TMilitaryUnit*>(cursor.Advance());
    }
  }
  return false;
}

bool FindHostileRedeployExcluding(TMilitaryUnit* skipUnit, short skipDest, TMilitaryUnit** outUnit,
                                  short* outDest, short* outDefender) {
  int slot;
  for (slot = 0; slot < kNationSlotCount; ++slot) {
    TCountry* country = g_apTerrainTypeDescriptorTable[slot];
    CIterator cursor(country == 0 ? 0 : country->militaryUnitList44);
    TMilitaryUnit* unit;
    if (country == 0 || country->militaryUnitList44 == 0) {
      continue;
    }
    unit = static_cast<TMilitaryUnit*>(cursor.Reset());
    while (cursor.More() != 0) {
      const short source = unit->tileIndex06;
      Province* record;
      int adj;
      if (unit != skipUnit && source >= 0 && source < 0x180) {
        record = &g_pGlobalMapState->cityScoreTable[source];
        for (adj = 0; adj < record->adjacentRegionCount08; ++adj) {
          const short dest = record->adjacentRegionIds0A[adj];
          short defender;
          if (dest < 0 || dest >= 0x180 || dest == skipDest) {
            continue;
          }
          if (g_pGlobalMapState->cityScoreTable[dest].ownerNationCode00 ==
                  record->ownerNationCode00 ||
              g_pGlobalMapState->cityScoreTable[dest].stationedUnitChain98 == 0) {
            continue;
          }
          defender = g_pGlobalMapState->ResolveTileOwnerNationCodeNormalized(dest);
          if (defender < 0) {
            continue;
          }
          *outUnit = unit;
          *outDest = dest;
          *outDefender = defender;
          return true;
        }
      }
      unit = static_cast<TMilitaryUnit*>(cursor.Advance());
    }
  }
  return false;
}

bool FindHostileRedeploy(TMilitaryUnit** outUnit, short* outDest, short* outDefender) {
  return FindHostileRedeployExcluding(0, -1, outUnit, outDest, outDefender);
}

void ForceWarBetween(short left, short right) {
  g_pDiplomacyTurnStateManager->relationPropagationMatrix[left * kNationSlotCount + right] =
      kDiplomacyRelationshipWar;
  g_pDiplomacyTurnStateManager->relationPropagationMatrix[right * kNationSlotCount + left] =
      kDiplomacyRelationshipWar;
}

TZone* FindUnoccupiedMapZone() {
  TZone* candidate;
  for (candidate = g_pMapActionContextListHead; candidate != 0; candidate = candidate->prev18) {
    int occupied = 0;
    TShip* ship;
    for (ship = g_pNavyPrimaryOrderListHead; ship != 0; ship = ship->next) {
      if (ship->location == candidate) {
        occupied = 1;
        break;
      }
    }
    if (occupied == 0) {
      return candidate;
    }
  }
  return 0;
}

TTaskForce* CreateFrigateForce(TZone* zone, short nation, int shipCount, int orders,
                               void* orderTarget) {
  int i;
  TTaskForce* force;
  for (i = 0; i < shipCount; ++i) {
    TShip* ship = new TShip();
    ship->IShip(3, zone, nation, "navy-tactical");
  }
  force = zone->CreateTaskForceFromNavyOrdersForNationIfEligible(nation);
  if (force != 0) {
    force->SubmitOrders(orders, orderTarget);
  }
  return force;
}

void ProbeNavyDeployTiles(TNavyBattle* battle, TTacticalUnit* unit, JsonArray* tiles) {
  TTacticalPlayer* player;
  TTacticalUnit* savedSelected;
  TTacticalUnit* occupant;
  int savedTile;
  int savedCursor;
  int savedSide;
  int savedLive;
  char savedReady;
  int tile;
  if (unit == 0) {
    return;
  }
  player = (&battle->tacticalPlayer14)[unit->side20];
  savedTile = unit->tileIndex8;
  savedReady = player->sideReadyFlag10;
  savedCursor = player->cursorIndex18;
  savedSelected = battle->selectedUnit1c;
  savedSide = battle->currentSideC;
  savedLive = battle->battleLive10;
  for (tile = 0; tile < battle->tacticalTileCount3c; ++tile) {
    occupant = battle->tileGrid4[tile].occupant4;
    battle->DeployTacticalUnitToTile(unit, tile);
    if (unit->tileIndex8 == tile) {
      tiles->Add(tile);
      unit->tileIndex8 = savedTile;
      battle->tileGrid4[tile].occupant4 = occupant;
      player->sideReadyFlag10 = savedReady;
      player->cursorIndex18 = savedCursor;
      battle->selectedUnit1c = savedSelected;
      battle->currentSideC = savedSide;
      battle->battleLive10 = savedLive;
    }
  }
}

JSON_Value* CaptureNavyTacticalInit(TTaskForce* ourForce, TTaskForce* enemyForce) {
  TNavyBattle* battle;
  TNavyHumanPlayer* ourPlayer;
  TNavyAutoPlayer* enemyPlayer;
  TTacticalUnit* side0Unit;
  TTacticalUnit* side1Unit;
  JsonObject snapshot;
  JsonArray side0Tiles;
  JsonArray side1Tiles;

  battle = new TNavyBattle();
  battle->recordList20 = new TList();
  ourPlayer = new TNavyHumanPlayer();
  ourPlayer->INavyHumanPlayer(ourForce, 1, ourForce->nation);
  ourPlayer->secondaryList8 = new TList();
  enemyPlayer = new TNavyAutoPlayer();
  enemyPlayer->INavyAutoPlayer(enemyForce, 0, enemyForce->nation);
  enemyPlayer->secondaryList8 = new TList();
  battle->InitTacticalBattle(ourPlayer, enemyPlayer);

  side0Unit = static_cast<TTacticalUnit*>(ourPlayer->unitList4->GetEntryByOrdinal(1));
  side1Unit = static_cast<TTacticalUnit*>(enemyPlayer->unitList4->GetEntryByOrdinal(1));
  ProbeNavyDeployTiles(battle, side0Unit, &side0Tiles);
  ProbeNavyDeployTiles(battle, side1Unit, &side1Tiles);

  snapshot.Set("column_count", battle->battlefieldColumnCount34);
  snapshot.Set("current_side", battle->currentSideC);
  snapshot.Set("side0_nation", ourPlayer->nationIndex1C);
  snapshot.Set("side1_nation", enemyPlayer->nationIndex1C);
  snapshot.Set("side0_selected", side0Unit != 0 ? static_cast<int>(side0Unit->selectedFlag18) : 0);
  snapshot.Set("side1_selected", side1Unit != 0 ? static_cast<int>(side1Unit->selectedFlag18) : 0);
  snapshot.Set("side0_tiles", side0Tiles.Release());
  snapshot.Set("side1_tiles", side1Tiles.Release());

  battle->Free();
  return snapshot.Release();
}

short FirstHostileNation(short activeNation) {
  short nation;
  for (nation = 0; nation < kMajorNationCount; ++nation) {
    if (nation != activeNation && g_apNationStates[nation] != 0) {
      return nation;
    }
  }
  return -1;
}

} // namespace

RuntimeActionResult RunSpecialistRecruitment(NativeTransition& transition) {
  TGreatPower* nation = ActiveNation();

  JsonObject args;
  args.Set("nation", static_cast<int>(ActiveNationSlot()));
  args.Set("unit_kind", "sappers");
  args.Set("quantity", 1);
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }

  TUnitOrder order;
  order.IUnitOrder(nation->city, 24, -1, 0, -1, 0, 0, kHighSkillWorkforceMode, 1);
  order.quantity = 1;
  order.Produce();
  return transition.Finish();
}

RuntimeActionResult RunMilitaryMaintenance(NativeTransition& transition) {
  const NationSlot nationSlot = ActiveNationSlot();
  TGreatPower* nation = ActiveNation();
  const NationSlot foreignNationSlot = nationSlot == 0 ? 1 : 0;

  while (nation->militaryUnitList44->GetCount() != 0) {
    TMilitaryUnit* unit =
        static_cast<TMilitaryUnit*>(nation->militaryUnitList44->GetEntryByOrdinal(1));
    unit->DetachUnitOrderFromOwnerAndReset();
    unit->Free();
  }

  TMilitaryUnit* ownedMinutemen = new TMilitaryUnit();
  ownedMinutemen->IMilitaryUnit(EncodeMilitaryUnitKind(kMilitaryUnitMinutemen), -1, nationSlot);
  TMilitaryUnit* ownedArtillery = new TMilitaryUnit();
  ownedArtillery->IMilitaryUnit(EncodeMilitaryUnitKind(kMilitaryUnitLightArtillery), -1,
                                nationSlot);
  TMilitaryUnit* ownedArmor = new TMilitaryUnit();
  ownedArmor->IMilitaryUnit(EncodeMilitaryUnitKind(kMilitaryUnitArmor), -1, nationSlot);
  TMilitaryUnit* foreignArmor = new TMilitaryUnit();
  foreignArmor->IMilitaryUnit(EncodeMilitaryUnitKind(kMilitaryUnitArmor), -1, foreignNationSlot);

  TShip* ownedSlot3 = new TShip();
  ownedSlot3->IShip(3, g_pMapActionContextListHead, nationSlot, "maintenance-owned-slot3");
  TShip* ownedSlot9 = new TShip();
  ownedSlot9->IShip(9, g_pMapActionContextListHead, nationSlot, "maintenance-owned-slot9");
  TShip* ownedSlot12 = new TShip();
  ownedSlot12->IShip(12, g_pMapActionContextListHead, nationSlot, "maintenance-owned-slot12");
  TShip* foreignSlot12 = new TShip();
  foreignSlot12->IShip(12, g_pMapActionContextListHead, foreignNationSlot,
                       "maintenance-foreign-slot12");

  nation->treasuryValue10 = 10000;
  nation->militaryExpenses960 = 0;

  JsonObject args;
  args.Set("nation", static_cast<int>(nationSlot));
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }

  nation->PayForMilitary();
  return transition.Finish();
}

// Complete recovered phase; in particular, its army cleanup precedes navy work.
RuntimeActionResult RunMilitaryPhase(NativeTransition& transition) {
  g_pSimMgr->economicTurn = 6;

  JsonObject args;
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }

  // Deterministic CRT seed so retail-vs-recomp differentials see identical
  // rand() streams (military AI consumes rand()).
  srand(0x1234);
  g_pSimMgr->DoMilitary();
  return transition.Finish();
}

RuntimeActionResult RunSecondTurnMilitaryPhase(NativeTransition& transition) {
  g_pSimMgr->economicTurn = 2;

  JsonObject args;
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }

  // Deterministic CRT seed for retail-vs-recomp rand() parity in DoMilitary.
  srand(0x1234);
  g_pSimMgr->DoMilitary();
  return transition.Finish();
}

RuntimeActionResult RunMilitaryPhaseShipsWithoutOrders(NativeTransition& transition) {
  // Deterministic CRT seed for retail-vs-recomp rand() parity in DoMilitary.
  srand(0x1234);
  g_pSimMgr->economicTurn = 6;
  TZone* zone = g_pActiveMapOrderContext->FindFirstPortZoneContextByNation(ActiveNationSlot());
  if (zone == 0) {
    return RuntimeActionResult::Failure("the fixture has no active-nation port zone");
  }
  TShip* damaged = new TShip();
  damaged->IShip(3, zone, ActiveNationSlot(), "military-unordered-damaged");
  damaged->strength = 1;
  TShip* ready = new TShip();
  ready->IShip(9, zone, ActiveNationSlot(), "military-unordered-ready");

  JsonObject args;
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }
  g_pSimMgr->DoMilitary();
  return transition.Finish();
}

RuntimeActionResult RunMilitaryPhaseNavalEncounterImpl(NativeTransition& transition,
                                                       short attackerType, short defenderType) {
  // Deterministic CRT seed so the retail-vs-recomp differential sees identical
  // rand() streams through ship setup and DoMilitary.
  srand(0x1234);
  const short activeNation = ActiveNationSlot();
  short hostileNation = -1;
  for (short nation = 0; nation < kMajorNationCount; ++nation) {
    if (nation != activeNation && g_apNationStates[nation] != 0) {
      hostileNation = nation;
      break;
    }
  }
  TZone* zone = 0;
  for (TZone* candidate = g_pMapActionContextListHead; candidate != 0;
       candidate = candidate->prev18) {
    bool occupied = false;
    for (TShip* ship = g_pNavyPrimaryOrderListHead; ship != 0; ship = ship->next) {
      if (ship->location == candidate) {
        occupied = true;
        break;
      }
    }
    if (!occupied) {
      zone = candidate;
      break;
    }
  }
  if (hostileNation < 0 || zone == 0) {
    return RuntimeActionResult::Failure("the fixture cannot create a naval encounter");
  }

  TShip* attackerShip = new TShip();
  attackerShip->IShip(attackerType, zone, activeNation, "military-encounter-attacker");
  TTaskForce* attacker = zone->CreateTaskForceFromNavyOrdersForNationIfEligible(activeNation);
  if (attacker == 0) {
    return RuntimeActionResult::Failure("could not create the attacking task force");
  }
  attacker->SubmitOrders(3, 0);

  TShip* defenderShip = new TShip();
  defenderShip->IShip(defenderType, zone, hostileNation, "military-encounter-defender");
  TTaskForce* defender = zone->CreateTaskForceFromNavyOrdersForNationIfEligible(hostileNation);
  if (defender == 0) {
    return RuntimeActionResult::Failure("could not create the defending task force");
  }
  defender->SubmitOrders(6, zone);
  ForceWarBetween(activeNation, hostileNation);

  JsonObject args;
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }
  g_pSimMgr->DoMilitary();

  // Retail resolves the encounter by attrition and may free one or both task
  // forces, so `attacker`/`defender` are dangling here -- do not touch them.

  return transition.Finish();
}

RuntimeActionResult RunMilitaryPhaseNavalEncounter(NativeTransition& transition) {
  return RunMilitaryPhaseNavalEncounterImpl(transition, 3, 3);
}

RuntimeActionResult RunMilitaryPhaseNavalEscalation(NativeTransition& transition) {
  // Tier-3 attacker vs tier-1 defender so ResolveStrategicBattle's
  // favor-ratio tier escalation actually engages.
  return RunMilitaryPhaseNavalEncounterImpl(transition, 9, 3);
}

bool ProductionNavyShipSurvived(TShip* expected) {
  for (TShip* ship = g_pNavyPrimaryOrderListHead; ship != 0; ship = ship->next) {
    if (ship == expected) {
      return true;
    }
  }
  return false;
}

bool ProductionTaskForceRemainsQueued(TTaskForce* expected) {
  if (g_pNavyOrderManager == 0) {
    return false;
  }
  for (TTaskForce* force = g_pNavyOrderManager->orderQueueHead; force != 0;
       force = force->nextForce) {
    if (force == expected) {
      return true;
    }
  }
  return false;
}

JSON_Value* CaptureProductionNavalSide(TTaskForce* force, TShip* ship, TAdmiral* admiral) {
  JsonObject side;
  const bool survived = ProductionNavyShipSurvived(ship);
  const bool queued = ProductionTaskForceRemainsQueued(force);
  side.Set("survived", survived);
  side.Set("force_queued", queued);
  side.Set("defeated", queued ? force->defeated != 0 : !survived);
  if (survived) {
    side.Set("strength", static_cast<int>(ship->strength));
    side.Set("experience", static_cast<int>(ship->experience));
    side.Set("admiral_experience",
             ship->admiral == admiral ? static_cast<int>(admiral->experiencePoints) : -1);
  } else {
    side.SetNull("strength");
    side.SetNull("experience");
    side.SetNull("admiral_experience");
  }
  return side.Release();
}

JSON_Value* CaptureProductionNavalReportSide(const MapContextActionRecord* report, int sideIndex) {
  JsonArray ships;
  for (int index = 0; index < report->childCount24a[sideIndex]; ++index) {
    const MapOrderBattleSideChildRecord& child = report->sideChildRecords250[sideIndex][index];
    JsonObject ship;
    ship.Set("type", static_cast<int>(child.resourceType));
    ship.Set("strength", static_cast<int>(child.stockOrRequired));
    ship.Set("experience_bucket", static_cast<int>(child.strengthBucket));
    ships.Add(ship.Release());
  }
  return ships.Release();
}

RuntimeActionResult RunMilitaryPhaseNavalTierExhaustion(NativeTransition& transition) {
  srand(0x1234);
  const short activeNation = ActiveNationSlot();
  short hostileNation = -1;
  for (short nation = 0; nation < kMajorNationCount; ++nation) {
    if (nation != activeNation && g_apNationStates[nation] != 0) {
      hostileNation = nation;
      break;
    }
  }
  TZone* zone = FindUnoccupiedMapZone();
  if (hostileNation < 0 || zone == 0 || g_pNavyOrderManager == 0 ||
      g_pMapContextActionManager == 0 ||
      g_pMapContextActionManager->mapContextActionRecordList04 == 0) {
    return RuntimeActionResult::Failure("the fixture cannot create a controlled naval encounter");
  }

  TShip* attackerShip = new TShip();
  attackerShip->IShip(3, zone, activeNation, "tier-exhaustion-attacker");
  attackerShip->strength = 100;
  attackerShip->experience = 0;
  TTaskForce* attacker = zone->CreateTaskForceFromNavyOrdersForNationIfEligible(activeNation);
  if (attacker == 0) {
    return RuntimeActionResult::Failure("could not create the tier-exhaustion attacker");
  }
  attacker->SetAggression(1);
  attacker->defeated = 0;
  attacker->SubmitOrders(3, 0);
  TAdmiral* attackerAdmiral = new TAdmiral(activeNation);
  attackerAdmiral->experiencePoints = 0;
  attackerAdmiral->AssignToShip(attacker->flagship);

  TShip* defenderShip = new TShip();
  defenderShip->IShip(3, zone, hostileNation, "tier-exhaustion-defender");
  defenderShip->strength = 100;
  defenderShip->experience = 0;
  TTaskForce* defender = zone->CreateTaskForceFromNavyOrdersForNationIfEligible(hostileNation);
  if (defender == 0) {
    return RuntimeActionResult::Failure("could not create the tier-exhaustion defender");
  }
  defender->SetAggression(1);
  defender->defeated = 0;
  defender->SubmitOrders(6, zone);
  TAdmiral* defenderAdmiral = new TAdmiral(hostileNation);
  defenderAdmiral->experiencePoints = 100;
  defenderAdmiral->AssignToShip(defender->flagship);
  ForceWarBetween(activeNation, hostileNation);

  TSortedPtrList* reports = g_pMapContextActionManager->mapContextActionRecordList04;
  const int reportCountBefore = reports->GetSize();
  JsonObject args;
  args.Set("report_count_before", reportCountBefore);
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }
  g_pSimMgr->preferenceValues[1] = 0;
  g_pSimMgr->DoMilitary();
  if (reports->GetSize() != reportCountBefore + 1) {
    return RuntimeActionResult::Failure(
        "controlled production naval battle did not append one report");
  }

  MapContextActionRecord* report = static_cast<MapContextActionRecord*>(
      reports->GetPtrListEntryByOneBasedIndex(reportCountBefore + 1));
  if (!ProductionNavyShipSurvived(attackerShip) || !ProductionNavyShipSurvived(defenderShip) ||
      !ProductionTaskForceRemainsQueued(attacker) || !ProductionTaskForceRemainsQueued(defender) ||
      attackerShip->strength != 100 || defenderShip->strength != 100 ||
      (attacker->defeated != 0) == (defender->defeated != 0)) {
    return RuntimeActionResult::Failure(
        "controlled naval battle did not exhaust tiers with both fleets afloat");
  }
  const int participant =
      static_cast<int>(static_cast<signed char>(report->reportParticipantIndex02));
  JsonObject outcome;
  outcome.Set("participant", participant);
  outcome.Set("winner", participant == 0 ? "left" : participant == 1 ? "right" : "draw");
  outcome.Set("left", CaptureProductionNavalSide(attacker, attackerShip, attackerAdmiral));
  outcome.Set("right", CaptureProductionNavalSide(defender, defenderShip, defenderAdmiral));
  outcome.Set("left_report_ships", CaptureProductionNavalReportSide(report, 0));
  outcome.Set("right_report_ships", CaptureProductionNavalReportSide(report, 1));

  JsonObject result;
  result.Set("naval_outcome", outcome.Release());
  return transition.Finish(result.Release());
}

RuntimeActionResult RunStrategicNavalBattleMatrix(NativeTransition& transition) {
  const short activeNation = ActiveNationSlot();
  short hostileNation = -1;
  for (short nation = 0; nation < kMajorNationCount; ++nation) {
    if (nation != activeNation && g_apNationStates[nation] != 0) {
      hostileNation = nation;
      break;
    }
  }
  TZone* zone = FindUnoccupiedMapZone();
  if (g_pNavyOrderManager == 0 || g_pMapContextActionManager == 0 ||
      g_pMapContextActionManager->mapContextActionRecordList04 == 0 || hostileNation < 0 ||
      zone == 0) {
    return RuntimeActionResult::Failure("strategic naval matrix state is unavailable");
  }

  JsonObject args;
  args.Set("case_count",
           static_cast<int>(sizeof(kStrategicBattleMatrix) / sizeof(kStrategicBattleMatrix[0])));
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }

  JsonArray rows;
  const int caseCount =
      static_cast<int>(sizeof(kStrategicBattleMatrix) / sizeof(kStrategicBattleMatrix[0]));
  for (int caseIndex = 0; caseIndex < caseCount; ++caseIndex) {
    const StrategicBattleMatrixCase& testCase = kStrategicBattleMatrix[caseIndex];
    StrategicBattleFleet left = CreateStrategicBattleFleet(
        zone, activeNation, testCase.leftTypes, testCase.leftCount, testCase.leftAggression,
        testCase.leftStrength, testCase.leftExperience, testCase.leftAdmiralExperience, caseIndex,
        'l');
    StrategicBattleFleet right = CreateStrategicBattleFleet(
        zone, hostileNation, testCase.rightTypes, testCase.rightCount, testCase.rightAggression,
        testCase.rightStrength, testCase.rightExperience, testCase.rightAdmiralExperience,
        caseIndex, 'r');

    TSortedPtrList* reports = g_pMapContextActionManager->mapContextActionRecordList04;
    const int reportCountBefore = reports->GetSize();
    srand(testCase.seed);
    g_pNavyOrderManager->ResolveStrategicBattle(left.force, right.force);
    if (reports->GetSize() != reportCountBefore + 1) {
      FreeStrategicBattleFleet(left);
      FreeStrategicBattleFleet(right);
      return RuntimeActionResult::Failure("strategic naval battle did not append one report");
    }
    MapContextActionRecord* report = static_cast<MapContextActionRecord*>(
        reports->GetPtrListEntryByOneBasedIndex(reportCountBefore + 1));
    const int participant =
        static_cast<int>(static_cast<signed char>(report->reportParticipantIndex02));
    const int leftDefeated = left.force->defeated != 0;
    const int rightDefeated = right.force->defeated != 0;

    JsonObject row;
    row.Set("case", testCase.name);
    row.Set("seed", testCase.seed);
    row.Set("convergence", testCase.convergence);
    row.Set("resolution", testCase.resolution);
    row.Set("participant", participant);
    row.Set("winner", participant == 0 ? "left" : participant == 1 ? "right" : "draw");
    row.Set("left_defeated", leftDefeated != 0);
    row.Set("right_defeated", rightDefeated != 0);
    row.Set("left", CaptureStrategicBattleFleet(left, testCase.leftTypes, testCase.leftAggression,
                                                testCase.leftStrength, testCase.leftExperience,
                                                testCase.leftAdmiralExperience));
    row.Set("right",
            CaptureStrategicBattleFleet(right, testCase.rightTypes, testCase.rightAggression,
                                        testCase.rightStrength, testCase.rightExperience,
                                        testCase.rightAdmiralExperience));
    rows.Add(row.Release());

    FreeStrategicBattleFleet(left);
    FreeStrategicBattleFleet(right);
  }

  JsonObject result;
  result.Set("cases", rows.Release());
  return transition.Finish(result.Release());
}

RuntimeActionResult RunMilitaryPhaseLandCombat(NativeTransition& transition) {
  // Deterministic CRT seed so the retail-vs-recomp differential sees identical
  // rand() streams through order issuing and combat resolution.
  srand(0x1234);
  ClearAllMilitaryOrders();
  TMilitaryUnit* unit = 0;
  short dest = -1;
  short defender = -1;
  if (!FindHostileRedeploy(&unit, &dest, &defender)) {
    return RuntimeActionResult::Failure(
        "the loaded fixture has no adjacent enemy-garrisoned province");
  }
  ForceWarBetween(unit->ownerNationSlot18, defender);
  unit->SetOrders(kUnitOrderRedeploy, dest);

  JsonObject args;
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }

  g_pSimMgr->preferenceValues[0] = 0;
  g_pMapContextActionManager->DoCombatMoves();
  TArmyBattle* battle = g_pMapContextActionManager->activeBattleView3a4;
  int guard = 20000;
  while (battle != 0 && battle->battleOutcome44 == kTacticalBattleInProgress) {
    if (guard-- <= 0) {
      return RuntimeActionResult::Failure("tactical auto did not terminate");
    }
    battle->NextMove();
  }

  return transition.Finish();
}

RuntimeActionResult RunMilitaryPhaseLandInteractive(NativeTransition& transition) {
  // Same hostile redeploy as RunMilitaryPhaseLandCombat, but with the attacker
  // made the active nation and the real TArmyMgr::DoCombatMoves entry. The
  // battle is then pumped to the active nation's input, "Done" is posted via
  // FinishTacticalActionAndPostNextMoveCommand, and the rest auto-resolves.
  srand(0x1234);
  ClearAllMilitaryOrders();
  TMilitaryUnit* unit = 0;
  short dest = -1;
  short defender = -1;
  if (!FindHostileRedeploy(&unit, &dest, &defender)) {
    return RuntimeActionResult::Failure(
        "the loaded fixture has no adjacent enemy-garrisoned province");
  }
  ForceWarBetween(unit->ownerNationSlot18, defender);
  unit->SetOrders(kUnitOrderRedeploy, dest);
  g_pSimMgr->activeNationSlot = unit->ownerNationSlot18;

  JsonObject args;
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }

  g_pSimMgr->preferenceValues[0] = 0;
  g_pMapContextActionManager->DoCombatMoves();
  TArmyBattle* battle = g_pMapContextActionManager->activeBattleView3a4;
  if (battle == 0) {
    return RuntimeActionResult::Failure("hostile orders did not create a land battle");
  }
  StopActiveNationArmyPlayerForInput(battle);
  if (!PumpArmyBattleToActiveNationInput(battle)) {
    return RuntimeActionResult::Failure("tactical battle did not reach active-nation input");
  }
  battle->FinishTacticalActionAndPostNextMoveCommand();
  if (!PumpArmyBattleToActiveNationInput(battle)) {
    return RuntimeActionResult::Failure("Done did not reach the next active-nation input");
  }
  if (!AutoArmyBattleToCommit(battle)) {
    return RuntimeActionResult::Failure("tactical auto did not terminate after Done");
  }
  return transition.Finish();
}

RuntimeActionResult RunMilitaryPhaseLandRetreat(NativeTransition& transition) {
  // Mirror of RunInteractiveArmyBattleRetreat through the production
  // TArmyMgr::DoCombatMoves entry: pump to the active nation's input, then
  // order the retreat (fieldF=1 + stance profile 0 + turn pulse) and
  // auto-resolve to a decision.
  srand(0x1234);
  ClearAllMilitaryOrders();
  TMilitaryUnit* unit = 0;
  short dest = -1;
  short defender = -1;
  if (!FindHostileRedeploy(&unit, &dest, &defender)) {
    return RuntimeActionResult::Failure("fixture has no hostile army redeploy");
  }
  ForceWarBetween(unit->ownerNationSlot18, defender);
  unit->SetOrders(kUnitOrderRedeploy, dest);
  g_pSimMgr->activeNationSlot = unit->ownerNationSlot18;

  JsonObject args;
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }

  g_pSimMgr->preferenceValues[0] = 0;
  g_pMapContextActionManager->DoCombatMoves();
  TArmyBattle* battle = g_pMapContextActionManager->activeBattleView3a4;
  if (battle == 0) {
    return RuntimeActionResult::Failure("land battle was not created");
  }
  StopActiveNationArmyPlayerForInput(battle);
  if (!PumpArmyBattleToActiveNationInput(battle)) {
    return RuntimeActionResult::Failure("battle did not reach active-nation input");
  }
  TArmyPlayer* player = static_cast<TArmyPlayer*>(
      battle->currentSideC == 0 ? battle->tacticalPlayer14 : battle->tacticalPlayer18);
  player->fieldF = 1;
  player->notWatchedFlagE = 1;
  player->SelectAndApplyTacticalCursorModeProfile(0);
  player->AdvanceTacticalTurnPulse();
  if (!AutoArmyBattleToCommit(battle)) {
    return RuntimeActionResult::Failure("retreat did not terminate");
  }
  return transition.Finish();
}

RuntimeActionResult RunNavyBattleAcceptedDeployTiles(NativeTransition& transition) {
  const short activeNation = ActiveNationSlot();
  short hostileNation = FirstHostileNation(activeNation);
  TZone* zone = FindUnoccupiedMapZone();
  TTaskForce* attacker;
  TTaskForce* defender;
  JsonObject args;
  RuntimeActionResult started;
  JSON_Value* snapshot;
  if (hostileNation < 0 || zone == 0) {
    return RuntimeActionResult::Failure("the fixture cannot create a naval encounter");
  }
  attacker = CreateFrigateForce(zone, activeNation, 2, 3, 0);
  defender = CreateFrigateForce(zone, hostileNation, 2, 6, zone);
  if (attacker == 0 || defender == 0) {
    return RuntimeActionResult::Failure("could not create the naval task forces");
  }
  ForceWarBetween(activeNation, hostileNation);
  started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }
  snapshot = CaptureNavyTacticalInit(attacker, defender);
  return transition.Finish(snapshot);
}

RuntimeActionResult RunNavyBattlePlayerAsDefender(NativeTransition& transition) {
  const short activeNation = ActiveNationSlot();
  short hostileNation = FirstHostileNation(activeNation);
  TZone* zone = FindUnoccupiedMapZone();
  TTaskForce* attacker;
  TTaskForce* defender;
  JsonObject args;
  RuntimeActionResult started;
  JSON_Value* snapshot;
  if (hostileNation < 0 || zone == 0) {
    return RuntimeActionResult::Failure("the fixture cannot create a naval encounter");
  }
  attacker = CreateFrigateForce(zone, hostileNation, 2, 3, 0);
  defender = CreateFrigateForce(zone, activeNation, 2, 6, zone);
  if (attacker == 0 || defender == 0) {
    return RuntimeActionResult::Failure("could not create the naval task forces");
  }
  ForceWarBetween(activeNation, hostileNation);
  started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }
  snapshot = CaptureNavyTacticalInit(defender, attacker);
  return transition.Finish(snapshot);
}

RuntimeActionResult RunAdvisoryMapMissionsCase16(NativeTransition& transition) {
  int slot;
  int found = 0;

  JsonObject args;
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }

  for (slot = 0; slot < 7; ++slot) {
    TGreatPower* nation = g_apNationStates[slot];
    if (nation == 0 || nation->IsKindOf(RUNTIME_CLASS(TAutoGreatPower)) == 0) {
      continue;
    }
    if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(static_cast<short>(slot)) == 0) {
      continue;
    }
    found = 1;
    nation->SelectAndQueueAdvisoryMapMissionsCase16();
  }
  if (found == 0) {
    return RuntimeActionResult::Failure("the loaded fixture has no AutoGreatPower");
  }
  return transition.Finish();
}

RuntimeActionResult RunArmyMovementGiveOrders(NativeTransition& transition) {
  int slot;
  int found = 0;

  JsonObject args;
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }

  for (slot = 0; slot < 7; ++slot) {
    TGreatPower* nation = g_apNationStates[slot];
    if (nation == 0 || nation->IsKindOf(RUNTIME_CLASS(TAutoGreatPower)) == 0) {
      continue;
    }
    if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(static_cast<short>(slot)) == 0) {
      continue;
    }
    found = 1;
    nation->MoveArmy();
  }
  if (found == 0) {
    return RuntimeActionResult::Failure("the loaded fixture has no AutoGreatPower");
  }
  return transition.Finish();
}

RuntimeActionResult RunCombatMovesUncontested(NativeTransition& transition) {
  TMilitaryUnit* unit = 0;
  short dest = -1;
  JSON_Value* battle;
  srand(0x1234);
  ClearAllMilitaryOrders();
  if (!FindUncontestedRedeploy(&unit, &dest, 0)) {
    return RuntimeActionResult::Failure(
        "the loaded fixture has no adjacent same-owner provinces with a stationed unit");
  }
  unit->SetOrders(kUnitOrderRedeploy, dest);

  JsonObject args;
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }

  g_pMapContextActionManager->DoCombatMoves();
  JsonObject result;
  JsonArray battles;
  battle = CaptureActiveBattleJson();
  if (battle != 0) {
    battles.Add(battle);
  }
  result.Set("battles", battles.Release());
  result.Set("units", CaptureMilitaryUnitPositions());
  return transition.Finish(result.Release());
}

RuntimeActionResult RunCombatMovesCreatesBattle(NativeTransition& transition) {
  TMilitaryUnit* unit = 0;
  short dest = -1;
  short defender = -1;
  JSON_Value* battle;
  srand(0x1234);
  ClearAllMilitaryOrders();
  if (!FindHostileRedeploy(&unit, &dest, &defender)) {
    return RuntimeActionResult::Failure(
        "the loaded fixture has no adjacent enemy-garrisoned province");
  }
  ForceWarBetween(unit->ownerNationSlot18, defender);
  unit->SetOrders(kUnitOrderRedeploy, dest);

  JsonObject args;
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }

  g_pMapContextActionManager->DoCombatMoves();
  battle = CaptureActiveBattleJson();
  if (battle == 0) {
    return RuntimeActionResult::Failure("identical orders did not create a land battle");
  }
  JsonObject result;
  JsonArray battles;
  battles.Add(battle);
  result.Set("battles", battles.Release());
  result.Set("units", CaptureMilitaryUnitPositions());
  return transition.Finish(result.Release());
}

RuntimeActionResult RunAutoResolveLandBattle(NativeTransition& transition) {
  TMilitaryUnit* unit = 0;
  short dest = -1;
  short defender = -1;
  TArmyMgr* army;
  TArmyBattle* battle;
  int guard;
  JsonObject args;
  RuntimeActionResult started;

  srand(0x1234);
  ClearAllMilitaryOrders();
  if (!FindHostileRedeploy(&unit, &dest, &defender)) {
    return RuntimeActionResult::Failure(
        "the loaded fixture has no adjacent enemy-garrisoned province");
  }
  ForceWarBetween(unit->ownerNationSlot18, defender);
  unit->SetOrders(kUnitOrderRedeploy, dest);

  started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }

  g_pSimMgr->preferenceValues[0] = 0;
  army = g_pMapContextActionManager;
  army->FormStacks();
  army->nextStackOrdinal10 = 1;
  army->ResolveNextMove();
  battle = army->activeBattleView3a4;
  if (battle == 0) {
    return RuntimeActionResult::Failure("identical orders did not create a land battle");
  }

  guard = 20000;
  while (battle->battleOutcome44 == kTacticalBattleInProgress) {
    if (guard-- <= 0) {
      return RuntimeActionResult::Failure("tactical auto did not terminate");
    }
    battle->NextMove();
  }
  battle->NextMove();
  return transition.Finish();
}

RuntimeActionResult RunInteractiveArmyBattleDone(NativeTransition& transition) {
  TMilitaryUnit* unit = 0;
  short dest = -1;
  short defender = -1;
  TArmyMgr* army;
  TArmyBattle* battle;
  JsonObject args;
  JsonArray snapshots;

  srand(0x1234);
  ClearAllMilitaryOrders();
  if (!FindHostileRedeploy(&unit, &dest, &defender)) {
    return RuntimeActionResult::Failure(
        "the loaded fixture has no adjacent enemy-garrisoned province");
  }
  ForceWarBetween(unit->ownerNationSlot18, defender);
  unit->SetOrders(kUnitOrderRedeploy, dest);
  g_pSimMgr->activeNationSlot = unit->ownerNationSlot18;
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }

  g_pSimMgr->preferenceValues[0] = 0;
  army = g_pMapContextActionManager;
  army->FormStacks();
  army->nextStackOrdinal10 = 1;
  army->ResolveNextMove();
  battle = army->activeBattleView3a4;
  if (battle == 0) {
    return RuntimeActionResult::Failure("identical orders did not create a land battle");
  }
  StopActiveNationArmyPlayerForInput(battle);
  if (!PumpArmyBattleToActiveNationInput(battle)) {
    return RuntimeActionResult::Failure("tactical battle did not reach active-nation input");
  }
  snapshots.Add(CaptureArmyBattleSnapshot(battle));
  battle->FinishTacticalActionAndPostNextMoveCommand();
  if (!PumpArmyBattleToActiveNationInput(battle)) {
    return RuntimeActionResult::Failure("Done did not reach the next active-nation input");
  }
  snapshots.Add(CaptureArmyBattleSnapshot(battle));
  if (!AutoArmyBattleToCommit(battle)) {
    return RuntimeActionResult::Failure("tactical auto did not terminate after Done");
  }
  JsonObject result;
  result.Set("snapshots", snapshots.Release());
  return transition.Finish(result.Release());
}

RuntimeActionResult RunInteractiveArmyBattleMove(NativeTransition& transition) {
  TMilitaryUnit* unit = 0;
  short dest = -1;
  short defender = -1;
  TArmyMgr* army;
  TArmyBattle* battle;
  JsonObject args;
  JsonObject result;
  JsonArray snapshots;
  JsonArray targets;
  JsonArray actuals;
  int reactionStopped = 0;
  int inputGuard = 20;
  int tile;

  srand(0x1234);
  ClearAllMilitaryOrders();
  if (!FindHostileRedeploy(&unit, &dest, &defender)) {
    return RuntimeActionResult::Failure(
        "the loaded fixture has no adjacent enemy-garrisoned province");
  }
  ForceWarBetween(unit->ownerNationSlot18, defender);
  unit->SetOrders(kUnitOrderRedeploy, dest);
  g_pSimMgr->activeNationSlot = unit->ownerNationSlot18;
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }

  g_pSimMgr->preferenceValues[0] = 0;
  army = g_pMapContextActionManager;
  army->FormStacks();
  army->nextStackOrdinal10 = 1;
  army->ResolveNextMove();
  battle = army->activeBattleView3a4;
  if (battle == 0) {
    return RuntimeActionResult::Failure("identical orders did not create a land battle");
  }
  StopActiveNationArmyPlayerForInput(battle);
  if (!PumpArmyBattleToActiveNationInput(battle)) {
    return RuntimeActionResult::Failure("tactical battle did not reach active-nation input");
  }
  snapshots.Add(CaptureArmyBattleSnapshot(battle));
  while (!reactionStopped && battle->battleOutcome44 == kTacticalBattleInProgress &&
         inputGuard-- > 0) {
    int target = -1;
    int bestDistance = 9999;
    TTacticalUnit* moving = battle->selectedUnit1c;
    for (tile = 0; tile < battle->tacticalTileCount3c; ++tile) {
      int enemyTile;
      int distance;
      if (battle->tileMoveCostArray24[tile] <= 0 || battle->tileGrid4[tile].occupant4 != 0) {
        continue;
      }
      distance = 9999;
      for (enemyTile = 0; enemyTile < battle->tacticalTileCount3c; ++enemyTile) {
        TTacticalUnit* occupant = battle->tileGrid4[enemyTile].occupant4;
        if (occupant != 0 && occupant->side20 != moving->side20) {
          int candidate = ComputeHexTileDistanceFromIndices(tile, enemyTile);
          if (candidate < distance) {
            distance = candidate;
          }
        }
      }
      if (distance < bestDistance) {
        bestDistance = distance;
        target = tile;
      }
    }
    if (target < 0) {
      return RuntimeActionResult::Failure(
          "selected tactical unit did not reach a reaction-fire move target");
    }
    battle->MoveTacticalUnitAndQueueEvent232AIfNoAdjacentReachableTarget(moving, target);
    targets.Add(target);
    actuals.Add(moving->tileIndex8);
    reactionStopped = moving->tileIndex8 != target;
    if (!PumpArmyBattleToActiveNationInput(battle)) {
      return RuntimeActionResult::Failure("Move did not reach the next active-nation input");
    }
    snapshots.Add(CaptureArmyBattleSnapshot(battle));
  }
  if (!reactionStopped) {
    return RuntimeActionResult::Failure("fixture did not produce reaction-stopped movement");
  }
  result.Set("targets", targets.Release());
  result.Set("actuals", actuals.Release());
  result.Set("snapshots", snapshots.Release());
  if (!AutoArmyBattleToCommit(battle)) {
    return RuntimeActionResult::Failure("tactical auto did not terminate after Move");
  }
  return transition.Finish(result.Release());
}

RuntimeActionResult RunInteractiveArmyBattleAttack(NativeTransition& transition, int hoverState,
                                                   int defenderActive) {
  srand(0x1234);
  TMilitaryUnit* unit = 0;
  short dest = -1;
  short defender = -1;
  TArmyMgr* army;
  TArmyBattle* battle;
  JsonObject args;
  JsonObject result;
  JsonArray kinds;
  JsonArray targets;
  JsonArray actuals;
  JsonArray snapshots;
  int guard = 40;
  int attacked = 0;

  ClearAllMilitaryOrders();
  if (!FindHostileRedeploy(&unit, &dest, &defender)) {
    return RuntimeActionResult::Failure("fixture has no hostile army redeploy");
  }
  ForceWarBetween(unit->ownerNationSlot18, defender);
  unit->SetOrders(kUnitOrderRedeploy, dest);
  g_pSimMgr->activeNationSlot = defenderActive ? defender : unit->ownerNationSlot18;
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }
  g_pSimMgr->preferenceValues[0] = 0;
  army = g_pMapContextActionManager;
  army->FormStacks();
  army->nextStackOrdinal10 = 1;
  army->ResolveNextMove();
  battle = army->activeBattleView3a4;
  if (battle == 0) {
    return RuntimeActionResult::Failure("identical orders did not create a land battle");
  }
  StopActiveNationArmyPlayerForInput(battle);
  if (!PumpArmyBattleToActiveNationInput(battle)) {
    return RuntimeActionResult::Failure("battle did not reach active-nation input");
  }
  snapshots.Add(CaptureArmyBattleSnapshot(battle));
  while (!attacked && battle->battleOutcome44 == kTacticalBattleInProgress && guard-- > 0) {
    int target = -1;
    int tile;
    for (tile = 0; tile < battle->tacticalTileCount3c; ++tile) {
      if (battle->ComputeTacticalHoverCursorStateIndex(tile) == hoverState) {
        target = tile;
        break;
      }
    }
    if (target >= 0) {
      battle->DispatchTacticalActionByHoverStateIndex(target);
      kinds.Add(2);
      targets.Add(target);
      actuals.Add(-1);
      attacked = 1;
    } else if (hoverState == 5) {
      battle->FinishTacticalActionAndPostNextMoveCommand();
      kinds.Add(0);
      targets.Add(-1);
      actuals.Add(-1);
    } else {
      int bestDistance = 9999;
      TTacticalUnit* moving = battle->selectedUnit1c;
      for (tile = 0; tile < battle->tacticalTileCount3c; ++tile) {
        int enemyTile;
        int distance = 9999;
        if (battle->tileMoveCostArray24[tile] <= 0 || battle->tileGrid4[tile].occupant4 != 0) {
          continue;
        }
        for (enemyTile = 0; enemyTile < battle->tacticalTileCount3c; ++enemyTile) {
          TTacticalUnit* occupant = battle->tileGrid4[enemyTile].occupant4;
          if (occupant != 0 && occupant->side20 != moving->side20) {
            int candidate = ComputeHexTileDistanceFromIndices(tile, enemyTile);
            if (candidate < distance)
              distance = candidate;
          }
        }
        if (distance < bestDistance) {
          bestDistance = distance;
          target = tile;
        }
      }
      if (target < 0) {
        battle->FinishTacticalActionAndPostNextMoveCommand();
        kinds.Add(0);
        targets.Add(-1);
        actuals.Add(-1);
      } else {
        battle->MoveTacticalUnitAndQueueEvent232AIfNoAdjacentReachableTarget(moving, target);
        kinds.Add(1);
        targets.Add(target);
        actuals.Add(moving->tileIndex8);
      }
    }
    if (!PumpArmyBattleToActiveNationInput(battle)) {
      return RuntimeActionResult::Failure("input did not return to active nation");
    }
    snapshots.Add(CaptureArmyBattleSnapshot(battle));
  }
  if (!attacked) {
    return RuntimeActionResult::Failure("fixture did not reach requested attack type");
  }
  result.Set("kinds", kinds.Release());
  result.Set("targets", targets.Release());
  result.Set("actuals", actuals.Release());
  result.Set("snapshots", snapshots.Release());
  if (!AutoArmyBattleToCommit(battle)) {
    return RuntimeActionResult::Failure("tactical auto did not terminate after Attack");
  }
  return transition.Finish(result.Release());
}

RuntimeActionResult RunInteractiveArmyBattleMelee(NativeTransition& transition) {
  return RunInteractiveArmyBattleAttack(transition, 0xa, 1);
}

RuntimeActionResult RunInteractiveArmyBattleRanged(NativeTransition& transition) {
  return RunInteractiveArmyBattleAttack(transition, 5, 1);
}

RuntimeActionResult RunInteractiveArmyBattleRetreat(NativeTransition& transition) {
  TMilitaryUnit* unit = 0;
  short dest = -1;
  short defender = -1;
  TArmyMgr* army;
  TArmyBattle* battle;
  JsonObject args;

  srand(0x1234);
  ClearAllMilitaryOrders();
  if (!FindHostileRedeploy(&unit, &dest, &defender)) {
    return RuntimeActionResult::Failure("fixture has no hostile army redeploy");
  }
  ForceWarBetween(unit->ownerNationSlot18, defender);
  unit->SetOrders(kUnitOrderRedeploy, dest);
  g_pSimMgr->activeNationSlot = unit->ownerNationSlot18;
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded())
    return started;
  g_pSimMgr->preferenceValues[0] = 0;
  army = g_pMapContextActionManager;
  army->FormStacks();
  army->nextStackOrdinal10 = 1;
  army->ResolveNextMove();
  battle = army->activeBattleView3a4;
  if (battle == 0)
    return RuntimeActionResult::Failure("land battle was not created");
  StopActiveNationArmyPlayerForInput(battle);
  if (!PumpArmyBattleToActiveNationInput(battle)) {
    return RuntimeActionResult::Failure("battle did not reach active-nation input");
  }
  JSON_Value* initial = CaptureArmyBattleSnapshot(battle);
  TArmyPlayer* player = static_cast<TArmyPlayer*>(
      battle->currentSideC == 0 ? battle->tacticalPlayer14 : battle->tacticalPlayer18);
  player->fieldF = 1;
  player->notWatchedFlagE = 1;
  player->SelectAndApplyTacticalCursorModeProfile(0);
  player->AdvanceTacticalTurnPulse();
  if (!AutoArmyBattleToCommit(battle)) {
    JsonFreeValue(initial);
    return RuntimeActionResult::Failure("retreat did not terminate");
  }
  JsonArray snapshots;
  snapshots.Add(initial);
  JsonObject result;
  result.Set("snapshots", snapshots.Release());
  return transition.Finish(result.Release());
}

// FormStacks once, stop at the first tactical battle, then continue from the
// retained nextStackOrdinal10 without reforming. The first battle is not resolved.
RuntimeActionResult RunCombatMovesResumesAfterBattle(NativeTransition& transition) {
  TMilitaryUnit* firstUnit = 0;
  TMilitaryUnit* secondUnit = 0;
  short firstDest = -1;
  short secondDest = -1;
  short firstDefender = -1;
  short secondDefender = -1;
  TArmyMgr* army;
  JSON_Value* firstBattle;
  JSON_Value* secondBattle;
  JsonObject result;

  srand(0x1234);
  ClearAllMilitaryOrders();
  if (!FindHostileRedeploy(&firstUnit, &firstDest, &firstDefender)) {
    return RuntimeActionResult::Failure(
        "the loaded fixture has no adjacent enemy-garrisoned province");
  }
  if (!FindHostileRedeployExcluding(firstUnit, firstDest, &secondUnit, &secondDest,
                                    &secondDefender)) {
    return RuntimeActionResult::Failure("the loaded fixture has no second distinct hostile stack");
  }
  ForceWarBetween(firstUnit->ownerNationSlot18, firstDefender);
  ForceWarBetween(secondUnit->ownerNationSlot18, secondDefender);
  firstUnit->SetOrders(kUnitOrderRedeploy, firstDest);
  secondUnit->SetOrders(kUnitOrderRedeploy, secondDest);

  JsonObject args;
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }

  army = g_pMapContextActionManager;
  army->DoCombatMoves();
  firstBattle = CaptureActiveBattleJson();
  if (firstBattle == 0) {
    return RuntimeActionResult::Failure("first hostile stack did not create a land battle");
  }
  army->ResolveNextMove();
  secondBattle = CaptureActiveBattleJson();
  if (secondBattle == 0) {
    JsonFreeValue(firstBattle);
    return RuntimeActionResult::Failure(
        "second stack did not create a land battle after the first stop");
  }
  {
    JsonArray battles;
    battles.Add(firstBattle);
    battles.Add(secondBattle);
    result.Set("battles", battles.Release());
  }
  result.Set("units", CaptureMilitaryUnitPositions());
  return transition.Finish(result.Release());
}

RuntimeActionResult RunCombatMovesBattleThenLaterMovement(NativeTransition& transition) {
  TMilitaryUnit* hostile = 0;
  short hostileDest = -1;
  short defender = -1;
  int uncontestedCount = 0;
  TArmyMgr* army;
  JSON_Value* first;
  JSON_Value* second;
  JsonObject result;
  JsonObject args;
  RuntimeActionResult started;

  srand(0x1234);
  ClearAllMilitaryOrders();
  if (!FindHostileRedeploy(&hostile, &hostileDest, &defender)) {
    return RuntimeActionResult::Failure(
        "the loaded fixture has no adjacent enemy-garrisoned province");
  }
  if (!IssueUncontestedRedeploys(hostile, &uncontestedCount)) {
    return RuntimeActionResult::Failure(
        "the loaded fixture has no later same-owner redeploy besides the hostile stack");
  }
  ForceWarBetween(hostile->ownerNationSlot18, defender);
  hostile->SetOrders(kUnitOrderRedeploy, hostileDest);

  started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }

  army = g_pMapContextActionManager;
  army->DoCombatMoves();
  first = CaptureActiveBattleJson();
  if (first == 0) {
    return RuntimeActionResult::Failure("identical orders did not create a land battle");
  }
  if (army->nextStackOrdinal10 > army->pendingUnitPool0c->GetCount()) {
    JsonFreeValue(first);
    return RuntimeActionResult::Failure(
        "the first battle consumed the last stack; no later movement remains");
  }

  army->ResolveNextMove();
  second = CaptureActiveBattleJson();
  {
    JsonArray battles;
    battles.Add(first);
    if (second != 0) {
      battles.Add(second);
    }
    result.Set("battles", battles.Release());
  }
  result.Set("units", CaptureMilitaryUnitPositions());
  return transition.Finish(result.Release());
}

RuntimeActionResult RunSecondTurnMilitaryCleanup(NativeTransition& transition) {
  g_pSimMgr->economicTurn = 2;
  srand(0x1234);

  RuntimeActionResult started = transition.Begin(JsonNullValue());
  if (!started.Succeeded()) {
    return started;
  }

  g_pNavyOrderManager->ClearAllTransientOrders();
  if (g_pSimMgr->multiplayerSessionRole != 2) {
    g_pGlobalMapState->RecomputeTileStrategicScoreHeatmap();
    RecomputeNationOrderPriorityMetrics();
    for (int slot = 0; slot < 7; ++slot) {
      TCountry* country = g_apTerrainTypeDescriptorTable[slot];
      TGreatPower* nation = g_apNationStates[slot];
      if (country != 0 && nation != 0 &&
          (country->encodedNationSlot < 100 || country->encodedNationSlot > 199)) {
        nation->RefreshTrackedEntriesAndReplanAiDevelopment(0);
      }
    }
  }
  for (int slot = 0; slot < 7; ++slot) {
    TCountry* country = g_apTerrainTypeDescriptorTable[slot];
    TGreatPower* nation = g_apNationStates[slot];
    if (country != 0 && nation != 0 &&
        (country->encodedNationSlot < 100 || country->encodedNationSlot > 199)) {
      nation->AddPurchasedItems();
    }
  }
  return transition.Finish();
}

static TAutoGreatPower* ConfigureAiNavalDevelopmentPressure(short* nationSlotOut) {
  TAutoGreatPower* autoNation = 0;
  short nationSlot = -1;
  for (short slot = 0; slot < 7; ++slot) {
    TGreatPower* nation = g_apNationStates[slot];
    if (nation != 0 && nation->IsKindOf(RUNTIME_CLASS(TAutoGreatPower)) != 0 &&
        g_pSimMgr->IsNationSlotEligibleForEventProcessing(slot) != 0) {
      autoNation = static_cast<TAutoGreatPower*>(nation);
      nationSlot = slot;
      break;
    }
  }
  if (autoNation == 0 || g_pMapActionContextListHead == 0) {
    return 0;
  }

  for (int index = 0; index < 16; ++index) {
    autoNation->interiorMinister->orderShortTableBA[index] = 20;
  }

  CIterator iter(autoNation->missionQueue);
  for (TMission* mission = static_cast<TMission*>(iter.Reset()); iter.More();
       mission = static_cast<TMission*>(iter.Advance())) {
    mission->flag10 = 1;
  }
  TControlSeaZoneMission* navyMission = new TControlSeaZoneMission(g_pMapActionContextListHead);
  navyMission->InitializeMissionWithNationIdAndResetPathMarker(nationSlot);
  navyMission->navyState28 = 2;
  navyMission->requiredShipEquipageByCategory[0] = 0.0f;
  navyMission->requiredShipEquipageByCategory[1] = 0.0f;
  navyMission->requiredShipEquipageByCategory[2] = 0.0f;
  navyMission->requiredShipEquipageByCategory[3] = 1000.0f;
  navyMission->flag10 = 0;
  autoNation->missionQueue->AddTail(navyMission);
  if (g_pMapActionContextListHead->primaryNeighbors.GetSize() != 0) {
    TShip* ship = new TShip();
    ship->IShip(4, g_pMapActionContextListHead->primaryNeighbors.GetAt(0), nationSlot,
                "naval-development-distance-weight");
    ship->strength = ship->GetMaxStrength();
    navyMission->AcceptReenforcement(ship, 0);
  }
  *nationSlotOut = nationSlot;
  return autoNation;
}

RuntimeActionResult RunAiNavalIndustryDevelopment(NativeTransition& transition) {
  short nationSlot = -1;
  TAutoGreatPower* autoNation = ConfigureAiNavalDevelopmentPressure(&nationSlot);
  if (autoNation == 0) {
    return RuntimeActionResult::Failure("AI naval-development fixture has no eligible nation");
  }

  JsonObject args;
  args.Set("nation", static_cast<int>(nationSlot));
  args.Set("average_allocation", 16);
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }

  autoNation->PlanAiDevelopmentActionsFromResourcePools(0);
  return transition.Finish();
}

RuntimeActionResult RunTurnStateAiReplanPerturbed(NativeTransition& transition) {
  short nationSlot = -1;
  if (g_pSimMgr == 0 || ConfigureAiNavalDevelopmentPressure(&nationSlot) == 0) {
    return RuntimeActionResult::Failure("AI replan fixture has no eligible nation");
  }

  g_pSimMgr->economicTurn = 2;
  g_pSimMgr->turnStateCode = 0x15;

  JsonObject args;
  args.Set("nation", static_cast<int>(nationSlot));
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }

  g_pSimMgr->AdvanceGlobalTurnStateMachine();
  return transition.Finish();
}

static bool ConfigureDamagedHostileSeaMission(short* nationSlotOut) {
  int slot;
  TZone* targetZone = 0;
  short missionNation = -1;
  TGreatPower* hostNation = 0;

  for (slot = 0; slot < 7; ++slot) {
    TGreatPower* nation = g_apNationStates[slot];
    if (nation == 0 || nation->IsKindOf(RUNTIME_CLASS(TAutoGreatPower)) == 0) {
      continue;
    }
    if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(static_cast<short>(slot)) == 0) {
      continue;
    }
    TAutoGreatPower* autoNation = static_cast<TAutoGreatPower*>(nation);
    CIterator iter(autoNation->missionQueue);
    for (TMission* mission = static_cast<TMission*>(iter.Reset()); iter.More();
         mission = static_cast<TMission*>(iter.Advance())) {
      if (mission->GetRuntimeClass() == RUNTIME_CLASS(TControlSeaZoneMission)) {
        TControlSeaZoneMission* sea = static_cast<TControlSeaZoneMission*>(mission);
        targetZone = sea->missionTargetZone;
        missionNation = static_cast<short>(slot);
        hostNation = nation;
        break;
      }
    }
    if (targetZone != 0) {
      break;
    }
  }

  if (targetZone == 0) {
    for (slot = 0; slot < 7; ++slot) {
      TGreatPower* nation = g_apNationStates[slot];
      if (nation == 0 || nation->IsKindOf(RUNTIME_CLASS(TAutoGreatPower)) == 0) {
        continue;
      }
      if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(static_cast<short>(slot)) == 0) {
        continue;
      }
      hostNation = nation;
      missionNation = static_cast<short>(slot);
      targetZone = g_pMapActionContextListHead;
      TControlSeaZoneMission* mission = new TControlSeaZoneMission(targetZone);
      mission->InitializeMissionWithNationIdAndResetPathMarker(missionNation);
      static_cast<TAutoGreatPower*>(nation)->missionQueue->AddTail(mission);
      break;
    }
  }

  if (targetZone == 0 || hostNation == 0) {
    return false;
  }

  short hostile = missionNation == 0 ? 1 : 0;
  ForceWarBetween(missionNation, hostile);
  TShip* ship = new TShip();
  ship->IShip(3, targetZone, hostile, "damaged-hostile-frigate");
  ship->strength = 899;
  *nationSlotOut = missionNation;
  return true;
}

RuntimeActionResult RunTurnStateAiReassessDamagedShip(NativeTransition& transition) {
  short nationSlot = -1;
  if (g_pSimMgr == 0 || !ConfigureDamagedHostileSeaMission(&nationSlot)) {
    return RuntimeActionResult::Failure("AI reassess fixture has no eligible sea mission");
  }

  g_pSimMgr->economicTurn = 2;
  g_pSimMgr->turnStateCode = 0x15;

  JsonObject args;
  args.Set("nation", static_cast<int>(nationSlot));
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }

  g_pSimMgr->AdvanceGlobalTurnStateMachine();
  return transition.Finish();
}

// ControlSeaZone Reassess only. Opening ControlSea missions do not read
// AutoGreatPower B64/B68/B6c pressure scores, so this is safe on the loaded
// beginning_of_game fixture without RecomputeNationOrderPriorityMetrics.
RuntimeActionResult RunReassessControlSeaMissions(NativeTransition& transition) {
  int slot;

  JsonObject args;
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }

  for (slot = 0; slot < 7; ++slot) {
    TGreatPower* nation = g_apNationStates[slot];
    if (nation == 0 || nation->IsKindOf(RUNTIME_CLASS(TAutoGreatPower)) == 0) {
      continue;
    }
    if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(static_cast<short>(slot)) == 0) {
      continue;
    }
    TAutoGreatPower* autoNation = static_cast<TAutoGreatPower*>(nation);
    CIterator iter(autoNation->missionQueue);
    for (TMission* mission = static_cast<TMission*>(iter.Reset()); iter.More();
         mission = static_cast<TMission*>(iter.Advance())) {
      if (mission->IsNavyMission() != 0 && mission->IsHospitalMission() != 0) {
        mission->Reassess();
      }
    }
  }
  return transition.Finish();
}

// ControlSeaZone Reassess with a hostile frigate at 899/900 strength. Integer
// strength/max_strength would treat that ratio as 0 and keep empty-zone needs.
RuntimeActionResult RunReassessControlSeaMissionsDamagedShip(NativeTransition& transition) {
  int slot;
  short missionNation = -1;
  if (!ConfigureDamagedHostileSeaMission(&missionNation)) {
    return RuntimeActionResult::Failure("AI reassess fixture has no eligible sea mission");
  }

  JsonObject args;
  args.Set("nation", static_cast<int>(missionNation));
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }

  for (slot = 0; slot < 7; ++slot) {
    TGreatPower* nation = g_apNationStates[slot];
    if (nation == 0 || nation->IsKindOf(RUNTIME_CLASS(TAutoGreatPower)) == 0) {
      continue;
    }
    if (g_pSimMgr->IsNationSlotEligibleForEventProcessing(static_cast<short>(slot)) == 0) {
      continue;
    }
    TAutoGreatPower* autoNation = static_cast<TAutoGreatPower*>(nation);
    CIterator iter(autoNation->missionQueue);
    for (TMission* mission = static_cast<TMission*>(iter.Reset()); iter.More();
         mission = static_cast<TMission*>(iter.Advance())) {
      if (mission->IsNavyMission() != 0 && mission->IsHospitalMission() != 0) {
        mission->Reassess();
      }
    }
  }
  return transition.Finish();
}

// Result is the IEEE-754 bits of RecomputeNationOrderPriorityMetrics plus the
// AutoGreatPower B64/B68/B6c scores it writes. Those globals are not saved.
RuntimeActionResult RunRecomputeNationOrderPriorityMetrics(NativeTransition& transition) {
  int nation;
  JsonObject args;
  JsonObject result;
  JsonArray queueDivergence;
  JsonArray mobileScore;
  JsonArray mobileDivergence;
  JsonArray combinedDivergence;
  JsonArray weightedMilitary;
  JsonArray expansionPressure;
  JsonArray unitDivergence;
  JsonArray missionPressure;
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }

  RecomputeNationOrderPriorityMetrics();

  for (nation = 0; nation < 7; ++nation) {
    queueDivergence.Add(FloatBits(g_afNationOrderQueueDivergence_006a3a88[nation]));
    mobileScore.Add(FloatBits(g_afNationMobileUnitScore_006a3b88[nation]));
    mobileDivergence.Add(FloatBits(g_afNationMobileUnitDivergence_006a3ae0[nation]));
    combinedDivergence.Add(FloatBits(g_afNationCombinedUnitDivergence_006a3b50[nation]));
    weightedMilitary.Add(FloatBits(g_afNationWeightedMilitaryOrderScore_006a3b20[nation]));
    TGreatPower* power = g_apNationStates[nation];
    if (power != 0 && power->IsKindOf(RUNTIME_CLASS(TAutoGreatPower)) != 0) {
      TAutoGreatPower* autoPower = static_cast<TAutoGreatPower*>(power);
      expansionPressure.Add(FloatBits(autoPower->expansionPressurePerCompatibleRegionB64));
      unitDivergence.Add(FloatBits(autoPower->averageUnitDivergencePerOwnedRegionB68));
      missionPressure.Add(FloatBits(autoPower->activeMissionPressureAverageB6c));
    } else {
      expansionPressure.Add(0U);
      unitDivergence.Add(0U);
      missionPressure.Add(0U);
    }
  }

  result.Set("queue_divergence", queueDivergence.Release());
  result.Set("mobile_score", mobileScore.Release());
  result.Set("mobile_divergence", mobileDivergence.Release());
  result.Set("combined_divergence", combinedDivergence.Release());
  result.Set("weighted_military", weightedMilitary.Release());
  result.Set("expansion_pressure", expansionPressure.Release());
  result.Set("unit_divergence", unitDivergence.Release());
  result.Set("mission_pressure", missionPressure.Release());
  return transition.Finish(result.Release());
}
