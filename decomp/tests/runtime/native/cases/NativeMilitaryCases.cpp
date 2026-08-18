#include "NativeCases.h"
#include "JsonArray.h"
#include "JsonObject.h"
#include "parson.h"

#include "game/city/TCity.h"
#include "game/city/TUnitOrder.h"
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
#include "game/navy/TNavyMgr.h"
#include "game/navy/TOcean.h"
#include "game/navy/TShip.h"
#include "game/navy/TNavyMgr.h"
#include "game/navy/TOcean.h"
#include "game/navy/TTaskForce.h"
#include "game/tactical/TArmyBattle.h"
#include "game/ui_core/CIterator.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/unit_domain_types.h"
#include "game/globals/nation_globals.h"

#include <string.h>

namespace {

unsigned int FloatBits(float value) {
  unsigned int bits = 0;
  memcpy(&bits, &value, sizeof(bits));
  return bits;
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

void ApplyUncontestedStack(TArmyStack* stack) {
  stack->cursor18 = stack->head14;
  TArmyStackUnitNode* node = stack->cursor18;
  TUnit* unit = (node != 0) ? node->unit : 0;
  while (unit != 0) {
    unit->MoveTo(unit->orderTargetIndex0C);
    unit->SetOrders(kUnitOrderIdle, -1);
    node = stack->cursor18;
    if (node != 0) {
      node = node->next;
      stack->cursor18 = node;
      unit = (node != 0) ? node->unit : 0;
    } else {
      unit = 0;
    }
  }
}

void PrependUnit(TMilitaryUnit** units, int* count, TMilitaryUnit* unit) {
  int index;
  for (index = *count; index > 0; --index) {
    units[index] = units[index - 1];
  }
  units[0] = unit;
  *count += 1;
}

JSON_Value* BuildPendingBattleJson(short province, short attackerNation, short defenderNation,
                                   TMilitaryUnit** attackers, int attackerCount,
                                   TMilitaryUnit** defenders, int defenderCount) {
  JsonObject result;
  JsonArray attackerUnits;
  JsonArray defenderUnits;
  int index;
  result.Set("province", static_cast<int>(province));
  result.Set("attacker_nation", static_cast<int>(attackerNation));
  result.Set("defender_nation", static_cast<int>(defenderNation));
  for (index = 0; index < attackerCount; ++index) {
    attackerUnits.Add(attackers[index]->persistentUnitId20);
  }
  for (index = 0; index < defenderCount; ++index) {
    defenderUnits.Add(defenders[index]->persistentUnitId20);
  }
  result.Set("attacker_units", attackerUnits.Release());
  result.Set("defender_units", defenderUnits.Release());
  return result.Release();
}

JSON_Value* TryCreateBattleWithoutUi(TArmyMgr* army, TArmyStack* stack) {
  TMilitaryUnit* attackers[256];
  TMilitaryUnit* defenders[256];
  int attackerCount = 0;
  int defenderCount = 0;
  const short dest = stack->ownerNationCodeE;
  const short cachedOwner = army->perTileOwnerNationCodeCache1c[dest];
  const short attackerNation = static_cast<short>(stack->categoryFlag8);
  TArmyStackUnitNode* node;
  TMilitaryUnit* garrison;

  stack->cursor18 = stack->head14;
  node = stack->cursor18;
  while (node != 0 && attackerCount < 256) {
    TUnit* unit = node->unit;
    if (unit != 0 && unit->orderTargetIndex0C == dest) {
      PrependUnit(attackers, &attackerCount, static_cast<TMilitaryUnit*>(unit));
    }
    node = node->next;
    stack->cursor18 = node;
  }
  if (attackerCount == 0) {
    return 0;
  }

  if (g_pDiplomacyTurnStateManager->IsNationPairRelationTurnStampOutOfDate(attackerNation,
                                                                           cachedOwner) == 0) {
    army->RelocateStackUnitsToStackTile(stack);
    return 0;
  }

  garrison = 0;
  if (dest >= 0 && dest < 0x180) {
    garrison = g_pGlobalMapState->cityScoreTable[dest].stationedUnitChain98;
  }
  for (; garrison != 0 && defenderCount < 256;
       garrison = static_cast<TMilitaryUnit*>(garrison->nextAtLocation14)) {
    PrependUnit(defenders, &defenderCount, garrison);
  }

  if (defenderCount != 0) {
    return BuildPendingBattleJson(dest, attackerNation, cachedOwner, attackers, attackerCount,
                                  defenders, defenderCount);
  }

  ApplyUncontestedStack(stack);
  army->perTileOwnerNationCodeCache1c[dest] = attackerNation;
  return 0;
}

JSON_Value* ProcessPendingStacksUntilBattle(int finalizeIfComplete) {
  TArmyMgr* army = g_pMapContextActionManager;
  int stackCount = army->pendingUnitPool0c->GetCount();
  while (army->nextStackOrdinal10 <= stackCount) {
    const int cursor = army->nextStackOrdinal10;
    TArmyStack* stack;
    JSON_Value* battle;
    army->nextStackOrdinal10 = cursor + 1;
    stack = static_cast<TArmyStack*>(army->pendingUnitPool0c->GetEntryByOrdinal(cursor));
    if (army->perTileOwnerNationCodeCache1c[stack->ownerNationCodeE] ==
        static_cast<short>(stack->categoryFlag8)) {
      ApplyUncontestedStack(stack);
    } else {
      battle = TryCreateBattleWithoutUi(army, stack);
      if (battle != 0) {
        return battle;
      }
    }
    stackCount = army->pendingUnitPool0c->GetCount();
  }
  if (finalizeIfComplete != 0) {
    army->ClearPendingStacksAndFinalizeMilitaryUnits();
    army->DoOwnershipChanges();
    return JsonNullValue();
  }
  return 0;
}

JSON_Value* ResolveNextPendingBattleWithoutUi() {
  return ProcessPendingStacksUntilBattle(0);
}

JSON_Value* ResolveCombatMovesWithoutBattleUi() {
  TArmyMgr* army = g_pMapContextActionManager;
  army->FormStacks();
  army->nextStackOrdinal10 = 1;
  return ProcessPendingStacksUntilBattle(1);
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

int TaskForceQueueIndex(TTaskForce* expected) {
  int index = 0;
  for (TTaskForce* force = g_pNavyOrderManager->orderQueueHead; force != 0;
       force = force->nextForce, ++index) {
    if (force == expected) {
      return index;
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

  g_pSimMgr->DoMilitary();
  return transition.Finish();
}

RuntimeActionResult RunMilitaryPhaseShipsWithoutOrders(NativeTransition& transition) {
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

RuntimeActionResult RunMilitaryPhaseNavalEncounter(NativeTransition& transition) {
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
  attackerShip->IShip(3, zone, activeNation, "military-encounter-attacker");
  TTaskForce* attacker = zone->CreateTaskForceFromNavyOrdersForNationIfEligible(activeNation);
  if (attacker == 0) {
    return RuntimeActionResult::Failure("could not create the attacking task force");
  }
  attacker->SubmitOrders(3, 0);

  TShip* defenderShip = new TShip();
  defenderShip->IShip(3, zone, hostileNation, "military-encounter-defender");
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

  const int attackerIndex = TaskForceQueueIndex(attacker);
  const int defenderIndex = TaskForceQueueIndex(defender);
  if (attackerIndex < 0 || defenderIndex < 0) {
    return RuntimeActionResult::Failure("the naval encounter did not retain both task forces");
  }

  JsonObject battle;
  battle.Set("attacker", attackerIndex);
  battle.Set("defender", defenderIndex);
  return transition.Finish(battle.Release());
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
  JSON_Value* result;
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

  result = ResolveCombatMovesWithoutBattleUi();
  return transition.Finish(result);
}

RuntimeActionResult RunCombatMovesCreatesBattle(NativeTransition& transition) {
  TMilitaryUnit* unit = 0;
  short dest = -1;
  short defender = -1;
  JSON_Value* result;
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

  result = ResolveCombatMovesWithoutBattleUi();
  if (result == 0 || json_value_get_type(result) != JSONObject) {
    JsonFreeValue(result);
    return RuntimeActionResult::Failure("identical orders did not create a land battle");
  }
  return transition.Finish(result);
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
  army->FormStacks();
  army->nextStackOrdinal10 = 1;
  firstBattle = ResolveNextPendingBattleWithoutUi();
  if (firstBattle == 0 || json_value_get_type(firstBattle) != JSONObject) {
    JsonFreeValue(firstBattle);
    return RuntimeActionResult::Failure("first hostile stack did not create a land battle");
  }
  secondBattle = ResolveNextPendingBattleWithoutUi();
  if (secondBattle == 0 || json_value_get_type(secondBattle) != JSONObject) {
    JsonFreeValue(firstBattle);
    JsonFreeValue(secondBattle);
    return RuntimeActionResult::Failure(
        "second stack did not create a land battle after the first stop");
  }
  result.Set("first", firstBattle);
  result.Set("second", secondBattle);
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
  army->FormStacks();
  army->nextStackOrdinal10 = 1;
  first = ProcessPendingStacksUntilBattle(0);
  if (first == 0 || json_value_get_type(first) != JSONObject) {
    JsonFreeValue(first);
    return RuntimeActionResult::Failure("identical orders did not create a land battle");
  }
  if (army->nextStackOrdinal10 > army->pendingUnitPool0c->GetCount()) {
    JsonFreeValue(first);
    return RuntimeActionResult::Failure(
        "the first battle consumed the last stack; no later movement remains");
  }

  second = ProcessPendingStacksUntilBattle(1);
  result.Set("first", first);
  result.Set("second", second);
  return transition.Finish(result.Release());
}

// Selection-bit clear, heatmap, militia adoption, and AddPurchasedItems only.
// Does not invoke navy straggler cleanup, mission prune, AI replan, or
// power/order metrics.
RuntimeActionResult RunMilitaryCleanupSupportedSubset(NativeTransition& transition) {
  int slot;
  if (g_pNavyPrimaryOrderListHead != 0) {
    g_pNavyPrimaryOrderListHead->selection = 1;
  }

  JsonObject args;
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }

  if (g_pNavyPrimaryOrderListHead != 0) {
    TShip* ship;
    for (ship = g_pNavyPrimaryOrderListHead; ship != 0; ship = ship->next) {
      if (ship->selection == 1) {
        ship->selection = 0;
      }
    }
  }
  g_pGlobalMapState->RecomputeTileStrategicScoreHeatmap();
  for (slot = 0; slot < 7; ++slot) {
    TCountry* country = g_apTerrainTypeDescriptorTable[slot];
    if (country == 0) {
      continue;
    }
    if (country->encodedNationSlot >= 100 && country->encodedNationSlot < 200) {
      continue;
    }
    if (g_apNationStates[slot] != 0) {
      TGreatPower* nation = g_apNationStates[slot];
      if (nation->IsKindOf(RUNTIME_CLASS(TAutoGreatPower)) != 0) {
        static_cast<TAutoGreatPower*>(nation)->SeedTrackedEntryAssignmentsFromEligibleUnits();
      }
      nation->AddPurchasedItems();
    }
  }
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

  if (targetZone != 0 && hostNation != 0) {
    short hostile = missionNation == 0 ? 1 : 0;
    ForceWarBetween(missionNation, hostile);
    TShip* ship = new TShip();
    ship->IShip(3, targetZone, hostile, "damaged-hostile-frigate");
    ship->strength = 899;
  }

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
