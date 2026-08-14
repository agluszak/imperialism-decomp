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
#include "game/map/map_records.h"
#include "game/military/TArmyMgr.h"
#include "game/military/TArmyStack.h"
#include "game/military/TArmyStackList.h"
#include "game/military/TMilitaryUnit.h"
#include "game/military/TUnit.h"
#include "game/military_domain_types.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/nation/TAutoGreatPower.h"
#include "game/nation/TGreatPower.h"
#include "game/nation_domain_types.h"
#include "game/navy/TShip.h"
#include "game/ui_core/CIterator.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/unit_domain_types.h"

namespace {

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

JSON_Value* ResolveCombatMovesWithoutBattleUi() {
  TArmyMgr* army = g_pMapContextActionManager;
  int stackCount;
  army->FormStacks();
  army->nextStackOrdinal10 = 1;
  stackCount = army->pendingUnitPool0c->GetCount();
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
  army->ClearPendingStacksAndFinalizeMilitaryUnits();
  army->DoOwnershipChanges();
  return JsonNullValue();
}

bool FindUncontestedRedeploy(TMilitaryUnit** outUnit, short* outDest) {
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
      if (source >= 0 && source < 0x180) {
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

bool FindHostileRedeploy(TMilitaryUnit** outUnit, short* outDest, short* outDefender) {
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
      if (source >= 0 && source < 0x180) {
        record = &g_pGlobalMapState->cityScoreTable[source];
        for (adj = 0; adj < record->adjacentRegionCount08; ++adj) {
          const short dest = record->adjacentRegionIds0A[adj];
          short defender;
          if (dest < 0 || dest >= 0x180) {
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

// Heatmap, militia growth, PayForMilitary, AutoGreatPower case-16 mission
// selection, and human MoveArmy budget. Does not invoke TSimMgr::DoMilitary
// (stack cleanup, navy CarryOutOrders, or AI GiveOrders).
RuntimeActionResult RunMilitaryPhaseSupportedSubset(NativeTransition& transition) {
  int slot;
  g_pSimMgr->economicTurn = 6;

  JsonObject args;
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }

  g_pGlobalMapState->RecomputeTileStrategicScoreHeatmap();
  for (slot = 0; slot < kNationSlotCount; ++slot) {
    TCountry* country = g_apTerrainTypeDescriptorTable[slot];
    if (country == 0) {
      continue;
    }
    if (slot < 7) {
      const short profileCode = country->encodedNationSlot;
      if (profileCode >= 100 && profileCode < 200) {
        continue;
      }
    }
    country->GrowMilitia();
  }
  for (slot = 0; slot < 7; ++slot) {
    TCountry* country = g_apTerrainTypeDescriptorTable[slot];
    TGreatPower* nation;
    if (country == 0) {
      continue;
    }
    if (country->encodedNationSlot >= 100 && country->encodedNationSlot < 200) {
      continue;
    }
    nation = g_apNationStates[slot];
    nation->PayForMilitary();
    nation->SelectAndQueueAdvisoryMapMissionsCase16();
    if (nation->IsKindOf(RUNTIME_CLASS(TAutoGreatPower)) == 0) {
      nation->MoveArmy();
    }
  }
  return transition.Finish();
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

RuntimeActionResult RunCombatMovesUncontested(NativeTransition& transition) {
  TMilitaryUnit* unit = 0;
  short dest = -1;
  JSON_Value* result;
  ClearAllMilitaryOrders();
  if (!FindUncontestedRedeploy(&unit, &dest)) {
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
  g_pDiplomacyTurnStateManager
      ->relationPropagationMatrix[unit->ownerNationSlot18 * kNationSlotCount + defender] =
      kDiplomacyRelationshipWar;
  g_pDiplomacyTurnStateManager
      ->relationPropagationMatrix[defender * kNationSlotCount + unit->ownerNationSlot18] =
      kDiplomacyRelationshipWar;
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

// Selection-bit clear, heatmap, and AddPurchasedItems only. Does not invoke the
// retail military-cleanup phase (navy cleanup, AI replan, power/order metrics).
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
      g_apNationStates[slot]->AddPurchasedItems();
    }
  }
  return transition.Finish();
}
