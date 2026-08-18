#include "NativeCases.h"
#include "JsonArray.h"
#include "JsonObject.h"

#include "game/city_ui/TCountry.h"
#include "game/city_ui/TLongintList.h"
#include "game/diplomacy_domain_types.h"
#include "game/globals/shared_globals.h"
#include "game/globals/tactical_globals.h"
#include "game/map/TMapMgr.h"
#include "game/map/TMapUberPicture.h"
#include "game/map/map_records.h"
#include "game/military/TArmyMgr.h"
#include "game/military/TMilitaryUnit.h"
#include "game/military_domain_types.h"
#include "game/military_ui/TDiplomacyMgr.h"
#include "game/nation/TGreatPower.h"
#include "game/nation_domain_types.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_core/TViewMgr.h"
#include "game/unit_domain_types.h"

namespace {

enum { kGlobalMapTileCount = 0x1950 };

short FirstOwnedProvince() {
  TGreatPower* nation = ActiveNation();
  if (nation == 0 || nation->ownedRegionList == 0) {
    return -1;
  }
  CLongintIterator regions(nation->ownedRegionList);
  short province = static_cast<short>(regions.FirstLong());
  if (!regions.More()) {
    return -1;
  }
  return province;
}

short AdjacentOwnedProvince(short province) {
  const Province& record = g_pGlobalMapState->cityScoreTable[province];
  short adj;
  for (adj = 0; adj < record.adjacentRegionCount08; ++adj) {
    const short dest = record.adjacentRegionIds0A[adj];
    if (dest >= 0 && dest < 0x180 &&
        g_pGlobalMapState->cityScoreTable[dest].ownerNationCode00 == record.ownerNationCode00) {
      return dest;
    }
  }
  return -1;
}

short AdjacentForeignProvince(short province) {
  const Province& record = g_pGlobalMapState->cityScoreTable[province];
  short adj;
  for (adj = 0; adj < record.adjacentRegionCount08; ++adj) {
    const short dest = record.adjacentRegionIds0A[adj];
    if (dest >= 0 && dest < 0x180 &&
        g_pGlobalMapState->cityScoreTable[dest].ownerNationCode00 != record.ownerNationCode00 &&
        g_pGlobalMapState->cityScoreTable[dest].ownerNationCode00 != -1) {
      return dest;
    }
  }
  return -1;
}

bool FindOwnedForeignProvincePair(short* source, short* target) {
  short province;
  for (province = 0; province < 0x180; ++province) {
    if (g_pGlobalMapState->cityScoreTable[province].ownerNationCode00 != ActiveNationSlot()) {
      continue;
    }
    short adjacent = AdjacentForeignProvince(province);
    if (adjacent >= 0) {
      *source = province;
      *target = adjacent;
      return true;
    }
  }
  return false;
}

short EmptyTileIndex() {
  int tile;
  for (tile = 0; tile < kGlobalMapTileCount; ++tile) {
    if (g_pGlobalMapState->terrainStateTable[tile].cityRecordIndex == -1) {
      return static_cast<short>(tile);
    }
  }
  return -1;
}

TMilitaryUnit* SpawnStationed(MilitaryUnitKind kind, short province) {
  TMilitaryUnit* unit = new TMilitaryUnit();
  unit->IMilitaryUnit(EncodeMilitaryUnitKind(kind), -1, ActiveNationSlot());
  unit->MoveTo(province);
  unit->SetOrders(kUnitOrderIdle, -1);
  return unit;
}

JSON_Value* ToolbarCountJson(short province) {
  int available[10];
  int totals[10];
  int category;
  bool canUpgrade = false;
  TMilitaryUnit* unit = 0;
  JsonObject result;
  JsonArray availableJson;
  JsonArray totalsJson;

  for (category = 0; category < 10; ++category) {
    available[category] = 0;
    totals[category] = 0;
  }
  if (province >= 0 && province < 0x180) {
    unit = g_pGlobalMapState->cityScoreTable[province].stationedUnitChain98;
  }
  for (; unit != 0; unit = static_cast<TMilitaryUnit*>(unit->nextAtLocation14)) {
    const short order = static_cast<short>(unit->unitOrder);
    const int toolbarCategory = g_awTacticalUnitCategoryCodeBySlot[unit->orderType];
    switch (order) {
    case 0:
      ++available[toolbarCategory];
    case 2:
    case 3:
    case 4:
      ++totals[toolbarCategory];
      break;
    }
    if (unit->CanUpgrade()) {
      canUpgrade = true;
    }
  }
  for (category = 0; category < 10; ++category) {
    availableJson.Add(available[category]);
    totalsJson.Add(totals[category]);
  }
  result.Set("available", availableJson.Release());
  result.Set("totals", totalsJson.Release());
  result.Set("can_upgrade", canUpgrade);
  return result.Release();
}

} // namespace

RuntimeActionResult RunArmyToolbarCounts(NativeTransition& transition) {
  const short province = FirstOwnedProvince();
  TMilitaryUnit* idle;
  TMilitaryUnit* sleeping;
  JsonObject args;
  if (province < 0) {
    return RuntimeActionResult::Failure("the fixture has no owned province");
  }
  idle = SpawnStationed(kMilitaryUnitRegulars, province);
  sleeping = SpawnStationed(kMilitaryUnitRegulars, province);
  SpawnStationed(kMilitaryUnitMinutemen, province);
  sleeping->SetOrders(kUnitOrderSleep, -1);
  (void)idle;

  args.Set("province", static_cast<int>(province));
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }
  return transition.Finish(ToolbarCountJson(province));
}

RuntimeActionResult RunArmySelectCategory(NativeTransition& transition) {
  const short province = FirstOwnedProvince();
  JsonObject args;
  short remaining;
  if (province < 0) {
    return RuntimeActionResult::Failure("the fixture has no owned province");
  }
  SpawnStationed(kMilitaryUnitRegulars, province);
  SpawnStationed(kMilitaryUnitRegulars, province);

  args.Set("province", static_cast<int>(province));
  args.Set("category", 2);
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }
  remaining = g_pMapContextActionManager->ActivateFirstIdleTacticalUnitByCategoryAtTile(2, province);
  return transition.Finish(static_cast<int>(remaining));
}

RuntimeActionResult RunArmySetOrderMode(NativeTransition& transition) {
  const short province = FirstOwnedProvince();
  JsonObject args;
  if (province < 0) {
    return RuntimeActionResult::Failure("the fixture has no owned province");
  }
  SpawnStationed(kMilitaryUnitRegulars, province);
  SpawnStationed(kMilitaryUnitRegulars, province);
  g_pMapContextActionManager->pendingMapActionIndex = province;

  args.Set("province", static_cast<int>(province));
  args.Set("mode", 3);
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }
  g_pMapContextActionManager->SetOrdersForIdleUnitsOnPendingTile(3);
  return transition.Finish();
}

RuntimeActionResult RunArmySelectProvince(NativeTransition& transition) {
  const short province = FirstOwnedProvince();
  TMilitaryUnit* latr;
  TMilitaryUnit* done;
  TMilitaryUnit* militia;
  JsonObject args;
  if (province < 0) {
    return RuntimeActionResult::Failure("the fixture has no owned province");
  }
  latr = SpawnStationed(kMilitaryUnitRegulars, province);
  done = SpawnStationed(kMilitaryUnitRegulars, province);
  militia = SpawnStationed(kMilitaryUnitMinutemen, province);
  latr->SetOrders(static_cast<UnitOrder>(3), -1);
  done->SetOrders(static_cast<UnitOrder>(4), -1);
  militia->SetOrders(static_cast<UnitOrder>(4), -1);
  g_pViewMgr->mapUberPictureF0->SetMapInteractionMode(1);

  args.Set("province", static_cast<int>(province));
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }
  g_pMapContextActionManager->SetActiveProvinceSelection(province);
  return transition.Finish();
}

RuntimeActionResult RunArmyClickBlocked(NativeTransition& transition) {
  const short province = FirstOwnedProvince();
  const short tile = EmptyTileIndex();
  JsonObject args;
  int cursor;
  if (province < 0 || tile < 0) {
    return RuntimeActionResult::Failure("the fixture has no owned province or empty tile");
  }
  SpawnStationed(kMilitaryUnitRegulars, province);
  g_pMapContextActionManager->pendingMapActionIndex = province;

  args.Set("province", static_cast<int>(province));
  args.Set("tile", static_cast<int>(tile));
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }
  cursor = g_pMapContextActionManager->ComputeCivilianMapCursorStateIndex(tile, 0);
  return transition.Finish(cursor);
}

RuntimeActionResult RunArmyClickFriendly(NativeTransition& transition) {
  const short province = FirstOwnedProvince();
  const short dest = province < 0 ? -1 : AdjacentOwnedProvince(province);
  JsonObject args;
  if (province < 0 || dest < 0) {
    return RuntimeActionResult::Failure("the fixture has no adjacent owned province");
  }
  SpawnStationed(kMilitaryUnitRegulars, province);
  SpawnStationed(kMilitaryUnitMinutemen, province);
  g_pMapContextActionManager->pendingMapActionIndex = province;

  args.Set("province", static_cast<int>(province));
  args.Set("target", static_cast<int>(dest));
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }
  g_pMapContextActionManager->SelectMovableUnitOnCurrentTileAndPlaySfx(dest);
  return transition.Finish();
}

RuntimeActionResult RunArmyClickHostile(NativeTransition& transition) {
  short province;
  short dest;
  JsonObject args;
  if (!FindOwnedForeignProvincePair(&province, &dest)) {
    return RuntimeActionResult::Failure("the fixture has no adjacent foreign province");
  }
  SpawnStationed(kMilitaryUnitRegulars, province);
  g_pMapContextActionManager->pendingMapActionIndex = province;
  g_pDiplomacyTurnStateManager->relationPropagationMatrix
      [ActiveNationSlot() * kNationSlotCount +
       g_pGlobalMapState->cityScoreTable[dest].ownerNationCode00] = kDiplomacyRelationshipWar;
  g_pDiplomacyTurnStateManager->relationPropagationMatrix
      [g_pGlobalMapState->cityScoreTable[dest].ownerNationCode00 * kNationSlotCount +
       ActiveNationSlot()] = kDiplomacyRelationshipWar;

  args.Set("province", static_cast<int>(province));
  args.Set("target", static_cast<int>(dest));
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }
  TMilitaryUnit* unit = g_pGlobalMapState->GetMilitaryMaster(province);
  for (; unit != 0; unit = static_cast<TMilitaryUnit*>(unit->nextAtLocation14)) {
    if (unit->unitOrder == 0 &&
        unit->GetCategory() != EncodeArmyUnitCategory(kArmyUnitCategoryMilitia)) {
      unit->SetOrders(kUnitOrderRedeploy, dest);
    }
  }
  g_pGlobalMapState->MarkAdjacentHexOrderDirectionAndSelectTile(province, dest, 1);
  return transition.Finish();
}

RuntimeActionResult RunArmySelectionCycling(NativeTransition& transition) {
  const short province = FirstOwnedProvince();
  JsonObject args;
  short nextProvince;
  if (province < 0) {
    return RuntimeActionResult::Failure("the fixture has no owned province");
  }
  SpawnStationed(kMilitaryUnitRegulars, province);
  g_pMapContextActionManager->pendingMapActionIndex = province;
  g_pMapContextActionManager->SetOrdersForIdleUnitsOnPendingTile(2);

  args.Set("province", static_cast<int>(province));
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }
  nextProvince =
      g_pMapContextActionManager->FindNextSelectableProvinceForNation(ActiveNationSlot());
  return transition.Finish(static_cast<int>(nextProvince));
}
