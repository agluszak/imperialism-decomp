#include "NativeCases.h"
#include "JsonObject.h"

#include "game/city_ui/TLongintList.h"
#include "game/civilian_domain_types.h"
#include "game/globals/shared_globals.h"
#include "game/map/TMapMgr.h"
#include "game/map/TZone.h"
#include "game/map/map_records.h"
#include "game/military/TCivUnit.h"
#include "game/military/TMilitaryUnit.h"
#include "game/military_domain_types.h"
#include "game/nation/TGreatPower.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/unit_domain_types.h"

namespace {

bool FindOwnedEmptyTile(NationSlot nationSlot, StrategicTileIndex* tileIndex) {
  for (StrategicTileIndex candidate = 0; candidate < 0x1950; ++candidate) {
    const TTerrainStateRecord& tile = g_pGlobalMapState->terrainStateTable[candidate];
    if (tile.ownerNationTag04 == nationSlot && tile.firstCivilianOrder20 == 0 &&
        (tile.activeFlags1c & 4) == 0) {
      *tileIndex = candidate;
      return true;
    }
  }
  return false;
}

short FindPresentMinorSlot() {
  for (short slot = 7; slot < 23; ++slot) {
    if (g_apTerrainTypeDescriptorTable[slot] != 0) {
      return slot;
    }
  }
  return -1;
}

short FindNonCapitalOwnedProvince(TGreatPower* nation) {
  if (nation == 0 || nation->ownedRegionList == 0) {
    return -1;
  }
  const short homeTile = static_cast<short>(nation->homeTileIndex);
  TLongintList* regions = nation->ownedRegionList;
  const int totalRegions = regions->GetSize();
  for (int ordinal = 1; ordinal <= totalRegions; ++ordinal) {
    const short regionId = static_cast<short>(regions->At(ordinal));
    Province& record = g_pGlobalMapState->cityScoreTable[regionId];
    if (record.cityTileIndex04 != homeTile && record.linkedRegionCount > 0) {
      return regionId;
    }
  }
  return -1;
}

short FindAiGreatPowerSlot(short humanSlot) {
  for (short slot = 0; slot < 7; ++slot) {
    if (slot != humanSlot && g_apNationStates[slot] != 0) {
      return slot;
    }
  }
  return -1;
}

} // namespace

RuntimeActionResult RunCiviliansPhase(NativeTransition& transition) {
  const NationSlot nationSlot = ActiveNationSlot();
  StrategicTileIndex tile = -1;
  if (!FindOwnedEmptyTile(nationSlot, &tile)) {
    return RuntimeActionResult::Failure("the loaded map has no empty owned tile");
  }

  TCivUnit* depot = new TCivUnit();
  depot->ICivUnit(kCivilianUnitEngineer, tile, nationSlot);
  depot->SetOrders(kUnitOrderBuildDepot, tile);
  depot->remainingTurns24 = 1;

  TCivUnit* sleep = new TCivUnit();
  sleep->ICivUnit(kCivilianUnitEngineer, tile, nationSlot);
  sleep->SetOrders(kUnitOrderSleep, tile);

  TCivUnit* redeploy = new TCivUnit();
  redeploy->ICivUnit(kCivilianUnitDeveloper, tile, nationSlot);
  redeploy->SetOrders(kUnitOrderRedeploy, tile);
  redeploy->remainingTurns24 = 2;

  JsonObject args;
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }

  g_pSimMgr->DoCivilians();
  return transition.Finish();
}

RuntimeActionResult RunProvinceLossWithStationedUnit(NativeTransition& transition) {
  TGreatPower* nation = ActiveNation();
  const short province = FindNonCapitalOwnedProvince(nation);
  if (province < 0) {
    return RuntimeActionResult::Failure(
        "the loaded fixture has no non-capital owned province with linked tiles");
  }
  const short minorSlot = FindPresentMinorSlot();
  if (minorSlot < 0) {
    return RuntimeActionResult::Failure("the loaded fixture has no minor nation");
  }

  const NationSlot nationSlot = ActiveNationSlot();
  const StrategicTileIndex tile =
      g_pGlobalMapState->cityScoreTable[province].linkedTileIndices42[0];
  TCivUnit* civilian = new TCivUnit();
  civilian->ICivUnit(kCivilianUnitMiner, tile, nationSlot);

  TMilitaryUnit* stationed = new TMilitaryUnit();
  stationed->IMilitaryUnit(EncodeMilitaryUnitKind(kMilitaryUnitMinutemen), province, nationSlot);
  TMilitaryUnit* detached = new TMilitaryUnit();
  detached->IMilitaryUnit(EncodeMilitaryUnitKind(kMilitaryUnitMinutemen), -1, nationSlot);

  JsonObject args;
  args.Set("province", static_cast<int>(province));
  args.Set("new_owner", static_cast<int>(minorSlot));
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }

  g_pGlobalMapState->ChangeProvinceOwner(province, minorSlot);
  return transition.Finish();
}

RuntimeActionResult RunProvinceOwnerOceanContext(NativeTransition& transition) {
  TGreatPower* nation = ActiveNation();
  const short province = FindNonCapitalOwnedProvince(nation);
  if (province < 0) {
    return RuntimeActionResult::Failure(
        "the loaded fixture has no non-capital owned province with linked tiles");
  }
  const short aiSlot = FindAiGreatPowerSlot(ActiveNationSlot());
  if (aiSlot < 0) {
    return RuntimeActionResult::Failure("the loaded fixture has no AI great power");
  }
  TZone* zone = g_pMapActionContextListHead;
  if (zone == 0) {
    return RuntimeActionResult::Failure("the loaded fixture has no ocean zone context");
  }

  Province& record = g_pGlobalMapState->cityScoreTable[province];
  record.adjacentRegionCount08 = 0;
  zone->secondaryNeighbors.Add(&record);

  JsonObject args;
  args.Set("province", static_cast<int>(province));
  args.Set("new_owner", static_cast<int>(aiSlot));
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }

  TGreatPower* ai = g_apNationStates[aiSlot];
  const unsigned char savedEligibility = ai->diplomacyEligibilityA0;
  ai->diplomacyEligibilityA0 = 0;
  g_pGlobalMapState->ChangeProvinceOwner(province, aiSlot);
  ai->diplomacyEligibilityA0 = savedEligibility;
  return transition.Finish();
}
