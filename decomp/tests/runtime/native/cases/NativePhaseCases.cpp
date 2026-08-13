#include "NativeCases.h"
#include "JsonObject.h"

#include "game/city_ui/TLongintList.h"
#include "game/globals/shared_globals.h"
#include "game/map/TMapMgr.h"
#include "game/map/TZone.h"
#include "game/map/map_records.h"
#include "game/military/TCivUnit.h"
#include "game/military/TMilitaryUnit.h"
#include "game/military_domain_types.h"
#include "game/nation/TGreatPower.h"
#include "game/unit_domain_types.h"

namespace {

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
