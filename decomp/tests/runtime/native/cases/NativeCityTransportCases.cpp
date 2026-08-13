#include "NativeCases.h"
#include "JsonObject.h"

#include "game/city/TCity.h"
#include "game/city_ui/TLongintList.h"
#include "game/globals/shared_globals.h"
#include "game/globals/game_session_globals.h"
#include "game/map/TMapMgr.h"
#include "game/map/map_records.h"
#include "game/nation/TGreatPower.h"
#include "game/resource_domain_types.h"
#include "game/ui_screens/TSimMgr.h"

#include <string.h>

namespace {

short SeedNonCapitalOwnedRegionDevelopment(TGreatPower* nation) {
  if (nation == 0 || nation->city == 0 || nation->ownedRegionList == 0) {
    return -1;
  }

  const short economicTurn = g_pSimMgr->GetEconomicTurn();
  const short homeTile = static_cast<short>(nation->homeTileIndex);
  TLongintList* regions = nation->ownedRegionList;
  const int totalRegions = regions->GetSize();
  short chosenId = -1;

  for (int ordinal = 1; ordinal <= totalRegions; ++ordinal) {
    const short regionId = static_cast<short>(regions->At(ordinal));
    Province& record = g_pGlobalMapState->cityScoreTable[regionId];
    record.lastTurnTick = economicTurn;
    if (chosenId == -1 && record.cityTileIndex04 != homeTile && record.linkedRegionCount > 0) {
      chosenId = regionId;
    }
  }
  if (chosenId == -1) {
    return -1;
  }

  Province& chosen = g_pGlobalMapState->cityScoreTable[chosenId];
  chosen.lastTurnTick = static_cast<short>(economicTurn - 6);
  chosen.developmentStage = 0;
  memset(chosen.resourceDevelopmentCounts82, 0, sizeof(chosen.resourceDevelopmentCounts82));

  const StrategicTileIndex linked = chosen.linkedTileIndices42[0];
  TTerrainStateRecord& tile = g_pGlobalMapState->terrainStateTable[linked];
  tile.resourceTypeByEdge[0] = static_cast<signed char>(kResourceCotton);
  tile.resourceTypeByEdge[1] = static_cast<signed char>(kResourceKindNone);
  tile.developmentClassNibbles0c = 3;

  nation->city->productionOrderTable1dc[1] = 4;
  return chosenId;
}

} // namespace

RuntimeActionResult RunOwnedRegionDevelopment(NativeTransition& transition) {
  TGreatPower* nation = ActiveNation();
  if (SeedNonCapitalOwnedRegionDevelopment(nation) < 0) {
    return RuntimeActionResult::Failure(
        "the loaded fixture has no non-capital owned province with linked tiles");
  }

  JsonObject args;
  args.Set("nation", static_cast<int>(ActiveNationSlot()));
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }

  nation->AdvanceOwnedRegionDevelopmentCountersAndHandleEvents();
  return transition.Finish();
}

RuntimeActionResult RunCityAndTransportPhase(NativeTransition& transition) {
  TGreatPower* nation = ActiveNation();
  if (SeedNonCapitalOwnedRegionDevelopment(nation) < 0) {
    return RuntimeActionResult::Failure(
        "the loaded fixture has no non-capital owned province with linked tiles");
  }
  nation->pendingActionStatus.byAction[10] = 0x32;

  JsonObject args;
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }

  g_pSimMgr->DoCityAndTransport();
  return transition.Finish();
}
