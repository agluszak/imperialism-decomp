#include "NativeCases.h"
#include "JsonObject.h"

#include "game/city/TCity.h"
#include "game/city/TTown.h"
#include "game/globals/shared_globals.h"
#include "game/map/TMapMgr.h"
#include "game/nation/TGreatPower.h"
#include "game/resource_domain_types.h"
#include "game/ui_core/TSortedList.h"

#include <string.h>

namespace {

void ClearTileYieldSources(StrategicTileIndex tileIndex) {
  TTerrainStateRecord& tile = g_pGlobalMapState->terrainStateTable[tileIndex];
  tile.resourceTypeByEdge[0] = kResourceKindNone;
  tile.resourceTypeByEdge[1] = kResourceKindNone;

  const ProvinceIndex cityRecordIndex = tile.cityRecordIndex;
  if (cityRecordIndex >= 0 && cityRecordIndex < 0x180 &&
      g_pGlobalMapState->cityScoreTable[cityRecordIndex].cityTileIndex04 == tileIndex) {
    memset(g_pGlobalMapState->cityScoreTable[cityRecordIndex].resourceDevelopmentCounts82, 0,
           sizeof(g_pGlobalMapState->cityScoreTable[cityRecordIndex].resourceDevelopmentCounts82));
  }
}

} // namespace

RuntimeActionResult RunNationResourceYieldRebuild(NativeTransition& transition) {
  TGreatPower* nation = ActiveNation();

  JsonObject args;
  args.Set("nation", static_cast<int>(ActiveNationSlot()));
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }

  nation->RebuildNationResourceYieldCountersAndDevelopmentTargets();
  return transition.Finish();
}

RuntimeActionResult RunAiNationResourceYieldRebuildClampsTargets(NativeTransition& transition) {
  const NationSlot nationSlot = 0;
  TGreatPower* nation = g_apNationStates[nationSlot];
  TTown* town = nation->city->homeTownMarkerB0;
  const StrategicTileIndex homeTileIndex = town->tileIndex;

  short neighbors[6];
  TMapMgr::GetNeighborTileIDArray(homeTileIndex, neighbors,
                                  g_pGlobalMapState->hexNeighborWrapHorizontally);
  TTerrainStateRecord& homeTile = g_pGlobalMapState->terrainStateTable[homeTileIndex];
  ClearTileYieldSources(homeTileIndex);
  for (int direction = 0; direction < 6; ++direction) {
    const StrategicTileIndex neighbor = neighbors[direction];
    if (neighbor != -1) {
      ClearTileYieldSources(neighbor);
    }
  }

  town->transportLinked = false;
  town->enabledFlag = 0;
  town->activeFlag = true;
  homeTile.gateFlag = 1;
  homeTile.developmentClassNibbles0c = 3;
  homeTile.resourceTypeByEdge[0] = static_cast<signed char>(kResourceFish);
  homeTile.resourceTypeByEdge[1] = static_cast<signed char>(kResourceCotton);

  for (int resource = 0; resource < kResourceKindCount; ++resource) {
    nation->needCurrentByType[resource] = 0;
    nation->needTargetByType[resource] = 0;
  }
  nation->needTargetByType[kResourceFish] = 4;
  nation->needTargetByType[kResourceCotton] = 6;
  nation->reservedTransportCapacity = 10;

  JsonObject args;
  args.Set("nation", static_cast<int>(nationSlot));
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }

  nation->RebuildNationResourceYieldCountersAndDevelopmentTargets();
  if (nation->needCurrentByType[kResourceCotton] != 4 ||
      nation->needCurrentByType[kResourceFish] != 0 ||
      nation->needCurrentByType[kResourceLivestock] != 4 ||
      nation->needTargetByType[kResourceCotton] != 4 ||
      nation->needTargetByType[kResourceFish] != 4 || nation->reservedTransportCapacity != 8) {
    return RuntimeActionResult::Failure(
        "the AI yield rebuild did not exercise the clamp-then-rollover branch");
  }
  return transition.Finish();
}

RuntimeActionResult RunNationResourceYieldRebuildMultipleTowns(NativeTransition& transition) {
  const NationSlot nationSlot = 0;
  TGreatPower* nation = g_apNationStates[nationSlot];
  TTown* homeTown = nation->city->homeTownMarkerB0;

  homeTown->enabledFlag = 0;
  homeTown->activeFlag = true;
  homeTown->transportLinked = false;

  char* linkedTiles = 0;
  nation->BuildTransportLinkedInfluenceMap(&linkedTiles);
  if (linkedTiles == 0) {
    return RuntimeActionResult::Failure("the transport influence map was not returned");
  }
  StrategicTileIndex outpostTile = -1;
  for (int tile = 0; tile < 0x1950; ++tile) {
    if (linkedTiles[tile] == 0 &&
        static_cast<short>(g_pGlobalMapState->terrainStateTable[tile].ownerNationTag04) ==
            nationSlot) {
      outpostTile = static_cast<StrategicTileIndex>(tile);
      break;
    }
  }
  delete[] linkedTiles;
  if (outpostTile == -1) {
    return RuntimeActionResult::Failure(
        "the loaded fixture has no disconnected owned tile for a second town");
  }

  TTown* outpost = new TTown();
  outpost->ITown("Outpost", outpostTile, 0, nationSlot);
  outpost->hasAdjacentCity = false;
  outpost->transportLinked = true;
  nation->townMarkerList->AddTail(outpost);

  JsonObject args;
  args.Set("nation", static_cast<int>(nationSlot));
  RuntimeActionResult started = transition.Begin(args.Release());
  if (!started.Succeeded()) {
    return started;
  }

  nation->RebuildNationResourceYieldCountersAndDevelopmentTargets();
  if (nation->townMarkerList->GetCount() != 2 ||
      nation->townMarkerList->GetEntryByOrdinal(1) != homeTown ||
      nation->townMarkerList->GetEntryByOrdinal(2) != outpost || !homeTown->transportLinked ||
      outpost->transportLinked) {
    return RuntimeActionResult::Failure(
        "the multi-town yield rebuild did not preserve order and linked-state contrast");
  }
  return transition.Finish();
}
