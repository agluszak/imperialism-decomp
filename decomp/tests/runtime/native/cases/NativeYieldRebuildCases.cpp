#include "NativeTransition.h"
#include "JsonObject.h"

#include "game/city/TCity.h"
#include "game/city/TTown.h"
#include "game/globals/shared_globals.h"
#include "game/map/TMapMgr.h"
#include "game/nation/TGreatPower.h"
#include "game/resource_domain_types.h"
#include "game/ui_core/TSortedList.h"
#include "game/ui_screens/TSimMgr.h"

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
  const NationSlot nationSlot = g_pSimMgr->GetActiveNationId();
  TGreatPower* nation = g_apNationStates[nationSlot];
  if (nation == 0 || nation->city == 0 || nation->city->homeTownMarkerB0 == 0) {
    return RuntimeActionResult::Failure(
        "the loaded active nation is not the human beginning-save player");
  }

  JsonObject caseCapture;
  caseCapture.Set("nation", static_cast<int>(nationSlot));

  RuntimeActionResult started = transition.Begin(caseCapture.Release());
  if (!started.Succeeded()) {
    return started;
  }

  nation->RebuildNationResourceYieldCountersAndDevelopmentTargets();
  return transition.Finish();
}

RuntimeActionResult RunAiNationResourceYieldRebuildClampsTargets(NativeTransition& transition) {
  const NationSlot nationSlot = 0;
  TGreatPower* nation = g_apNationStates[nationSlot];
  if (nation == 0 || nation->city == 0 || nation->city->homeTownMarkerB0 == 0 ||
      nation->townMarkerList == 0 || nation->townMarkerList->GetCount() != 1 ||
      g_pGlobalMapState == 0 || g_pGlobalMapState->terrainStateTable == 0) {
    return RuntimeActionResult::Failure(
        "the loaded fixture has no supported automated one-town nation zero");
  }

  TTown* town = nation->city->homeTownMarkerB0;
  const StrategicTileIndex homeTileIndex = town->tileIndex;
  if (homeTileIndex < 0 || homeTileIndex >= 0x1950 || nation->homeTileIndex != homeTileIndex ||
      town->ownerNation != nationSlot) {
    return RuntimeActionResult::Failure("the AI home town is not bound to its home tile");
  }

  short neighbors[6];
  TMapMgr::GetNeighborTileIDArray(homeTileIndex, neighbors,
                                  g_pGlobalMapState->hexNeighborWrapHorizontally);
  TTerrainStateRecord& homeTile = g_pGlobalMapState->terrainStateTable[homeTileIndex];
  if (homeTile.cityRecordIndex < 0 || homeTile.cityRecordIndex >= 0x180 ||
      g_pGlobalMapState->cityScoreTable[homeTile.cityRecordIndex].cityTileIndex04 !=
          homeTileIndex) {
    return RuntimeActionResult::Failure("the AI home tile has no matching province record");
  }
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

  JsonObject caseCapture;
  caseCapture.Set("nation", static_cast<int>(nationSlot));

  RuntimeActionResult started = transition.Begin(caseCapture.Release());
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
