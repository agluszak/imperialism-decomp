#include "game/map/TMapMgr.h"
#include "game/globals/game_session_globals.h"

// FUNCTION: IMPERIALISM 0x0050e2c0
ProvinceIndex Province::GetIndex() const {
  return static_cast<ProvinceIndex>(this - g_pGlobalMapState->cityScoreTable);
}

// FUNCTION: IMPERIALISM 0x0050ec60
Province::Province() {}

// FUNCTION: IMPERIALISM 0x0054ae90
Province& Province::operator=(const Province& source) {
  ownerNationCode00 = source.ownerNationCode00;
  formerOwnerNationCode01 = source.formerOwnerNationCode01;
  developmentStage = source.developmentStage;
  fortLevel03 = source.fortLevel03;
  cityTileIndex04 = source.cityTileIndex04;
  lastTurnTick = source.lastTurnTick;
  adjacentRegionCount08 = source.adjacentRegionCount08;
  for (int a = 0; a < 12; ++a) {
    adjacentRegionIds[a] = source.adjacentRegionIds[a];
  }
  for (int b = 0; b < 12; ++b) {
    adjacentRegionAnchorTiles[b] = source.adjacentRegionAnchorTiles[b];
  }
  linkedRegionCount = source.linkedRegionCount;
  byte3B = source.byte3B;
  byte3C = source.byte3C;
  secondaryNeighborTileIndex = source.secondaryNeighborTileIndex;
  primaryNeighborTileIndex = source.primaryNeighborTileIndex;
  for (int c = 0; c < 0x20; ++c) {
    linkedTileIndices42[c] = source.linkedTileIndices42[c];
  }
  for (int d = 0; d < 10; ++d) {
    resourceDevelopmentCounts[d] = source.resourceDevelopmentCounts[d];
  }
  stationedUnitChain = source.stationedUnitChain;
  cityScoreValue = source.cityScoreValue;
  navyOrderReachableA0 = source.navyOrderReachableA0;
  exploredByNationMask = source.exploredByNationMask;
  resourcePresenceMask = source.resourcePresenceMask;
  regionClassA3 = source.regionClassA3;
  cityNameA4 = source.cityNameA4;
  return *this;
}
