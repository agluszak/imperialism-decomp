#include "game/TGlobalMapState.h"

#include "game/TPtrList.h"
#include "game/TMinor.h"
#include "game/TCivilianOrderState.h"
#include "game/diplomacy_globals.h"

#pragma optimize("y", on) // omit frame pointer, as in the original bodies

extern "C" {
extern short g_Build_Hex_Area_LookupTable_00696E70[];
extern short g_Build_Hex_Area_LookupTable_00696E80[];
}

// FUNCTION: IMPERIALISM 0x00512b50
void TGlobalMapState::ComputeHexNeighborTileIndices(short tileIndex, short* neighborTiles,
                                                    char wrapHorizontally) {
  unsigned int row = static_cast<unsigned int>(static_cast<int>(tileIndex) / 0x6c);
  int col = static_cast<int>(tileIndex) % 0x6c;
  unsigned int rowParity = row & 1U;
  short sVar4;
  if (rowParity == 0) {
    sVar4 = static_cast<short>(tileIndex + -0x6d);
    neighborTiles[2] = static_cast<short>(tileIndex + 0x6c);
    neighborTiles[0] = static_cast<short>(tileIndex + -0x6c);
    neighborTiles[3] = static_cast<short>(tileIndex + 0x6b);
    neighborTiles[1] = static_cast<short>(tileIndex + 1);
    neighborTiles[4] = static_cast<short>(tileIndex + -1);
  } else {
    sVar4 = static_cast<short>(tileIndex + -0x6c);
    neighborTiles[2] = static_cast<short>(tileIndex + 0x6d);
    neighborTiles[0] = static_cast<short>(tileIndex + -0x6b);
    neighborTiles[3] = static_cast<short>(tileIndex + 0x6c);
    neighborTiles[1] = static_cast<short>(tileIndex + 1);
    neighborTiles[4] = static_cast<short>(tileIndex + -1);
  }
  neighborTiles[5] = sVar4;
  if (col < 0x6b) {
    if (col == 0) {
      if (wrapHorizontally == '\0') {
        neighborTiles[4] = static_cast<short>(tileIndex + 0x6b);
        if (rowParity == 0) {
          neighborTiles[5] = static_cast<short>(tileIndex + -1);
          neighborTiles[3] = static_cast<short>(tileIndex + 0xd7);
        }
      } else {
        neighborTiles[4] = -1;
        neighborTiles[3] = -1;
        neighborTiles[5] = -1;
      }
    }
  } else if (wrapHorizontally == '\0') {
    neighborTiles[1] = static_cast<short>(tileIndex + -0x6b);
    if (rowParity != 0) {
      neighborTiles[2] = static_cast<short>(tileIndex + 1);
      neighborTiles[0] = static_cast<short>(tileIndex + -0xd7);
    }
  } else {
    neighborTiles[1] = -1;
    neighborTiles[0] = -1;
    neighborTiles[2] = -1;
  }
  if (0x3a < static_cast<int>(row)) {
    neighborTiles[2] = -1;
    neighborTiles[3] = -1;
    return;
  }
  if (row == 0) {
    neighborTiles[0] = -1;
    neighborTiles[5] = -1;
  }
}

// FUNCTION: IMPERIALISM 0x00512cc0
short TGlobalMapState::GetWrappedHexNeighborTileIndexByDirection(short tileIndex, short direction) {
  int tile = static_cast<int>(tileIndex);
  int row = tile / 0x6c;
  int col = tile % 0x6c;
  int rowParity = row & 1;
  int scaledCol = rowParity + col * 2;

  int dir = static_cast<int>(direction);
  if (dir < 0) {
    dir += 6;
  } else if (dir > 5) {
    dir -= 6;
  }

  scaledCol += static_cast<int>(g_Build_Hex_Area_LookupTable_00696E70[dir]);

  if (static_cast<short>(direction) < 0) {
    dir = static_cast<int>(static_cast<short>(direction)) + 6;
  } else if (static_cast<short>(direction) > 5) {
    dir = static_cast<int>(static_cast<short>(direction)) - 6;
  }

  short wrappedRow = static_cast<short>(row);
  wrappedRow = static_cast<short>(wrappedRow + g_Build_Hex_Area_LookupTable_00696E80[dir]);

  if (scaledCol > 0xd7) {
    scaledCol -= 0xd9;
  } else if (scaledCol < 0) {
    scaledCol += 0xd8;
  }

  if (wrappedRow < 0) {
    wrappedRow = 0;
  } else if (wrappedRow > 0x3b) {
    wrappedRow = 0x3b;
  }

  int halfCol = scaledCol;
  int halfColSign = halfCol >> 0x1f;
  halfCol = (halfCol - halfColSign) >> 1;
  int result = halfCol + static_cast<int>(wrappedRow) * 0x6c;
  if (result < 0 || result >= 0x1950) {
    return -1;
  }
  return static_cast<short>(result);
}

namespace {

const int kGlobalMapTileCount = 0x1950;

short FindReachableRecruitSpawnTileRecursiveImpl(TGlobalMapState* mapState, short tileIndex,
                                                 short ownerNationTag, char allowActiveFlag2) {
  TTerrainStateRecordView* tile = &mapState->terrainStateTable[tileIndex];
  if (tile->recruitSearchVisited0e != 0) {
    return -1;
  }
  tile->recruitSearchVisited0e = 1;
  if (tile->ownerNationTag04 != ownerNationTag) {
    return -1;
  }

  TCivilianOrderState* civilianOrder = tile->firstCivilianOrder20;
  bool noMatchingCivilian = civilianOrder == 0;
  if (!noMatchingCivilian) {
    while (civilianOrder->ownerNationSlot18 != ownerNationTag) {
      civilianOrder = civilianOrder->nextOnTile;
      if (civilianOrder == 0) {
        noMatchingCivilian = true;
        break;
      }
    }
  }
  if (noMatchingCivilian) {
    if ((tile->activeFlags1c & 2) == 0) {
      return tileIndex;
    }
    if (allowActiveFlag2 != 0) {
      return tileIndex;
    }
  }

  short neighborTiles[6];
  TGlobalMapState::ComputeHexNeighborTileIndices(tileIndex, neighborTiles,
                                                 mapState->hexNeighborWrapHorizontally20);
  for (short neighborIndex = 0; neighborIndex < 6; ++neighborIndex) {
    if (neighborTiles[neighborIndex] == -1) {
      continue;
    }
    short foundTile = FindReachableRecruitSpawnTileRecursiveImpl(
        mapState, neighborTiles[neighborIndex], ownerNationTag, allowActiveFlag2);
    if (foundTile != -1) {
      return foundTile;
    }
  }
  return -1;
}

} // namespace

// FUNCTION: IMPERIALISM 0x00513290
void TGlobalMapState::DispatchFormationEntryActionsAndMaybeCreateTurnEvent12(
    short regionIndex, int newOwnerNationSlot) {
  (void)regionIndex;
  (void)newOwnerNationSlot;
}

// FUNCTION: IMPERIALISM 0x00514c80
short TGlobalMapState::FindReachableRecruitSpawnTileWithVisitedReset(short startTileIndex,
                                                                     char allowActiveFlag2) {
  signed char ownerNationTag = terrainStateTable[startTileIndex].ownerNationTag04;
  for (int tileIndex = 0; tileIndex < kGlobalMapTileCount; ++tileIndex) {
    terrainStateTable[tileIndex].recruitSearchVisited0e = 0;
  }
  return FindReachableRecruitSpawnTileRecursiveImpl(this, startTileIndex, ownerNationTag,
                                                    allowActiveFlag2);
}

// FUNCTION: IMPERIALISM 0x00517c30
char TGlobalMapState::AreNationsBorderLinked(int nationA, int nationB) {
  TPtrList* regionList = g_apTerrainTypeDescriptorTable[nationA]->ownedRegionList;
  if (regionList->GetCountSlot48() < 1) {
    return 0;
  }
  int ordinal = 1;
  do {
    int regionId = regionList->GetIntByOrdinalSlot24(ordinal);
    TGlobalMapCityScoreRecord* record = &cityScoreTable[regionId];
    char found = 0;
    int neighborCount = record->adjacentRegionCount08;
    if (neighborCount > 0) {
      for (int neighborIndex = 0; neighborIndex < neighborCount; ++neighborIndex) {
        short neighborRegionId = record->adjacentRegionIds0A[neighborIndex];
        if (cityScoreTable[neighborRegionId].ownerNationCode00 == nationB) {
          found = 1;
          break;
        }
      }
    }
    if (found != 0) {
      return 1;
    }
    ++ordinal;
  } while (ordinal <= regionList->GetCountSlot48());
  return 0;
}

// FUNCTION: IMPERIALISM 0x00518960
void TGlobalMapState::SetRegionDevelopmentStageByte(short regionId, unsigned char stage) {
  cityScoreTable[regionId].developmentStage = stage;
}
