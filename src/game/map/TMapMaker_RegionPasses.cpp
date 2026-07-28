#include "game/map_ui/TMapMaker.h"
#include "game/map/TMapMgr.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/globals/map_ui_globals.h"

namespace {

// Hex neighbour of `tileIndex` in `direction` on the 108x60 grid, honouring the map's
// horizontal-wrap flag. Mirrors the inlined form the original emits at every use site.
inline int HexNeighborInline(int tileIndex, int direction) {
  int col;
  if ((tileIndex / 0x6c & 1U) == 0) {
    col = g_hexColOffsetEvenRow_00697450[direction];
  } else {
    col = g_hexColOffsetOddRow_00697480[direction];
  }
  col = tileIndex % 0x6c + col;
  int row = tileIndex / 0x6c + g_hexRowOffset_00697468[direction];
  if (g_pGlobalMapState->hexNeighborWrapHorizontally == '\0') {
    if (col < 0) {
      col = col + 0x6c;
    } else if (0x6b < col) {
      col = col - 0x6c;
    }
  } else {
    if (col < 0 || 0x6b < col) {
      return -1;
    }
  }
  if (-1 < row && row < 0x3c) {
    return col + row * 0x6c;
  }
  return -1;
}

} // namespace

// Centroid tile of the territory owned by `nationCode`, read from each grid record's
// owner byte (record[4]). Territory touching both the left and right map edges wraps
// horizontally; `useWrapOffset` biases the accumulated column sum instead of re-sweeping
// with every column snapped to whichever edge dominates. Returns -1 for an empty match.
// FUNCTION: IMPERIALISM 0x00529d90
int TMapMaker::ComputeOwnedTerritoryCentroidTile(int nationCode, char useWrapOffset) {
  int columnSum = 0;
  int rowSum = 0;
  int matchCount = 0;
  int tileIndex = 0;
  char* ownerBase = mapTileGrid08 + 4;
  char leftEdgeCount = '\0';
  char rightEdgeCount = '\0';

  char* owner = ownerBase;
  do {
    if (*owner == nationCode) {
      int column = tileIndex % 0x6c;
      if (column < 0x19) {
        leftEdgeCount = leftEdgeCount + '\x01';
      }
      if (0x53 < column) {
        rightEdgeCount = rightEdgeCount + '\x01';
      }
      columnSum = columnSum + column;
      rowSum = rowSum + tileIndex / 0x6c;
      matchCount = matchCount + 1;
    }
    tileIndex = tileIndex + 1;
    owner = owner + 0x24;
  } while (tileIndex < 0x1950);

  bool wrapsHorizontally;
  if (leftEdgeCount < '\x01' || rightEdgeCount < '\x01') {
    wrapsHorizontally = false;
  } else {
    wrapsHorizontally = true;
    if (useWrapOffset == '\0') {
      columnSum = 0;
      rowSum = 0;
      matchCount = 0;
      tileIndex = 0;
      owner = ownerBase;
      do {
        if (*owner == nationCode) {
          int column = tileIndex % 0x6c;
          if (column < 0x36 && leftEdgeCount < rightEdgeCount) {
            column = 0x6b;
          }
          if (0x36 < column && rightEdgeCount < leftEdgeCount) {
            column = 0;
          }
          columnSum = columnSum + column;
          rowSum = rowSum + tileIndex / 0x6c;
          matchCount = matchCount + 1;
        }
        tileIndex = tileIndex + 1;
        owner = owner + 0x24;
      } while (tileIndex < 0x1950);
      if (matchCount != 0) {
        return (columnSum / matchCount) % 0x6c + (rowSum / matchCount) * 0x6c;
      }
      return -1;
    }
  }
  if (wrapsHorizontally && useWrapOffset != '\0') {
    columnSum = columnSum + leftEdgeCount * 0x6c;
  }
  if (matchCount != 0) {
    return (columnSum / matchCount) % 0x6c + (rowSum / matchCount) * 0x6c;
  }
  return -1;
}

// Compact the city-region ids stored in each grid record's owner byte: every distinct
// region class (record[4] - 0x17) is assigned the next free ordinal via the shared remap
// table, the record is rewritten with the remapped id, and the number of distinct regions
// is left in cityRegionCount2a4.
// FUNCTION: IMPERIALISM 0x0052a0a0
void TMapMaker::CompactCityRegionIds() {
  cityRegionCount2a4 = 0;

  int* remapCursor = g_cityRegionIdRemapTable_006a3498;
  for (int remaining = 0x100; remaining != 0; remaining = remaining - 1) {
    *remapCursor = -1;
    remapCursor = remapCursor + 1;
  }

  int byteOffset = 0;
  do {
    int regionClass;
    if (byteOffset < 0 || mapTileGrid08[byteOffset] != '\x05') {
      regionClass = -1;
    } else {
      regionClass = mapTileGrid08[byteOffset + 4] - 0x17;
    }
    if (-1 < regionClass) {
      if (g_cityRegionIdRemapTable_006a3498[regionClass] == -1) {
        g_cityRegionIdRemapTable_006a3498[regionClass] = cityRegionCount2a4;
        cityRegionCount2a4 = cityRegionCount2a4 + 1;
      }
      mapTileGrid08[byteOffset + 4] =
          static_cast<char>(g_cityRegionIdRemapTable_006a3498[regionClass]) + '\x17';
    }
    byteOffset = byteOffset + 0x24;
  } while (byteOffset < 0x38f40);
}

// Repair pass over the whole 6480-tile grid: every entry whose value is below -1 is an
// orphaned leaf, and adopts the value of the first hex neighbour that both holds a valid
// (>= 0) value and shares its terrain class. The class key is -1 unless the tile record's
// leading byte is 5, in which case it is record[4] - 0x17. Returns the repair count.
// FUNCTION: IMPERIALISM 0x0052d4b0
int TMapMaker::RepairOrphanedTileValuesFromNeighbors(short* tileValues) {
  int repairedCount = 0;
  int tileIndex = 0;
  int byteOffset = 0;
  short* cursor = tileValues;

  do {
    if (*cursor < -1) {
      int direction = 0;
      do {
        int neighbor = HexNeighborInline(tileIndex, direction);
        if (-1 < neighbor && -1 < tileValues[neighbor]) {
          int ownClass;
          char* ownRecord;
          if (byteOffset < 0 || (ownRecord = mapTileGrid08 + byteOffset, *ownRecord != '\x05')) {
            ownClass = -1;
          } else {
            ownClass = ownRecord[4] - 0x17;
          }

          char* neighborRecord = mapTileGrid08 + neighbor * 0x24;
          int neighborClass;
          if (*neighborRecord == '\x05') {
            neighborClass = neighborRecord[4] - 0x17;
          } else {
            neighborClass = -1;
          }

          if (ownClass == neighborClass) {
            *cursor = tileValues[neighbor];
            repairedCount = repairedCount + 1;
            break;
          }
        }
        direction = direction + 1;
      } while (direction < 6);
    }
    byteOffset = byteOffset + 0x24;
    tileIndex = tileIndex + 1;
    cursor = cursor + 1;
  } while (byteOffset <= 0x38f3f);

  return repairedCount;
}

// Hand each active city region the next sequential value: for region ordinal i the entries
// still carrying placeholder -(i + 2) are searched from the start of the grid, and the
// first match takes *nextValue (which is then advanced). Returns the number assigned.
// FUNCTION: IMPERIALISM 0x0052d6b0
int TMapMaker::AssignSequentialValuesToRegionPlaceholders(short* tileValues, int* nextValue) {
  int regionOrdinal = 0;
  int assignedCount = 0;

  if (0 < cityRegionCount2a4) {
    int placeholder = -2;
    do {
      int tileIndex = 0;
      short* cursor = tileValues;
      do {
        if (placeholder == *cursor) {
          tileValues[tileIndex] = static_cast<short>(*nextValue);
          assignedCount = assignedCount + 1;
          *nextValue = *nextValue + 1;
          break;
        }
        tileIndex = tileIndex + 1;
        cursor = cursor + 1;
      } while (tileIndex < 0x1950);
      regionOrdinal = regionOrdinal + 1;
      placeholder = placeholder + -1;
    } while (regionOrdinal < cityRegionCount2a4);
  }

  return assignedCount;
}
