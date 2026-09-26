// TMapMaker::RotateMapColumnsByPeakWaterTileDensity (0x00529960) -- a UMapper.cpp pass that
// rotates the 108-column tile map horizontally so the column band with the highest water-tile
// density is recentred. It finds the peak of a 3-column sliding sum of water tiles over the
// 60 rows, nudges an empty peak column to
// the midpoint of the nearest non-empty columns on either side, then copies the whole grid
// into a scratch buffer and writes it back column-rotated by that amount.

#include "game/map_generation/TMapMaker.h"

#include "decomp_types.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/mfc.h"
#include "game/gfx/ui_invalidation_guard.h"
#ifdef IMPERIALISM_RUNTIME_TESTS
#include "RuntimeCoarseMapOracle.h"
#endif

namespace {

inline unsigned char IsWaterTile(const TTerrainStateRecord* tile) {
  return tile->terrainKindStorage00 == kStrategicTerrainWater;
}

// Water tiles in one 60-row column.
inline int CountWaterTilesInColumn(const TTerrainStateRecord* column) {
  int count = 0;
  int rows = 0x3c;
  do {
    if (column->terrainKindStorage00 == kStrategicTerrainWater) {
      count = count + 1;
    }
    column += 0x6c;
    rows = rows + -1;
  } while (rows != 0);
  return count;
}

} // namespace

// FUNCTION: IMPERIALISM 0x00529910
int TMapMaker::CountSeaTilesInColumn(int columnIndex) {
  int count = 0;
  int rows = 0x3c;
  TTerrainStateRecord* tile = tiles + columnIndex;
  do {
    if (IsWaterTile(tile) != 0) {
      ++count;
    }
    tile += 0x6c;
    --rows;
  } while (rows != 0);
  return count;
}

// FUNCTION: IMPERIALISM 0x00529960
void TMapMaker::RotateMapColumnsByPeakWaterTileDensity() {
  int total = 0;
  int windowPos = 0;
  int bestDensity = -1;
  int bestColumn = 0;
  int window[3];

  // Prime the 3-column sliding sum with the columns preceding column 0 (wrap-around).
  int* w = window;
  TTerrainStateRecord* column = tiles + 104;
  int prime = 3;
  do {
    int count = CountWaterTilesInColumn(column);
    *w = count;
    total = total + count;
    ++column;
    w = w + 1;
    prime = prime + -1;
  } while (prime != 0);

  // Slide across all 108 columns, tracking the peak 3-column sum.
  int scanCol = 0;
  column = tiles;
  do {
    int count = CountWaterTilesInColumn(column);
    total = total + count;
    if (bestDensity < total) {
      bestColumn = scanCol;
      bestDensity = total;
    }
    int evicted = window[windowPos];
    window[windowPos] = count;
    total = total - evicted;
    windowPos = windowPos + 1;
    if (2 < windowPos) {
      windowPos = 0;
    }
    scanCol = scanCol + 1;
    ++column;
  } while (scanCol < 0x6c);

  // If the peak column itself holds no water tiles, recentre on the midpoint between the nearest
  // non-empty columns to its left and right.
  if (CountWaterTilesInColumn(tiles + bestColumn) == 0) {
    int leftCol = bestColumn + -1;
    if (leftCol < 0) {
      leftCol = bestColumn + 0x6b;
    }
    bestColumn = bestColumn + 1;
    if (0x6b < bestColumn) {
      bestColumn = 0;
    }
    while (CountWaterTilesInColumn(tiles + leftCol) == 0) {
      leftCol = leftCol + -1;
      if (leftCol < 0) {
        leftCol = 0x6b;
      }
    }
    while (CountWaterTilesInColumn(tiles + bestColumn) == 0) {
      bestColumn = bestColumn + 1;
      if (0x6b < bestColumn) {
        bestColumn = 0;
      }
    }
    leftCol = leftCol + 1;
    if (0x6b < leftCol) {
      leftCol = 0;
    }
    int rightCol = bestColumn + -1;
    if (rightCol < 0) {
      rightCol = bestColumn + 0x6b;
    }
    if (rightCol < leftCol) {
      bestColumn = (leftCol + 0x6c + rightCol) / 2;
      if (0x6c < bestColumn) {
        bestColumn = bestColumn + -0x6c;
      }
    } else {
      bestColumn = (rightCol + leftCol) / 2;
    }
  }
#ifdef IMPERIALISM_RUNTIME_TESTS
  RuntimeTerrainMapOracleRecordRotationColumn(bestColumn);
#endif

  // Copy the whole grid, then write it back rotated so the chosen column band leads.
  TTerrainStateRecord* scratch = new TTerrainStateRecord[0x1950];
  if (scratch == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag("D:\\Ambit\\Cross\\UMapper.cpp", 0x904);
  }

  int sourceCol = bestColumn + 0x6b;
  memcpy(scratch, tiles, sizeof(TTerrainStateRecord) * 0x1950);
  for (int destColumn = 0; destColumn < 0x6c; ++destColumn, ++sourceCol) {
    const TTerrainStateRecord* scratchRow = scratch + sourceCol % 0x6c;
    for (int row = 0; row < 0x3c; ++row) {
      memcpy(tiles + row * 0x6c + destColumn, scratchRow, sizeof(TTerrainStateRecord));
      scratchRow += 0x6c;
    }
  }
  delete[] scratch;
}
