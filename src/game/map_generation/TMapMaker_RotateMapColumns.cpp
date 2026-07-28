// TMapMaker::RotateMapColumnsByPeakCityTileDensity (0x00529960) -- a UMapper.cpp pass that
// rotates the 108-column tile map horizontally so the column band with the highest city-tile
// density is recentred. It finds the peak of a 3-column sliding sum of water tiles over the
// 60 rows (row stride 0xf30 = 108*0x24), nudges an empty peak column to
// the midpoint of the nearest non-empty columns on either side, then copies the whole grid
// into a scratch buffer and writes it back column-rotated by that amount. Own translation
// unit (like the other UMapper routines).

#include "game/map_generation/TMapMaker.h"

#include "decomp_types.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/mfc.h"
#include "game/gfx/ui_invalidation_guard.h"

namespace {

// Water tiles in one 60-row column, starting at byte pointer `column`.
inline int CountCityTilesInColumn(char* column) {
  int count = 0;
  int rows = 0x3c;
  do {
    if (*column == kStrategicTerrainWater) {
      count = count + 1;
    }
    column = column + 0xf30;
    rows = rows + -1;
  } while (rows != 0);
  return count;
}

} // namespace

// FUNCTION: IMPERIALISM 0x00529960
void TMapMaker::RotateMapColumnsByPeakCityTileDensity() {
  int total = 0;
  int windowPos = 0;
  int bestDensity = -1;
  int bestColumn = 0;
  int window[3];

  // Prime the 3-column sliding sum with the columns preceding column 0 (wrap-around).
  int* w = window;
  char* column = mapTileGrid08 + 0xea0;
  int prime = 3;
  do {
    int count = CountCityTilesInColumn(column);
    *w = count;
    total = total + count;
    column = column + 0x24;
    w = w + 1;
    prime = prime + -1;
  } while (prime != 0);

  // Slide across all 108 columns, tracking the peak 3-column sum.
  int scanCol = 0;
  column = mapTileGrid08;
  do {
    int count = CountCityTilesInColumn(column);
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
    column = column + 0x24;
  } while (scanCol < 0x6c);

  // If the peak column itself holds no city tiles, recentre on the midpoint between the nearest
  // non-empty columns to its left and right.
  if (CountCityTilesInColumn(mapTileGrid08 + bestColumn * 0x24) == 0) {
    int leftCol = bestColumn + -1;
    if (leftCol < 0) {
      leftCol = bestColumn + 0x6b;
    }
    bestColumn = bestColumn + 1;
    if (0x6b < bestColumn) {
      bestColumn = 0;
    }
    while (CountCityTilesInColumn(mapTileGrid08 + leftCol * 0x24) == 0) {
      leftCol = leftCol + -1;
      if (leftCol < 0) {
        leftCol = 0x6b;
      }
    }
    while (CountCityTilesInColumn(mapTileGrid08 + bestColumn * 0x24) == 0) {
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

  // Copy the whole grid, then write it back rotated so the chosen column band leads.
  int* scratch = new int[0xe3d0];
  if (scratch == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag("D:\\Ambit\\Cross\\UMapper.cpp", 0x904);
  }

  int destByte = 0;
  int sourceCol = bestColumn + 0x6b;
  memcpy(scratch, mapTileGrid08, 0x38f40);
  do {
    int rows = 0x3c;
    int* scratchRow = scratch + (sourceCol % 0x6c) * 9;
    int rowByte = destByte;
    do {
      rows = rows + -1;
      memcpy(mapTileGrid08 + rowByte, scratchRow, 0x24);
      scratchRow = scratchRow + 0x3cc;
      rowByte = rowByte + 0xf30;
    } while (rows != 0);
    destByte = destByte + 0x24;
    sourceCol = sourceCol + 1;
  } while (destByte < 0xf30);

  if (scratch != nullptr) {
    delete[] scratch;
  }
}
