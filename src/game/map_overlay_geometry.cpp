// Free geometry helpers for the UMapper overlay grid (a 0xd8=216-wide doubled-column grid laid
// over the 0x6c=108-wide hex tile map).

#include "game/map_overlay_geometry.h"

#include "game/TGlobalMapState.h"
#include "game/global_data_tables.h"

// FUNCTION: IMPERIALISM 0x00528c10
int GetNeighborTileIndexOnMap108x60(int tileIndex, int direction) {
  int col;
  if ((tileIndex / 0x6c & 1U) == 0) {
    col = g_hexColOffsetEvenRow_00697450[direction];
  } else {
    col = g_hexColOffsetOddRow_00697480[direction];
  }
  col = tileIndex % 0x6c + col;
  int row = tileIndex / 0x6c + g_hexRowOffset_00697468[direction];
  if (g_pGlobalMapState->hexNeighborWrapHorizontally20 == '\0') {
    if (col < 0) {
      col = col + 0x6c;
    } else if (0x6b < col) {
      col = col - 0x6c;
    }
  } else {
    if (col < 0) {
      return -1;
    }
    if (0x6b < col) {
      return -1;
    }
  }
  if (-1 < row && row < 0x3c) {
    return col + row * 0x6c;
  }
  return -1;
}

// FUNCTION: IMPERIALISM 0x0052a6e0
void WrapExtendedMapXCoordinateInPlace(int* x) {
  if (g_pGlobalMapState->hexNeighborWrapHorizontally20 == '\0') {
    int value = *x;
    if (value >= 0xd8) {
      *x = value - 0xd8;
      return;
    }
    if (value < 0) {
      *x = value + 0xd8;
    }
  }
}

// FUNCTION: IMPERIALISM 0x0052c990
int ConvertTileIndexToOverlayCoord216BySide(int tileIndex, char side) {
  unsigned int row = tileIndex / 0x6c;
  int column = (row & 1) + (tileIndex % 0x6c) * 2;
  int result = column;
  if (side == '\0') {
    result = column + 2;
    row = row + 1;
    if (result >= 0xd8) {
      result -= 0xd8;
    }
  }
  return result + row * 0xd8;
}

// FUNCTION: IMPERIALISM 0x0052e990
unsigned int MapEdgePoint::Equals(const MapEdgePoint* other) const {
  if (y == other->y && x == other->x) {
    return 1;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x005A39A0
int ComputeHexTileDistanceFromIndices(int tileIndexA, int tileIndexB) {
  unsigned int rowA = static_cast<unsigned int>(tileIndexA / 0x1d);
  int colA = (rowA & 1U) + (tileIndexA % 0x1d) * 2;
  unsigned int rowB = static_cast<unsigned int>(tileIndexB / 0x1d);
  int colB = (rowB & 1U) + (tileIndexB % 0x1d) * 2;

  if (colB < colA) {
    colB = colA * 2 - colB;
  }
  if (static_cast<int>(rowB) < static_cast<int>(rowA)) {
    rowB = rowA * 2 - rowB;
  }

  int rowDelta = static_cast<int>(rowB - rowA);
  colA = (colB - rowDelta) - colA;
  if (0 < colA) {
    return colA / 2 + rowDelta;
  }
  return rowDelta;
}
