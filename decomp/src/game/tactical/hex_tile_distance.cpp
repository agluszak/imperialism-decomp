#include "game/tactical/hex_tile_distance.h"

// FUNCTION: IMPERIALISM 0x005a39a0
int ComputeHexTileDistanceFromIndices(int tileIndexA, int tileIndexB) {
  unsigned int rowA = tileIndexA / 29;
  int colA = (rowA & 1U) + (tileIndexA % 29) * 2;
  unsigned int rowB = tileIndexB / 29;
  int colB = (rowB & 1U) + (tileIndexB % 29) * 2;

  if (colB < colA) {
    colB = colA * 2 - colB;
  }
  if (static_cast<int>(rowB) < static_cast<int>(rowA)) {
    rowB = rowA * 2 - rowB;
  }

  int rowDelta = rowB - rowA;
  colA = (colB - rowDelta) - colA;
  if (colA > 0) {
    return colA / 2 + rowDelta;
  }
  return rowDelta;
}
