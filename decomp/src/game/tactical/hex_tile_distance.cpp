#include "game/tactical/hex_tile_distance.h"

// FUNCTION: IMPERIALISM 0x005a39a0
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
