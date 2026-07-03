// Free geometry helpers for the UMapper overlay grid (a 0xd8=216-wide doubled-column grid laid
// over the 0x6c=108-wide hex tile map).

#include "game/map_overlay_geometry.h"

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
