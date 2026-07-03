#pragma once

// Free geometry helpers for the UMapper overlay grid (0xd8=216-wide doubled-column grid over the
// 0x6c=108-wide hex tile map).

// Converts a hex tile index to its overlay-grid coordinate for the given edge side.
int ConvertTileIndexToOverlayCoord216BySide(int tileIndex, char side); // 0x0052c990
