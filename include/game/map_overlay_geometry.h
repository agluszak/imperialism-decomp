#pragma once

// Free geometry helpers for the UMapper overlay grid (0xd8=216-wide doubled-column grid over the
// 0x6c=108-wide hex tile map).

// Wraps an extended overlay X coordinate back into [0, 0xd8) in place when the map wraps
// horizontally. 0x0052a6e0.
void WrapExtendedMapXCoordinateInPlace(int* x);

// Converts a hex tile index to its overlay-grid coordinate for the given edge side.
int ConvertTileIndexToOverlayCoord216BySide(int tileIndex, char side); // 0x0052c990
