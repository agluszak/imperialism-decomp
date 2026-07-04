#pragma once

// Free geometry helpers for the UMapper overlay grid (0xd8=216-wide doubled-column grid over the
// 0x6c=108-wide hex tile map).

// A route/overlay edge endpoint (overlay x,y). Used by the scanline region-fill pass.
struct MapEdgePoint {
  int x; // +0x00
  int y; // +0x04

  // 1 if both coordinates match `other`, else 0. 0x0052e990.
  unsigned int Equals(const MapEdgePoint* other) const;
};

// Neighbour tile index on the 108x60 hex map in the given direction (0..5), with horizontal
// wrap; -1 if off-map. 0x00528c10.
int GetNeighborTileIndexOnMap108x60(int tileIndex, int direction);

// Wraps an extended overlay X coordinate back into [0, 0xd8) in place when the map wraps
// horizontally. 0x0052a6e0.
void WrapExtendedMapXCoordinateInPlace(int* x);

// Converts a hex tile index to its overlay-grid coordinate for the given edge side.
int ConvertTileIndexToOverlayCoord216BySide(int tileIndex, char side); // 0x0052c990
