#pragma once

#include "game/tactical/hex_tile_distance.h"

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

// Maps a clicked tile to a map-context action code used by the map-order handlers. See the
// .cpp for the per-class breakdown. 0x00559a70.
int __stdcall GetMapContextActionCode(short nTileIndex, int dwInputFlags);

// Converts a hex tile index (row*0x6c + col) to its isometric screen-space {x,y} offset in
// outScreenXY, relative to a scrolled origin (originCol, originRow) and scaled by tileScale.
// The column wraps horizontally: `tileIndex - originCol` is taken mod 0x6c directly (the
// row*0x6c term vanishes under the modulo), and odd rows are offset by half a tile in x for
// the hex stagger. 0x00565d20.
void ComputeWrappedIsometricScreenOffsetFromTile(int tileIndex, int* outScreenXY, int tileScale,
                                                 short originCol, short originRow);

// Draws the hex-cell border-highlight polygon for a tile (per-edge QDFrameRect segments
// where the tile borders a different owner or an ocean neighbor). 0x00508f30.
void BuildHexNeighborHighlightPolygonForTile(short tileId, int compareValue);
