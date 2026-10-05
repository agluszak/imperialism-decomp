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

int GetNeighborTileIndexOnMap108x60(int tileIndex, int direction);

int* WrapExtendedMapXCoordinateInPlace(int* x);

// Converts a hex tile index to its overlay-grid coordinate for the given edge side.
int ConvertTileIndexToOverlayCoord216BySide(int tileIndex, char side); // 0x0052c990

int __stdcall GetMapContextActionCode(short nTileIndex, int dwInputFlags);

int __stdcall GetActiveMapOrderEntryActionCode(short nTileIndex, int dwInputFlags);

void ComputeWrappedIsometricScreenOffsetFromTile(int tileIndex, int* outScreenXY, int tileScale,
                                                 short originCol, short originRow);

void BuildHexNeighborHighlightPolygonForTile(short tileId, int compareValue);

void DrawHexNeighborBorderGuidePathForTile(short tileId, int compareValue, short tileScale);
