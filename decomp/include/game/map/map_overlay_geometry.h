#pragma once

#include "game/tactical/hex_tile_distance.h"

// Geometry helpers for the 216-column doubled overlay grid over the 108-column hex map.

// A route/overlay edge endpoint (overlay x,y). Used by the scanline region-fill pass.
struct MapEdgePoint {
  int x;
  int y;

  // 1 if both coordinates match `other`, else 0.
  unsigned int Equals(const MapEdgePoint* other) const;
};

int GetNeighborTileIndexOnMap108x60(int tileIndex, int direction);

int* WrapExtendedMapXCoordinateInPlace(int* x);

// Converts a hex tile index to its overlay-grid coordinate for the given edge side.
int ConvertTileIndexToOverlayCoord216BySide(int tileIndex, char side);

int __stdcall GetMapContextActionCode(short nTileIndex, int dwInputFlags);

int __stdcall GetActiveMapOrderEntryActionCode(short nTileIndex, int dwInputFlags);

void ComputeWrappedIsometricScreenOffsetFromTile(int tileIndex, int* outScreenXY, int tileScale,
                                                 short originCol, short originRow);

void BuildHexNeighborHighlightPolygonForTile(short tileId, int compareValue);

void DrawHexNeighborBorderGuidePathForTile(short tileId, int compareValue, short tileScale);
