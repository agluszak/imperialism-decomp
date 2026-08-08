#pragma once

// Hex-tile distance on a 29-wide (0x1d) doubled-column hex grid -- distinct from the
// 108-wide strategic map overlay grid in map_overlay_geometry. Used by the AI players
// (TNavyAutoPlayer / TArmyPlayer) for tile-to-tile range scoring.
// Returns the hex step distance between two tile indices. 0x005A39A0.
int ComputeHexTileDistanceFromIndices(int tileIndexA, int tileIndexB);
