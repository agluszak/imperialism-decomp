#pragma once

void ComputeHexNeighborTileIndices(short tileIndex, short* neighborTiles, char wrapHorizontally);
short GetWrappedHexNeighborTileIndexByDirection(short tileIndex, short direction);
