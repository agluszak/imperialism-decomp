// TMapMaker::BuildCityRegionBorderOverlaySegments (0x0052c1a0) -- a ~1.6 KB UMapper.cpp
// routine that scans every tile's hex neighbours and appends a Seapoint into the overlay-quad
// table (g_seapointQuadTable_006a3478) for each city-region border edge. It runs in four
// phases over the 108x60 (=0x1950) tile grid at this->mapTileGrid08 (stride 0x24; a water
// tile carries a city-region id at tile[4]-0x17):
//   1. row 0 tiles (0..0x6b): direction-4 edges only;
//   2. tiles 0x6c..0x194f: directions 4 and 5, with 3-region triple-junction emission;
//   3. all tiles: directions 1 and 2, triple-junction emission via
//      EmitOverlaySegmentFromTileEdgeSorted, tailing off into a direction-1-only sweep of the
//      last rows.
// Its own translation unit (like the merge pass) so the inline accessors fold into the one
// body without perturbing neighbouring methods.

#include "game/map_ui/TMapMaker.h"

#include <stdlib.h>

#include "decomp_types.h"
#include "game/map/TMapMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/map_globals.h"
#include "game/globals/shared_globals.h"
#include "game/map/map_overlay_geometry.h"
#include "game/map/sea_geometry.h"

namespace {

// City-region id at a byte offset / tile index into the grid (inline forms matching the
// original's inlined water-terrain ? tile[4]-0x17 : -1 reads; the method
// GetCityRegionIdAtTileIndex
// is the same logic, used by the original where it emits a real call, in the tail sweep).
inline int RegionAtByteOffset(char* grid, int byteOffset) {
  if (byteOffset < 0) {
    return -1;
  }
  char* tile = grid + byteOffset;
  if (*tile != kStrategicTerrainWater) {
    return -1;
  }
  return tile[4] - 0x17;
}

inline int RegionAtTileIndex(char* grid, int tileIndex) {
  if (tileIndex < 0) {
    return -1;
  }
  char* tile = grid + tileIndex * 0x24;
  if (*tile != kStrategicTerrainWater) {
    return -1;
  }
  return tile[4] - 0x17;
}

// Inlined neighbour lookup (same logic as GetNeighborTileIndexOnMap108x60, which the original
// inlines here for directions 4/5/1 with a constant index and calls out-of-line for direction
// 2 and the tail sweep).
inline int HexNeighborInline(int tileIndex, int direction) {
  int col;
  if ((tileIndex / 0x6c & 1U) == 0) {
    col = g_hexColOffsetEvenRow_00697450[direction];
  } else {
    col = g_hexColOffsetOddRow_00697480[direction];
  }
  col = tileIndex % 0x6c + col;
  int row = tileIndex / 0x6c + g_hexRowOffset_00697468[direction];
  if (g_pGlobalMapState->hexNeighborWrapHorizontally == '\0') {
    if (col < 0) {
      col = col + 0x6c;
    } else if (0x6b < col) {
      col = col - 0x6c;
    }
  } else {
    if (col < 0 || 0x6b < col) {
      return -1;
    }
  }
  if (-1 < row && row < 0x3c) {
    return col + row * 0x6c;
  }
  return -1;
}

// Build a Seapoint (overlay coord for side 1 + the sorted region pair + a side code) and append
// it to the overlay-quad table through the stretch<Seapoint> vtable slot (matching the
// original's inlined ConvertTileIndex + InitSorted + indirect append).
inline void AppendBorderQuad(int tileIndex, int regionA, int regionB, int sideCode) {
  Seapoint sp;
  sp.InitSorted(ConvertTileIndexToOverlayCoord216BySide(tileIndex, 1), regionA, regionB, sideCode);
  stretch<Seapoint>* quad = &g_seapointQuadTable_006a3478;
  quad->Add(sp);
}

} // namespace

// FUNCTION: IMPERIALISM 0x0052c1a0
void TMapMaker::BuildCityRegionBorderOverlaySegments() {

  // Reset the overlay-quad table.
  if (g_seapointQuadTable_006a3478.Data() != nullptr) {
    free(g_seapointQuadTable_006a3478.Detach());
  }

  // Phase 1: row 0 tiles, direction-4 edges.
  int tileIdx = 0;
  int byteOffset = 0;
  do {
    int region1 = RegionAtByteOffset(mapTileGrid08, byteOffset);
    int region2 = RegionAtTileIndex(mapTileGrid08, HexNeighborInline(tileIdx, 4));
    if (region1 != region2 && region1 != -1 && region2 != -1) {
      AppendBorderQuad(tileIdx, region1, region2, 2);
    }
    byteOffset += 0x24;
    tileIdx += 1;
  } while (byteOffset < 0xf30);

  // Phase 2: remaining tiles, directions 4 and 5, with triple-junction emission.
  if (tileIdx < 0x1950) {
    byteOffset = tileIdx * 0x24;
    do {
      int thisRegion = RegionAtByteOffset(mapTileGrid08, byteOffset);
      int dir4region = RegionAtTileIndex(mapTileGrid08, HexNeighborInline(tileIdx, 4));
      int dir5region = RegionAtTileIndex(mapTileGrid08, HexNeighborInline(tileIdx, 5));

      int codeDir45 = 4;
      int codeThisDir4 = 2;
      int savedDir5 = dir5region;
      if (thisRegion == -1) {
        codeDir45 = 2;
        savedDir5 = -1;
        codeThisDir4 = 4;
        thisRegion = dir5region;
      }
      int codeFirst = codeThisDir4;
      int codeSecond = 0;
      int otherDir5 = savedDir5;
      if (dir4region == -1) {
        otherDir5 = -1;
        codeFirst = 0;
        codeSecond = codeThisDir4;
        dir4region = savedDir5;
      }
      if (thisRegion != dir4region && thisRegion != otherDir5 && dir4region != otherDir5) {
        if (otherDir5 == -1) {
          AppendBorderQuad(tileIdx, thisRegion, dir4region, codeFirst);
        } else {
          AppendBorderQuad(tileIdx, thisRegion, dir4region, codeFirst);
          AppendBorderQuad(tileIdx, thisRegion, otherDir5, codeSecond);
          AppendBorderQuad(tileIdx, dir4region, otherDir5, codeDir45);
        }
      }
      byteOffset += 0x24;
      tileIdx += 1;
    } while (byteOffset < 0x38f40);
  }

  // Phase 3: all tiles, directions 1 (inline) and 2 (via the neighbour helper), triple-junction
  // emission via EmitOverlaySegmentFromTileEdgeSorted; tails into a direction-1-only sweep.
  int t3 = 0;
  int off3 = 0;
  do {
    int rThis = RegionAtByteOffset(mapTileGrid08, off3);
    int dir1region = RegionAtTileIndex(mapTileGrid08, HexNeighborInline(t3, 1));
    int dir2region = RegionAtTileIndex(mapTileGrid08, GetNeighborTileIndexOnMap108x60(t3, 2));

    int codeA = 1;
    int codeB = 3;
    int codeThisDir1 = 5;
    int savedDir2 = dir2region;
    if (rThis == -1) {
      codeA = 5;
      savedDir2 = -1;
      codeThisDir1 = 1;
      rThis = dir2region;
    }
    int codeMid = codeThisDir1;
    int otherDir2 = savedDir2;
    if (dir1region == -1) {
      otherDir2 = -1;
      codeMid = 3;
      dir1region = savedDir2;
      codeB = codeThisDir1;
    }
    if (rThis != dir1region && rThis != otherDir2 && dir1region != otherDir2) {
      if (otherDir2 != -1) {
        EmitOverlaySegmentFromTileEdgeSorted(t3, 0, rThis, dir1region, codeMid);
        EmitOverlaySegmentFromTileEdgeSorted(t3, 0, rThis, otherDir2, codeB);
        rThis = dir1region;
        dir1region = otherDir2;
        codeMid = codeA;
      }
      EmitOverlaySegmentFromTileEdgeSorted(t3, 0, rThis, dir1region, codeMid);
    }
    t3 += 1;
    off3 += 0x24;
    if (0x3800f < off3) {
      for (; t3 < 0x1950; t3 += 1) {
        int r1 = GetCityRegionIdAtTileIndex(t3);
        int r2 = GetCityRegionIdAtTileIndex(GetNeighborTileIndexOnMap108x60(t3, 1));
        if (r1 != r2 && r1 != -1 && r2 != -1) {
          EmitOverlaySegmentFromTileEdgeSorted(t3, 0, r1, r2, 5);
        }
      }
      return;
    }
  } while (true);
}
