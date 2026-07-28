// TMapMaker::ReindexContiguousCityRegionIds (0x0052d1f0) -- a UMapper.cpp pass that compacts
// city-region ids into a contiguous 0..N range. It works in a 6480-entry (0x1950) short label
// buffer on the stack (large enough to trip MSVC's _chkstk frame probe):
//   1. seed labels[tile] = -2 - regionId for water tiles, else -1;
//   2. repeatedly: assign the next compacted id to the first tile carrying each old label, then
//      flood that id to same-original-region hex neighbours, until a pass assigns nothing new;
//   3. write labels back (tile[4] = label + 0x17) and store the new region count.
// Its own translation unit (like the other UMapper routines) so the inline neighbour accessor
// folds into the one body.

#include "game/map_ui/TMapMaker.h"

#include "decomp_types.h"
#include "game/map/TMapMgr.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/map/map_overlay_geometry.h"

namespace {

// Inlined hex neighbour lookup (same logic as GetNeighborTileIndexOnMap108x60, which the
// original inlines here), direction 0..5; -1 if off-map.
inline int HexNeighbor(int tileIndex, int direction) {
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

} // namespace

// FUNCTION: IMPERIALISM 0x0052d1f0
void TMapMaker::ReindexContiguousCityRegionIds() {
  short labels[0x1950];

  // Phase 1: seed a label per tile.
  char* tile = mapTileGrid08;
  unsigned int i = 0;
  short* p = labels;
  do {
    short value;
    if (*tile == kStrategicTerrainWater) {
      if (static_cast<int>(i) < 0) {
        value = -1;
      } else {
        value = static_cast<short>(-2 - (tile[4] - 0x17));
      }
    } else {
      value = -1;
    }
    *p = value;
    i = i + 1;
    tile = tile + 0x24;
    p = p + 1;
  } while (i < 0x1950);

  int newCount = 0;
  do {
    // Assign the next compacted id to the first tile carrying each old label value.
    int remaining = cityRegionCount2a4;
    int assigned = 0;
    if (remaining > 0) {
      int label = -2;
      do {
        int j = 0;
        short* pj = labels;
        do {
          if (label == *pj) {
            labels[j] = static_cast<short>(newCount);
            newCount = newCount + 1;
            assigned = assigned + 1;
            break;
          }
          j = j + 1;
          pj = pj + 1;
        } while (j < 0x1950);
        label = label - 1;
        remaining = remaining - 1;
      } while (remaining != 0);
    }

    if (assigned == 0) {
      // Write the compacted ids back into the tiles and store the new count.
      unsigned int off = 0;
      short* pw = labels;
      do {
        char* t = mapTileGrid08 + off;
        if (*t == kStrategicTerrainWater) {
          t[4] = static_cast<char>(*pw) + '\x17';
        }
        off = off + 0x24;
        pw = pw + 1;
      } while (off < 0x38f40);
      cityRegionCount2a4 = newCount;
      return;
    }

    // Flood each freshly-assigned id to same-original-region hex neighbours, repeating until a
    // pass changes nothing.
    int changed;
    do {
      int j = 0;
      short* pj = labels;
      changed = 0;
      do {
        if (*pj < -1) {
          for (int direction = 0; direction < 6; ++direction) {
            int neighbor = HexNeighbor(j, direction);
            if (-1 < neighbor && -1 < labels[neighbor]) {
              if (GetCityRegionIdAtTileIndex(j) == GetCityRegionIdAtTileIndex(neighbor)) {
                *pj = labels[neighbor];
                changed = changed + 1;
                break;
              }
            }
          }
        }
        j = j + 1;
        pj = pj + 1;
      } while (j < 0x1950);
    } while (changed != 0);
  } while (true);
}
