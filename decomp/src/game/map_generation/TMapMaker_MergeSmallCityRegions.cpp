// TMapMaker::MergeSmallCityRegionsAndCompactIds (0x0052d750) -- a ~4 KB monolithic UMapper.cpp
// routine that merges undersized city regions into a neighbour and compacts the region-id space.
// Data it drives (subsystem only partially recovered -- accessed via typed views, documented):
//  - the 108x60 tile grid at this->tiles; a water tile carries a city-region id in
//    ownerNationTag04, biased by 0x17;
//  - the global region-border-link table at 0x006a3900 (a stretch<SeaSegment>, i.e. the
//    project's growable-array template, NOT an MFC CArray): each 0x18-byte record holds the
//    shared-border bbox (int16 x0,y0,x1,y1 at +0/2/4/6) and the pair of region ids it
//    connects (uint16 at +0x10/+0x12), which is how this pass reinterprets the segment slot;
//  - per-region tile-count / merged-flag scratch arrays (function locals).

#include "game/map_generation/TMapMaker.h"

#include <math.h>

#include "decomp_types.h"
#include "game/map/TMapMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/map_globals.h"
#include "game/globals/shared_globals.h"
#include "game/map/sea_geometry.h"
#include "game/mfc.h"
#include "game/gfx/ui_invalidation_guard.h"

// The region-border-link table (0x006a3900) and the hex-neighbour offset tables this pass
// reads are defined in global_data_tables.cpp (declared in global_data_tables.h, included
// above).

namespace {

const int kMapWidth = 0x6c;    // 108 columns
const int kMapHeight = 0x3c;   // 60 rows
const int kTileCount = 0x1950; // 108 * 60
const int kRegionIdBias = 0x17;

// Access a region-border link, growing the table through its normal index operator.
inline SeaSegment* LinkElementAt(unsigned int i) {
  SeaSegmentStretch& t = g_regionBorderLinkTable_006a3900;
  return &t[i];
}

// Region id for a city-region tile (-1 if the index is invalid).
inline int TileRegionId(const TTerrainStateRecord* grid, int tileIndex) {
  if (tileIndex < 0) {
    return -1;
  }
  return static_cast<unsigned char>(grid[tileIndex].ownerNationTag04) - kRegionIdBias;
}

} // namespace

// FUNCTION: IMPERIALISM 0x0052d750
void TMapMaker::MergeSmallCityRegionsAndCompactIds() {
  int* tileCounts = new int[cityRegionCount2a4];
  if (tileCounts == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag("D:\\Ambit\\Cross\\UMapper.cpp", 0x11c5);
  }
  char* mergedFlags = new char[cityRegionCount2a4];
  if (mergedFlags == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag("D:\\Ambit\\Cross\\UMapper.cpp", 0x11c8);
  }

  for (int r = cityRegionCount2a4 - 1; r >= 0; --r) {
    tileCounts[r] = 0;
    mergedFlags[r] = 0;
  }

  // Phase 1: count city-region tiles per region id.
  for (int tileIndex = 0; tileIndex < kTileCount; ++tileIndex) {
    if (tiles[tileIndex].terrainKindStorage00 == kStrategicTerrainWater) {
      ++tileCounts[TileRegionId(tiles, tileIndex)];
    }
  }

  // Phase 2: from the last region down, merge each undersized region into its best neighbour and
  // compact ids by swapping the emptied slot with the last active region.
  int region = cityRegionCount2a4;
  while (true) {
    --region;
    if (region < 0) {
      delete[] tileCounts;
      delete[] mergedFlags;
      return;
    }

    const int regionByte = static_cast<unsigned char>(region);

    if (tileCounts[region] > 0 && tileCounts[region] < 0x20) {
      int mergeTarget = -1;
      int bestScore = -1;
      unsigned int bestLink = 0xffffffff;

      // 2a: score every border link touching this region; prefer the target with the largest
      // shared-border area weighted by target size, plus size/merge biases.
      for (unsigned int li = 0;
           li < static_cast<unsigned int>(g_regionBorderLinkTable_006a3900.Count()); ++li) {
        SeaSegment* link = LinkElementAt(li);
        int other;
        if (link->BorderRegionA() == regionByte) {
          other = link->BorderRegionB();
        } else if (link->BorderRegionB() != regionByte) {
          other = 0xfffe;
        } else {
          other = link->BorderRegionA();
        }
        if (static_cast<short>(other) < 0) {
          continue;
        }
        link = LinkElementAt(li);

        int bias = 0;
        if (tileCounts[other] + tileCounts[region] >= 0x20) {
          bias = 0x2710;
        }
        if (mergedFlags[other] == 0) {
          bias += 0x1388;
        }
        const int width = link->BorderX1() - link->BorderX0();
        const int height = link->BorderY1() - link->BorderY0();
        const int areaSq = width * width * height * height;
        const int score =
            static_cast<int>(sqrt(static_cast<double>(areaSq)) * tileCounts[other] + bias);
        if (bestScore < score) {
          bestScore = score;
          mergeTarget = other;
          bestLink = li;
        }
      }

      // 2b: no link neighbour and a very small region -> hex-adjacency search for any adjacent
      // tile belonging to a different region.
      bool unresolved = false;
      if (mergeTarget == -1) {
        if (tileCounts[region] < 7) {
          for (int tileIdx = 0; tileIdx < kTileCount && mergeTarget == -1; ++tileIdx) {
            TTerrainStateRecord* grid = tiles;
            if (grid[tileIdx].terrainKindStorage00 != kStrategicTerrainWater ||
                TileRegionId(grid, tileIdx) != region) {
              continue;
            }
            for (int dir = 0; dir < 6; ++dir) {
              int col = tileIdx % kMapWidth + ((tileIdx / kMapWidth & 1)
                                                   ? g_hexColOffsetOddRow_00697480[dir]
                                                   : g_hexColOffsetEvenRow_00697450[dir]);
              int row = tileIdx / kMapWidth + g_hexRowOffset_00697468[dir];
              int neighbor;
              if (g_pGlobalMapState->hexNeighborWrapHorizontally == '\0') {
                if (col < 0) {
                  col += kMapWidth;
                } else if (col >= kMapWidth) {
                  col -= kMapWidth;
                }
                neighbor = (row < 0 || row >= kMapHeight) ? -1 : col + row * kMapWidth;
              } else {
                neighbor = (col >= 0 && col < kMapWidth && row >= 0 && row < kMapHeight)
                               ? col + row * kMapWidth
                               : -1;
              }
              if (neighbor == -1) {
                continue;
              }
              TTerrainStateRecord* nTile = grid + neighbor;
              if (nTile->terrainKindStorage00 != kStrategicTerrainWater) {
                continue;
              }
              if (TileRegionId(grid, tileIdx) != TileRegionId(grid, neighbor)) {
                mergeTarget = TileRegionId(grid, neighbor);
                break;
              }
            }
          }
        }
        unresolved = (mergeTarget == -1);
      }

      if (!unresolved && mergeTarget >= 0) {
        // 2c: apply the merge -- fold this region's tiles/count into the target.
        tileCounts[mergeTarget] += tileCounts[region];
        tileCounts[region] = 0;
        mergedFlags[mergeTarget] = 1;
        for (int tileIndex = 0; tileIndex < kTileCount; ++tileIndex) {
          if (tiles[tileIndex].terrainKindStorage00 == kStrategicTerrainWater &&
              TileRegionId(tiles, tileIndex) == region) {
            tiles[tileIndex].ownerNationTag04 = static_cast<char>(mergeTarget) + kRegionIdBias;
          }
        }
        // Invalidate the consumed border-link record, then re-point every remaining link that
        // referenced `region` at `mergeTarget`.
        if (static_cast<int>(bestLink) >= 0) {
          SeaSegmentStretch& t = g_regionBorderLinkTable_006a3900;
          SeaSegment* consumed = &t[bestLink];
          consumed->BorderX0() = 0;
          consumed->BorderY0() = 0;
          consumed->BorderX1() = 0;
          consumed->BorderY1() = 0;
          consumed->BorderRegionA() = -1;
          consumed->BorderRegionB() = -1;
          consumed->BorderReserved08() = -1;
          consumed->BorderReserved0c() = -1;
        }
        for (unsigned int li = 0;
             li < static_cast<unsigned int>(g_regionBorderLinkTable_006a3900.Count()); ++li) {
          SeaSegment* link = LinkElementAt(li);
          if (link->BorderRegionA() == region) {
            link = LinkElementAt(li);
            link->BorderRegionA() = static_cast<short>(mergeTarget);
          }
          link = LinkElementAt(li);
          if (link->BorderRegionB() == region) {
            link = LinkElementAt(li);
            link->BorderRegionB() = static_cast<short>(mergeTarget);
          }
        }
      }
    }

    // Phase 3: if this region ended up empty, compact by swapping in the last active region.
    if (tileCounts[region] == 0) {
      int last = cityRegionCount2a4 - 1;
      cityRegionCount2a4 = last;
      tileCounts[region] = tileCounts[last];
      mergedFlags[region] = mergedFlags[cityRegionCount2a4];
      for (int tileIndex = 0; tileIndex < kTileCount; ++tileIndex) {
        if (tiles[tileIndex].terrainKindStorage00 == kStrategicTerrainWater &&
            TileRegionId(tiles, tileIndex) == cityRegionCount2a4) {
          tiles[tileIndex].ownerNationTag04 = static_cast<char>(regionByte) + kRegionIdBias;
        }
      }
      for (unsigned int li = 0;
           li < static_cast<unsigned int>(g_regionBorderLinkTable_006a3900.Count()); ++li) {
        SeaSegment* link = LinkElementAt(li);
        if (link->BorderRegionA() == cityRegionCount2a4) {
          link = LinkElementAt(li);
          link->BorderRegionA() = static_cast<short>(regionByte);
        }
        link = LinkElementAt(li);
        if (link->BorderRegionB() == cityRegionCount2a4) {
          link = LinkElementAt(li);
          link->BorderRegionB() = static_cast<short>(regionByte);
        }
      }
    }
  }
}
