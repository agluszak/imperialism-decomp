// TMapMaker::MergeSmallCityRegionsAndCompactIds (0x0052d750) -- a ~4 KB monolithic UMapper.cpp
// routine that merges undersized city regions into a neighbour and compacts the region-id space.
// It lives in its own translation unit so the inline accessors below fold into the one-function
// body (the build uses /Ob1) without perturbing neighbouring TMapMaker methods.
//
// Data it drives (subsystem only partially recovered -- accessed via typed views, documented):
//  - the 108x60 = 6480-tile grid at this->mapTileGrid08 (stride 0x24; a "city region" tile has
//    tile[0]==5, region id = tile[4]-0x17);
//  - the global region-border-link table at 0x006a3900 (a stretch<SeaSegment>, i.e. the
//    project's growable-array template, NOT an MFC CArray): each 0x18-byte record holds the
//    shared-border bbox (int16 x0,y0,x1,y1 at +0/2/4/6) and the pair of region ids it
//    connects (uint16 at +0x10/+0x12), which is how this pass reinterprets the segment slot;
//  - per-region tile-count / merged-flag scratch arrays (function locals).

#include <stdlib.h>

#include "game/TMapMaker.h"

#include <math.h>

#include "decomp_types.h"
#include "game/TGlobalMapState.h"
#include "game/global_data_tables.h"
#include "game/sea_geometry.h"
#include "game/mfc.h"
#include "game/ui_invalidation_guard.h"

// Allocator-tracked realloc (generic stub form; typed cast at the call site).

// One 0x18-byte region-border-link record (the overlay-span record this pass stores).
struct RegionBorderLink {
  short bboxX0;           // +0x00
  short bboxY0;           // +0x02
  short bboxX1;           // +0x04
  short bboxY1;           // +0x06
  int reserved08;         // +0x08
  int reserved0c;         // +0x0c
  unsigned short regionA; // +0x10
  unsigned short regionB; // +0x12
  short reserved14;       // +0x14
  short reserved16;       // +0x16
};

// The region-border-link table (0x006a3900) and the hex-neighbour offset tables this pass
// reads are defined in global_data_tables.cpp (declared in global_data_tables.h, included
// above).

namespace {

const int kMapWidth = 0x6c;         // 108 columns
const int kMapHeight = 0x3c;        // 60 rows
const int kTileStride = 0x24;       // 36 bytes / tile
const int kTileGridBytes = 0x38f40; // 6480 * 0x24
const int kRegionIdBias = 0x17;     // tile[4] region id is biased by +0x17

// Inlined ElementAt(i) matching the original's inlined table access: grow via the real
// OverStretch method on a miss, bump count, then return the (region-border-typed) record.
inline RegionBorderLink* LinkElementAt(unsigned int i) {
  SeaSegmentStretch& t = g_regionBorderLinkTable_006a3900;
  if (static_cast<unsigned int>(t.Capacity()) <= i) {
    t.OverStretch(i + 1);
  }
  if (static_cast<unsigned int>(t.Count()) <= i) {
    t.Count() = i + 1;
  }
  return reinterpret_cast<RegionBorderLink*>(&t.Data()[i]);
}

// region id for the city-region tile at byte offset `off` in the grid (-1 if offset negative).
inline int TileRegionId(char* grid, int off) {
  if (off < 0) {
    return -1;
  }
  return static_cast<unsigned char>(grid[off + 4]) - kRegionIdBias;
}

} // namespace

// FUNCTION: IMPERIALISM 0x0052d750
void TMapMaker::MergeSmallCityRegionsAndCompactIds() {
  int* tileCounts = reinterpret_cast<int*>(::operator new(cityRegionCount2a4 * 4));
  if (tileCounts == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag("D:\\Ambit\\Cross\\UMapper.cpp", 0x11c5);
  }
  char* mergedFlags = reinterpret_cast<char*>(::operator new(cityRegionCount2a4));
  if (mergedFlags == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag("D:\\Ambit\\Cross\\UMapper.cpp", 0x11c8);
  }

  for (int r = cityRegionCount2a4 - 1; r >= 0; --r) {
    tileCounts[r] = 0;
    mergedFlags[r] = 0;
  }

  // Phase 1: count city-region tiles per region id.
  for (int off = 0; off < kTileGridBytes; off += kTileStride) {
    if (mapTileGrid08[off] == '\x05') {
      ++tileCounts[TileRegionId(mapTileGrid08, off)];
    }
  }

  // Phase 2: from the last region down, merge each undersized region into its best neighbour and
  // compact ids by swapping the emptied slot with the last active region.
  int region = cityRegionCount2a4;
  while (true) {
    --region;
    if (region < 0) {
      ::operator delete(tileCounts);
      ::operator delete(mergedFlags);
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
        RegionBorderLink* link = LinkElementAt(li);
        int other;
        if (link->regionA == regionByte) {
          other = static_cast<short>(link->regionB);
        } else if (link->regionB != regionByte) {
          other = 0xfffe;
        } else {
          other = static_cast<short>(link->regionA);
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
        const int width = link->bboxX1 - link->bboxX0;
        const int height = link->bboxY1 - link->bboxY0;
        const int areaSq = width * width * height * height;
        // MSVC emits the FILD/FSQRT/FIMUL/FIADD chain + a _ftol (0x5e73d0) call for this
        // (double)->int cast, matching the original.
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
          int tileIdx = 0;
          for (int off = 0; off < kTileGridBytes && mergeTarget == -1;
               off += kTileStride, ++tileIdx) {
            char* grid = mapTileGrid08;
            if (grid[off] != '\x05' || TileRegionId(grid, off) != region) {
              continue;
            }
            for (int dir = 0; dir < 6; ++dir) {
              int col = tileIdx % kMapWidth + ((tileIdx / kMapWidth & 1)
                                                   ? g_hexColOffsetOddRow_00697480[dir]
                                                   : g_hexColOffsetEvenRow_00697450[dir]);
              int row = tileIdx / kMapWidth + g_hexRowOffset_00697468[dir];
              int neighbor;
              if (g_pGlobalMapState->hexNeighborWrapHorizontally20 == '\0') {
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
              char* nTile = grid + neighbor * kTileStride;
              if (*nTile != '\x05') {
                continue;
              }
              if (TileRegionId(grid, off) != TileRegionId(grid, neighbor * kTileStride)) {
                mergeTarget = TileRegionId(grid, neighbor * kTileStride);
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
        for (int off = 0; off < kTileGridBytes; off += kTileStride) {
          if (mapTileGrid08[off] == '\x05' && TileRegionId(mapTileGrid08, off) == region) {
            mapTileGrid08[off + 4] = static_cast<char>(mergeTarget) + kRegionIdBias;
          }
        }
        // Invalidate the consumed border-link record, then re-point every remaining link that
        // referenced `region` at `mergeTarget`.
        if (static_cast<int>(bestLink) >= 0) {
          SeaSegmentStretch& t = g_regionBorderLinkTable_006a3900;
          if (static_cast<unsigned int>(t.Capacity()) <= bestLink) {
            int want = bestLink + 1;
            unsigned int newCap = static_cast<unsigned int>(want) * 2;
            if (newCap > 0x7fffffff) {
              newCap = 0x7fffffff;
            }
            SeaSegment* grown = reinterpret_cast<SeaSegment*>(realloc(t.Data(), want * 0x30));
            if (grown == nullptr) {
              t.ReallocExact(want);
            } else {
              t.Data() = grown;
              t.Capacity() = newCap;
            }
          }
          if (static_cast<unsigned int>(t.Count()) <= bestLink) {
            t.Count() = bestLink + 1;
          }
          RegionBorderLink* consumed = reinterpret_cast<RegionBorderLink*>(&t.Data()[bestLink]);
          consumed->bboxX0 = 0;
          consumed->bboxY0 = 0;
          consumed->bboxX1 = 0;
          consumed->bboxY1 = 0;
          consumed->regionA = 0xffff;
          consumed->regionB = 0xffff;
          consumed->reserved08 = -1;
          consumed->reserved0c = -1;
        }
        for (unsigned int li = 0;
             li < static_cast<unsigned int>(g_regionBorderLinkTable_006a3900.Count()); ++li) {
          RegionBorderLink* link = LinkElementAt(li);
          if (link->regionA == region) {
            link = LinkElementAt(li);
            link->regionA = static_cast<unsigned short>(mergeTarget);
          }
          link = LinkElementAt(li);
          if (link->regionB == region) {
            link = LinkElementAt(li);
            link->regionB = static_cast<unsigned short>(mergeTarget);
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
      for (int off = 0; off < kTileGridBytes; off += kTileStride) {
        if (mapTileGrid08[off] == '\x05' &&
            TileRegionId(mapTileGrid08, off) == cityRegionCount2a4) {
          mapTileGrid08[off + 4] = static_cast<char>(regionByte) + kRegionIdBias;
        }
      }
      for (unsigned int li = 0;
           li < static_cast<unsigned int>(g_regionBorderLinkTable_006a3900.Count()); ++li) {
        RegionBorderLink* link = LinkElementAt(li);
        if (static_cast<int>(static_cast<short>(link->regionA)) == cityRegionCount2a4) {
          link = LinkElementAt(li);
          link->regionA = static_cast<unsigned short>(regionByte);
        }
        link = LinkElementAt(li);
        if (static_cast<int>(static_cast<short>(link->regionB)) == cityRegionCount2a4) {
          link = LinkElementAt(li);
          link->regionB = static_cast<unsigned short>(regionByte);
        }
      }
    }
  }
}
