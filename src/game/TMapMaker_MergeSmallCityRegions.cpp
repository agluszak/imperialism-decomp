// TMapMaker::MergeSmallCityRegionsAndCompactIds (0x0052d750) -- a ~4 KB monolithic UMapper.cpp
// routine that merges undersized city regions into a neighbour and compacts the region-id space.
// It lives in its own translation unit so the inline accessors below fold into the one-function
// body (the build uses /Ob1) without perturbing neighbouring TMapMaker methods.
//
// Data it drives (subsystem only partially recovered -- accessed via typed views, documented):
//  - the 108x60 = 6480-tile grid at this->mapTileGrid08 (stride 0x24; a "city region" tile has
//    tile[0]==5, region id = tile[4]-0x17);
//  - the global region-border-link table at 0x006a3900 (MFC-CArray-style grow buffer): each
//    0x18-byte record holds the shared-border bbox (int16 x0,y0,x1,y1 at +0/2/4/6) and the pair
//    of region ids it connects (uint16 at +0x10/+0x12);
//  - per-region tile-count / merged-flag scratch arrays (function locals).

#include "game/TMapMaker.h"

#include <math.h>

#include "decomp_types.h"
#include "game/TGlobalMapState.h"
#include "game/global_data_tables.h"
#include "game/mfc.h"
#include "game/ui_invalidation_guard.h"

// Unrecovered helpers reached via typed casts at the call sites (generic stub form).
extern undefined4 ReallocateHeapBlockWithAllocatorTracking(void); // allocator-tracked realloc
extern undefined4 ReserveOverlaySpanRecordArray18Capacity(void);  // 0x0052b3e0 (thiscall on table)
extern undefined4
ReallocateRouteRecordBufferByCountStride18(void); // 0x0052e310 (thiscall on table)

// One 0x18-byte region-border-link record.
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

// The global region-border-link table object at 0x006a3900.
struct RegionBorderLinkTable {
  int field00;              // +0x00
  RegionBorderLink* buffer; // +0x04
  int capacity;             // +0x08 (elements)
  int count;                // +0x0c
};
RegionBorderLinkTable g_regionBorderLinkTable_006a3900;

// Hex-neighbour offset tables (offset-coordinate grid; even/odd rows shift columns differently).
const int g_hexColOffsetEvenRow_00697450[6] = {0, 1, 0, -1, -1, -1};
const int g_hexRowOffset_00697468[6] = {-1, 0, 1, 1, 0, -1};
const int g_hexColOffsetOddRow_00697480[6] = {1, 1, 1, 0, -1, 0};

namespace {

const int kMapWidth = 0x6c;         // 108 columns
const int kMapHeight = 0x3c;        // 60 rows
const int kTileStride = 0x24;       // 36 bytes / tile
const int kTileGridBytes = 0x38f40; // 6480 * 0x24
const int kRegionIdBias = 0x17;     // tile[4] region id is biased by +0x17

// MFC-CArray-style ElementAt(i): grow buffer/count so i is addressable, then return &record[i].
inline RegionBorderLink* LinkElementAt(unsigned int i) {
  RegionBorderLinkTable& t = g_regionBorderLinkTable_006a3900;
  if (static_cast<unsigned int>(t.capacity) <= i) {
    reinterpret_cast<void(__fastcall*)(RegionBorderLinkTable*, int)>(
        ReserveOverlaySpanRecordArray18Capacity)(&t, i + 1);
  }
  if (static_cast<unsigned int>(t.count) <= i) {
    t.count = i + 1;
  }
  return &t.buffer[i];
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
           li < static_cast<unsigned int>(g_regionBorderLinkTable_006a3900.count); ++li) {
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
          RegionBorderLinkTable& t = g_regionBorderLinkTable_006a3900;
          if (static_cast<unsigned int>(t.capacity) <= bestLink) {
            int want = bestLink + 1;
            unsigned int newCap = static_cast<unsigned int>(want) * 2;
            if (newCap > 0x7fffffff) {
              newCap = 0x7fffffff;
            }
            RegionBorderLink* grown =
                reinterpret_cast<RegionBorderLink*>(reinterpret_cast<void*(__cdecl*)(void*, int)>(
                    ReallocateHeapBlockWithAllocatorTracking)(t.buffer, want * 0x18));
            if (grown == nullptr) {
              reinterpret_cast<void(__fastcall*)(RegionBorderLinkTable*, int)>(
                  ReallocateRouteRecordBufferByCountStride18)(&t, want);
            } else {
              t.buffer = grown;
              t.capacity = newCap;
            }
          }
          if (static_cast<unsigned int>(t.count) <= bestLink) {
            t.count = bestLink + 1;
          }
          RegionBorderLink* consumed = &t.buffer[bestLink];
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
             li < static_cast<unsigned int>(g_regionBorderLinkTable_006a3900.count); ++li) {
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
           li < static_cast<unsigned int>(g_regionBorderLinkTable_006a3900.count); ++li) {
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
