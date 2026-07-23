// TMapMaker::GenerateCityRegionIdsBySeedAndNeighborPropagation (0x0052a160) -- the UMapper.cpp
// pass that lays out city regions: seed a label per tile (-1 city / -2 non-city), scatter
// region-centre seeds across a g_regionSeedGridRows x g_regionSeedGridCols lattice with LCG
// jitter (spiral-searching outward for an empty city tile at each lattice point), then flood
// each region id to adjacent same-region city tiles until stable, and write tile[4]=id+0x17.
// Own translation unit (like the other UMapper routines).

#include "game/TMapMaker.h"

#include "decomp_types.h"
#include "game/TMapMgr.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/mfc.h"

namespace {

// Inlined hex neighbour lookup (matches the original's inlined accessor in the flood phase).
inline int HexNeighbor(int tileIndex, int direction) {
  int col;
  if ((tileIndex / 0x6c & 1U) == 0) {
    col = g_hexColOffsetEvenRow_00697450[direction];
  } else {
    col = g_hexColOffsetOddRow_00697480[direction];
  }
  col = tileIndex % 0x6c + col;
  int row = tileIndex / 0x6c + g_hexRowOffset_00697468[direction];
  if (g_pGlobalMapState->hexNeighborWrapHorizontally20 == '\0') {
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

// FUNCTION: IMPERIALISM 0x0052a160
void TMapMaker::GenerateCityRegionIdsBySeedAndNeighborPropagation() {
  short* labels = new short[0x1950];

  // Phase 1: seed a label per tile: -1 for water tiles, -2 otherwise.
  int i = 0;
  short* p = labels;
  do {
    short index = static_cast<short>(i);
    i = i + 1;
    *p = (g_pGlobalMapState->terrainStateTable[index].GetTerrainKind() == kStrategicTerrainWater) -
         2;
    p = p + 1;
  } while (i < 0x1950);
  cityRegionCount2a4 = 0;

  // Phase 2: scatter region-centre seeds across the lattice, spiralling out to the nearest
  // still-empty city tile.
  if (0 < g_regionSeedGridRows_006a38ec) {
    int rowBase = 0;
    int cols = g_regionSeedGridCols_006a38f0;
    int rows = g_regionSeedGridRows_006a38ec;
    int rowIdx = 0;
    do {
      int colIdx = 0;
      if (0 < cols) {
        int colBase = 0;
        do {
          unsigned int r = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
          g_mapGenLcgState_006a38e8 = r * 0x15a4e35 + 1;
          int col = rowBase / rows + 2 + (r >> 0xc & 0x7fff) % 5;
          int row = colBase / cols + 2 + (g_mapGenLcgState_006a38e8 >> 0xc & 0x7fff) % 5;
          if ((colIdx & 1) != 0) {
            col = col + rows / 2;
            if (0x6b < col) {
              col = col - 0x6c;
            }
          }
          int radius = 0;
          int ring = 1;
          int direction = 0;
          TMapMgr::StepHexRowColByDirectionWithWrapRules(&row, &col, 4);
          TMapMgr::StepHexRowColByDirectionWithWrapRules(&row, &col, direction);
          while (ring < 3) {
            int neighbor;
            if (row < 0 || 0x3b < row || col < 0 || 0x6b < col) {
              neighbor = -1;
            } else {
              neighbor = col + row * 0x6c;
            }
            if (neighbor != -1 && labels[neighbor] == -1) {
              labels[neighbor] = static_cast<short>(cityRegionCount2a4);
              cityRegionCount2a4 = cityRegionCount2a4 + 1;
              break;
            }
            radius = radius + 1;
            if (ring <= radius) {
              radius = 0;
              direction = direction + 1;
              if (5 < direction) {
                ring = ring + 1;
                direction = 0;
                TMapMgr::StepHexRowColByDirectionWithWrapRules(&row, &col, 4);
              }
            }
            TMapMgr::StepHexRowColByDirectionWithWrapRules(&row, &col, direction);
          }
          colIdx = colIdx + 1;
          colBase = colBase + 0x6c;
          cols = g_regionSeedGridCols_006a38f0;
          rows = g_regionSeedGridRows_006a38ec;
        } while (colIdx < g_regionSeedGridCols_006a38f0);
      }
      rowIdx = rowIdx + 1;
      rowBase = rowBase + 0x6c;
    } while (rowIdx < rows);
  }

  // Phase 3: flood region ids to adjacent same-region city tiles; the +0x400 bias marks tiles
  // claimed this round so a single pass can't cascade. Repeat until nothing changes, then write
  // the ids back to the tiles.
  do {
    int changed = 0;
    int j = 0;
    short* pj = labels;
    do {
      if (*pj == -1) {
        for (int direction = 0; direction < 6; ++direction) {
          int neighbor = HexNeighbor(j, direction);
          if (neighbor != -1) {
            short nl = labels[neighbor];
            if (-1 < nl && nl < 0x400) {
              *pj = nl + 0x400;
              changed = changed + 1;
            }
          }
        }
      }
      j = j + 1;
      pj = pj + 1;
    } while (j < 0x1950);

    int k = 0x1950;
    short* pk = labels;
    do {
      if (0x3ff < *pk) {
        *pk = *pk - 0x400;
      }
      pk = pk + 1;
      k = k - 1;
    } while (k != 0);

    if (changed < 1) {
      int off = 0;
      short* pw = labels;
      do {
        if (-1 < *pw) {
          *(mapTileGrid08 + 4 + off) = static_cast<char>(*pw) + '\x17';
        }
        off = off + 0x24;
        pw = pw + 1;
      } while (off < 0x38f40);
      delete[] labels;
      return;
    }
  } while (true);
}
