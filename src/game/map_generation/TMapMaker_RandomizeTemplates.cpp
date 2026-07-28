// TMapMaker::RandomizeRegionTemplateBanksForMismatchedNeighborClasses (0x005293d0) -- a
// UMapper.cpp pass that, for each of the three neighbour classes differing from the base
// class, fetches the coarse cell's fine-grid template block (via
// GetFineGridCellBasePointerFromCoarseIndex) and randomly mirrors 9-dword (one tile-row)
// template banks within it using the shared map-gen LCG.

#include "game/map_generation/TMapMaker.h"

#include <string.h>

#include "decomp_types.h"
#include "game/globals/map_globals.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"

// FUNCTION: IMPERIALISM 0x005293d0
unsigned int TMapMaker::RandomizeRegionTemplateBanksForMismatchedNeighborClasses(
    int coarseIndex, unsigned short baseClass, unsigned short class3, unsigned short class4,
    unsigned short class5) {
  unsigned int result = class3;
  if (class3 != baseClass) {
    MapGeneratorTileRecord* cell = GetFineGridCellBasePointerFromCoarseIndex(coarseIndex);
    g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
    MapGeneratorTileRecord* dst = nullptr;
    MapGeneratorTileRecord* src = nullptr;
    bool copy = true;
    switch ((g_mapGenLcgState_006a38e8 >> 0xc & 0x7fff) % 5) {
    case 1:
    case 5:
      src = &cell[112];
      dst = &cell[111];
      break;
    case 2:
      dst = &cell[112];
      src = &cell[111];
      break;
    default:
      copy = false;
      break;
    }
    if (copy) {
      memcpy(dst, src, sizeof(*dst));
    }
    dst = &cell[219];
    g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
    unsigned int r = g_mapGenLcgState_006a38e8 >> 0xc & 0x7fff;
    result = r / 5;
    copy = true;
    switch (r % 5) {
    case 1:
      src = &cell[220];
      break;
    case 2:
    case 5:
      src = dst;
      dst = &cell[220];
      break;
    default:
      copy = false;
      break;
    }
    if (copy) {
      memcpy(dst, src, sizeof(*dst));
    }
  }

  if (class4 != baseClass) {
    MapGeneratorTileRecord* cell = GetFineGridCellBasePointerFromCoarseIndex(coarseIndex);
    MapGeneratorTileRecord* dst = &cell[324];
    unsigned int r = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
    if ((r >> 0xc & 1) != 0) {
      dst = &cell[325];
    }
    g_mapGenLcgState_006a38e8 = r * 0x15a4e35 + 1;
    unsigned int r2 = g_mapGenLcgState_006a38e8 >> 0xc & 0x7fff;
    result = r2 / 7;
    MapGeneratorTileRecord* src = nullptr;
    bool copy = true;
    switch (r2 % 7) {
    case 0:
    case 1:
    case 3:
    case 5:
      src = dst + 108;
      break;
    case 2:
    case 4:
    case 6:
      src = dst;
      dst = dst + 108;
      break;
    default:
      copy = false;
      break;
    }
    if (copy) {
      memcpy(dst, src, sizeof(*dst));
    }
  }

  if (class5 != baseClass) {
    MapGeneratorTileRecord* cell = GetFineGridCellBasePointerFromCoarseIndex(coarseIndex);
    MapGeneratorTileRecord* dst = &cell[326];
    unsigned int r = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
    if ((r >> 0xc & 1) != 0) {
      dst = &cell[327];
    }
    g_mapGenLcgState_006a38e8 = r * 0x15a4e35 + 1;
    unsigned int r2 = g_mapGenLcgState_006a38e8 >> 0xc & 0x7fff;
    result = r2 / 7;
    switch (r2 % 7) {
    case 0:
    case 1:
    case 3:
    case 5: {
      MapGeneratorTileRecord* src = dst + 108;
      memcpy(dst, src, sizeof(*dst));
      return result;
    }
    case 2:
    case 4:
    case 6: {
      MapGeneratorTileRecord* src = dst + 108;
      memcpy(src, dst, sizeof(*src));
      break;
    }
    default:
      break;
    }
  }
  return result;
}
