// TMapMaker::RandomizeRegionTemplateBanksForMismatchedNeighborClasses (0x005293d0) -- a
// UMapper.cpp pass that, for each of the three neighbour classes differing from the base
// class, fetches the coarse cell's fine-grid template block (via
// GetFineGridCellBasePointerFromCoarseIndex) and randomly mirrors 9-dword (one tile-row)
// template banks within it using the shared map-gen LCG.

#include "game/map_ui/TMapMaker.h"

#include "decomp_types.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"

// FUNCTION: IMPERIALISM 0x005293d0
unsigned int TMapMaker::RandomizeRegionTemplateBanksForMismatchedNeighborClasses(
    int coarseIndex, unsigned short baseClass, unsigned short class3, unsigned short class4,
    unsigned short class5) {
  unsigned int result = class3;
  if (class3 != baseClass) {
    char* cell = GetFineGridCellBasePointerFromCoarseIndex(coarseIndex);
    g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
    int* dst = nullptr;
    int* src = nullptr;
    int n = 0;
    bool copy = true;
    switch ((g_mapGenLcgState_006a38e8 >> 0xc & 0x7fff) % 5) {
    case 1:
    case 5:
      n = 9;
      src = reinterpret_cast<int*>(cell + 0xfc0);
      dst = reinterpret_cast<int*>(cell + 0xf9c);
      break;
    case 2:
      dst = reinterpret_cast<int*>(cell + 0xfc0);
      n = 9;
      src = reinterpret_cast<int*>(cell + 0xf9c);
      break;
    default:
      copy = false;
      break;
    }
    if (copy) {
      for (; n != 0; n = n + -1) {
        *dst = *src;
        src = src + 1;
        dst = dst + 1;
      }
    }
    dst = reinterpret_cast<int*>(cell + 0x1ecc);
    g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
    unsigned int r = g_mapGenLcgState_006a38e8 >> 0xc & 0x7fff;
    result = r / 5;
    copy = true;
    switch (r % 5) {
    case 1:
      src = reinterpret_cast<int*>(cell + 0x1ef0);
      n = 9;
      break;
    case 2:
    case 5:
      n = 9;
      src = dst;
      dst = reinterpret_cast<int*>(cell + 0x1ef0);
      break;
    default:
      copy = false;
      break;
    }
    if (copy) {
      for (; n != 0; n = n + -1) {
        *dst = *src;
        src = src + 1;
        dst = dst + 1;
      }
    }
  }

  if (class4 != baseClass) {
    char* cell = GetFineGridCellBasePointerFromCoarseIndex(coarseIndex);
    int* dst = reinterpret_cast<int*>(cell + 0x2d90);
    unsigned int r = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
    if ((r >> 0xc & 1) != 0) {
      dst = reinterpret_cast<int*>(cell + 0x2db4);
    }
    g_mapGenLcgState_006a38e8 = r * 0x15a4e35 + 1;
    unsigned int r2 = g_mapGenLcgState_006a38e8 >> 0xc & 0x7fff;
    result = r2 / 7;
    int* src = nullptr;
    int n = 0;
    bool copy = true;
    switch (r2 % 7) {
    case 0:
    case 1:
    case 3:
    case 5:
      src = dst + 0x3cc;
      n = 9;
      break;
    case 2:
    case 4:
    case 6:
      n = 9;
      src = dst;
      dst = dst + 0x3cc;
      break;
    default:
      copy = false;
      break;
    }
    if (copy) {
      for (; n != 0; n = n + -1) {
        *dst = *src;
        src = src + 1;
        dst = dst + 1;
      }
    }
  }

  if (class5 != baseClass) {
    char* cell = GetFineGridCellBasePointerFromCoarseIndex(coarseIndex);
    int* dst = reinterpret_cast<int*>(cell + 0x2dd8);
    unsigned int r = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
    if ((r >> 0xc & 1) != 0) {
      dst = reinterpret_cast<int*>(cell + 0x2dfc);
    }
    g_mapGenLcgState_006a38e8 = r * 0x15a4e35 + 1;
    unsigned int r2 = g_mapGenLcgState_006a38e8 >> 0xc & 0x7fff;
    result = r2 / 7;
    switch (r2 % 7) {
    case 0:
    case 1:
    case 3:
    case 5: {
      int* src = dst + 0x3cc;
      for (int n = 9; n != 0; n = n + -1) {
        *dst = *src;
        src = src + 1;
        dst = dst + 1;
      }
      return result;
    }
    case 2:
    case 4:
    case 6: {
      int* src = dst + 0x3cc;
      for (int n = 9; n != 0; n = n + -1) {
        *src = *dst;
        dst = dst + 1;
        src = src + 1;
      }
      break;
    }
    default:
      break;
    }
  }
  return result;
}
