#include <string.h>
#include <time.h>

#include "game/TMapMaker.h"
#include "game/CString.h"
#include "game/TObject.h"
#include "game/TControl.h"
#include "game/TMapMgr.h"
#include "game/TSetupRandomMapPicture.h"
#include "game/global_data_tables.h"
#include "game/sea_geometry.h"

// Same hex-neighbor math as TMapMgr::ComputeHexNeighborTileIndices, but over
// TMapMaker's own full-resolution generation grid (mapTileGrid08, 108x60, stride
// 0x24) rather than the coarse 15x27 region grid.
static __inline int ComputeHexAdjacentFullGridTileIndex(int tileIndex, int direction);

// SYNTHETIC: IMPERIALISM 0x00525950
// TMapMaker::GetRuntimeClass
IMPLEMENT_DYNAMIC(TMapMaker, TObject)

// FUNCTION: IMPERIALISM 0x00525970
TMapMaker::TMapMaker() : TObject() {}

// SYNTHETIC: IMPERIALISM 0x00525990
// TMapMaker::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x005259c0
TMapMaker::~TMapMaker() {}

// Inline-expanded at every keyword test in 0x525a30 (the original emits the compare
// loop at each site): true when `text` begins with `keyword` followed by NUL or ' '.
static __inline char TuningKeywordMatches(const char* text, const char* keyword) {
  char k = *keyword;
  if (k != 0) {
    do {
      if (k != *text) {
        return 0;
      }
      ++keyword;
      k = *keyword;
      ++text;
    } while (k != 0);
  }
  if (*text != 0 && *text != ' ') {
    return 0;
  }
  return 1;
}

// FUNCTION: IMPERIALISM 0x00525a30
void TMapMaker::GenerateMapFromTuningStringAndApplyScenarioOverrides(char* tileGrid,
                                                                     Province* cityTable,
                                                                     CString* tuningString) {
  mapTileGrid08 = tileGrid;
  cityScoreTable0c = cityTable;
  g_mapGenDesertQuota_006a38bc = 200;
  g_mapGenMountainQuota_006a3470 = 150;
  g_mapGenHillsQuota_006a38c0 = 250;
  g_mapGenForestQuota_006a38f8 = 250;
  g_mapGenSwampQuota_006a38e0 = 150;
  g_mapGenRiverCount_006a38e4 = 10;
  g_regionSeedGridRows_006a38ec = 14;
  g_regionSeedGridCols_006a38f0 = 8;

  // Parse the tuning string: option letters only count after the "@^>" marker.
  int budget = 1000;
  const char* p = static_cast<LPCSTR>(*tuningString);
  char armed = 0;
  char c = *p;
  while (c != 0) {
    if (armed == 0) {
      if (c == '@') {
        c = *++p;
        if (c == '^') {
          c = *++p;
          armed = (c == '>');
        }
      }
    }
    if (armed != 0) {
      switch (c) {
      case 'D':
        g_mapGenDesertQuota_006a38bc = 300;
        break;
      case 'd':
        g_mapGenDesertQuota_006a38bc = 100;
        break;
      case 'M':
        g_mapGenMountainQuota_006a3470 = 300;
        break;
      case 'm':
        g_mapGenMountainQuota_006a3470 = 100;
        break;
      case 'H':
        g_mapGenHillsQuota_006a38c0 = 500;
        break;
      case 'h':
        g_mapGenHillsQuota_006a38c0 = 100;
        break;
      case 'F':
        g_mapGenForestQuota_006a38f8 = 500;
        break;
      case 'f':
        g_mapGenForestQuota_006a38f8 = 100;
        break;
      case 'S':
        g_mapGenSwampQuota_006a38e0 = 300;
        break;
      case 's':
        g_mapGenSwampQuota_006a38e0 = 100;
        break;
      case 'P':
        budget = 750;
        break;
      case 'p':
        budget = 1500;
        break;
      case 'R':
        g_mapGenRiverCount_006a38e4 = 20;
        break;
      case 'r':
        g_mapGenRiverCount_006a38e4 = 5;
        break;
      case 'c':
        g_regionSeedGridRows_006a38ec = 18;
        g_regionSeedGridCols_006a38f0 = 10;
        break;
      case 'C':
        g_regionSeedGridRows_006a38ec = 10;
        g_regionSeedGridCols_006a38f0 = 6;
        break;
      default:
        break;
      }
    }
    c = *++p;
  }

  // Rescale the five class quotas to the chosen budget.
  int quotaSum = g_mapGenSwampQuota_006a38e0 + g_mapGenHillsQuota_006a38c0 +
                 g_mapGenForestQuota_006a38f8 + g_mapGenDesertQuota_006a38bc +
                 g_mapGenMountainQuota_006a3470;
  if (quotaSum != budget) {
    g_mapGenDesertQuota_006a38bc = budget * g_mapGenDesertQuota_006a38bc / quotaSum;
    g_mapGenMountainQuota_006a3470 = budget * g_mapGenMountainQuota_006a3470 / quotaSum;
    g_mapGenHillsQuota_006a38c0 = budget * g_mapGenHillsQuota_006a38c0 / quotaSum;
    g_mapGenForestQuota_006a38f8 = budget * g_mapGenForestQuota_006a38f8 / quotaSum;
    g_mapGenSwampQuota_006a38e0 = budget * g_mapGenSwampQuota_006a38e0 / quotaSum;
  }

  // Hash the tuning string into the map-gen PRNG seed (falling back to wall clock),
  // and derive the zone status-code seed from one LCG advance.
  const char* h = static_cast<LPCSTR>(*tuningString);
  int seed = 0x6e616461;
  for (char hc = *h; hc != 0; hc = *++h) {
    seed = (seed >> 16) + seed * 2 + hc;
  }
  g_mapGenLcgState_006a38e8 = seed;
  if (seed == 0) {
    // CRT time(); seed is 0 on this path, so the original's pushed arg is NULL.
    seed = time(0);
  }
  seed = seed * 0x15a4e35 + 1;
  g_mapGenLcgState_006a38e8 = seed;
  g_zoneStatusCodePrngSeed_006a5aec = (static_cast<unsigned int>(seed) >> 12) & 0x7fff;
  if (g_zoneStatusCodePrngSeed_006a5aec == 0) {
    g_zoneStatusCodePrngSeed_006a5aec = time(0);
  }

  for (;;) {
    // Attempt loop: regenerate until the attempt sticks and both region-class
    // validations accept it. The setup-picture globe spins between every phase.
    char retryAttempt;
    do {
      if (g_pActiveRandomMapSetupPicture006A4268 != 0) {
        g_pActiveRandomMapSetupPicture006A4268->SpinYourGlobe();
      }
      RunMapGenerationAttempt();
      retryAttempt = ErrorCheck();
      if (retryAttempt != 0) {
        retryAttempt = 1;
      } else if (ValidateAllColumnsHaveAssignedRegionClass() == 0) {
        retryAttempt = 1;
      } else {
        retryAttempt = (ValidateTerrainClassAdjacencyCoverageMask() == 0);
      }
    } while (retryAttempt != 0);

    // Backfill the unassigned city-region id slots.
    if (g_pActiveRandomMapSetupPicture006A4268 != 0) {
      g_pActiveRandomMapSetupPicture006A4268->SpinYourGlobe();
    }
    int i;
    for (i = 0x17; i != 0; --i) {
      if (cityRegionIds200[0x17 - i] == -1) {
        cityRegionIds200[0x17 - i] = ++cityRegionNextId1fc;
      }
    }

    if (g_pActiveRandomMapSetupPicture006A4268 != 0) {
      g_pActiveRandomMapSetupPicture006A4268->SpinYourGlobe();
    }
    MapGenPassSlot0E();
    if (g_pActiveRandomMapSetupPicture006A4268 != 0) {
      g_pActiveRandomMapSetupPicture006A4268->SpinYourGlobe();
    }
    if (g_pActiveRandomMapSetupPicture006A4268 != 0) {
      g_pActiveRandomMapSetupPicture006A4268->SpinYourGlobe();
    }
    MapGenPassSlot1E();
    if (g_pActiveRandomMapSetupPicture006A4268 != 0) {
      g_pActiveRandomMapSetupPicture006A4268->SpinYourGlobe();
    }
    MapGenPassSlot0F();
    if (g_pActiveRandomMapSetupPicture006A4268 != 0) {
      g_pActiveRandomMapSetupPicture006A4268->SpinYourGlobe();
    }
    RotateMapColumnsByPeakCityTileDensity();
    if (g_pActiveRandomMapSetupPicture006A4268 != 0) {
      g_pActiveRandomMapSetupPicture006A4268->SpinYourGlobe();
    }
    MapGenFinalizePassSlot19(0);

    // Easter-egg keyword overrides: each mutates matching land tiles (type 5 = water
    // is always skipped) with a per-tile LCG draw.
    const char* text = static_cast<LPCSTR>(*tuningString);
    if (TuningKeywordMatches(text, "Dune")) {
      char* tile = mapTileGrid08;
      int t;
      for (t = 0x1950; t != 0; --t) {
        if (*tile != 5) {
          g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
          if (static_cast<int>((g_mapGenLcgState_006a38e8 >> 12) & 0x7fff) % 10 != 0) {
            *tile = 6;
          }
        }
        tile += 0x24;
      }
    }
    text = static_cast<LPCSTR>(*tuningString);
    if (TuningKeywordMatches(text, "Congo")) {
      char* tile = mapTileGrid08;
      int t;
      for (t = 0x1950; t != 0; --t) {
        if (*tile != 5) {
          g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
          if (static_cast<int>((g_mapGenLcgState_006a38e8 >> 12) & 0x7fff) % 10 != 0) {
            *tile = 1;
            tile[0x13] = 0xd;
          }
        }
        tile += 0x24;
      }
    }
    text = static_cast<LPCSTR>(*tuningString);
    if (TuningKeywordMatches(text, "Mirkwood")) {
      char* tile = mapTileGrid08;
      int t;
      for (t = 0x1950; t != 0; --t) {
        if (*tile != 5) {
          g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
          if (static_cast<int>((g_mapGenLcgState_006a38e8 >> 12) & 0x7fff) % 10 != 0) {
            *tile = 1;
            g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
            tile[0x13] = static_cast<char>(((~(g_mapGenLcgState_006a38e8 >> 12) & 1) << 1) | 0xd);
          }
        }
        tile += 0x24;
      }
    }
    text = static_cast<LPCSTR>(*tuningString);
    if (TuningKeywordMatches(text, "Yucatan") ||
        TuningKeywordMatches(static_cast<LPCSTR>(*tuningString), "Siberia")) {
      char* tile = mapTileGrid08;
      int t;
      for (t = 0x1950; t != 0; --t) {
        if (*tile != 5) {
          g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
          if (static_cast<int>((g_mapGenLcgState_006a38e8 >> 12) & 0x7fff) % 10 != 0) {
            *tile = 1;
            tile[0x13] = 0xf;
          }
        }
        tile += 0x24;
      }
    }
    text = static_cast<LPCSTR>(*tuningString);
    if (TuningKeywordMatches(text, "Antarctica")) {
      char* tile = mapTileGrid08;
      int t;
      for (t = 0x1950; t != 0; --t) {
        if (*tile != 5) {
          g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
          if (static_cast<int>((g_mapGenLcgState_006a38e8 >> 12) & 0x7fff) % 10 != 0) {
            *tile = 6;
            tile[0x13] = 0xc;
          }
        }
        tile += 0x24;
      }
    }
    text = static_cast<LPCSTR>(*tuningString);
    if (TuningKeywordMatches(text, "Kansas")) {
      char* tile = mapTileGrid08;
      int t;
      for (t = 0x1950; t != 0; --t) {
        if (*tile != 5) {
          g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
          if (static_cast<int>((g_mapGenLcgState_006a38e8 >> 12) & 0x7fff) % 10 != 0) {
            *tile = 0;
          }
        }
        tile += 0x24;
      }
    }
    text = static_cast<LPCSTR>(*tuningString);
    if (TuningKeywordMatches(text, "Eden")) {
      char* tile = mapTileGrid08;
      int t;
      for (t = 0x1950; t != 0; --t) {
        if (*tile != 5) {
          g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
          if (static_cast<int>((g_mapGenLcgState_006a38e8 >> 12) & 0x7fff) % 10 != 0) {
            *tile = 7;
          }
        }
        tile += 0x24;
      }
    }
    text = static_cast<LPCSTR>(*tuningString);
    if (TuningKeywordMatches(text, "Everglades")) {
      char* tile = mapTileGrid08;
      int t;
      for (t = 0x1950; t != 0; --t) {
        if (*tile != 5) {
          g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
          if (static_cast<int>((g_mapGenLcgState_006a38e8 >> 12) & 0x7fff) % 5 != 0) {
            *tile = 4;
          }
        }
        tile += 0x24;
      }
    }
    text = static_cast<LPCSTR>(*tuningString);
    if (TuningKeywordMatches(text, "Nepal")) {
      char* tile = mapTileGrid08;
      int t;
      for (t = 0x1950; t != 0; --t) {
        if (*tile != 5) {
          g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
          if (static_cast<int>((g_mapGenLcgState_006a38e8 >> 12) & 0x7fff) % 5 != 0) {
            *tile = 3;
          }
        }
        tile += 0x24;
      }
    }
    text = static_cast<LPCSTR>(*tuningString);
    if (TuningKeywordMatches(text, "Scotland")) {
      char* tile = mapTileGrid08;
      int t;
      for (t = 0x1950; t != 0; --t) {
        if (*tile != 5) {
          g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
          if (static_cast<int>((g_mapGenLcgState_006a38e8 >> 12) & 0x7fff) % 5 != 0) {
            *tile = 2;
          }
        }
        tile += 0x24;
      }
    }
    text = static_cast<LPCSTR>(*tuningString);
    if (TuningKeywordMatches(text, "Eclectia")) {
      char* tile = mapTileGrid08;
      int t;
      for (t = 0x1950; t != 0; --t) {
        int bucket = tile[4] % 7;
        if (bucket > 4) {
          ++bucket;
        }
        if (*tile != 5) {
          g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
          if (static_cast<int>((g_mapGenLcgState_006a38e8 >> 12) & 0x7fff) % 5 != 0) {
            *tile = static_cast<char>(bucket);
            if (bucket == 1) {
              tile[0x13] = 0xf;
            }
          }
        }
        tile += 0x24;
      }
    }

    if (g_pActiveRandomMapSetupPicture006A4268 != 0) {
      g_pActiveRandomMapSetupPicture006A4268->SpinYourGlobe();
    }
    if (ValidateSeedCandidateExistsForEachTerrainClass() != 0) {
      break;
    }
    g_pGlobalMapState->AllocateAndResetTerrainAndCityScoreTables();
    if (g_pActiveRandomMapSetupPicture006A4268 != 0) {
      g_pActiveRandomMapSetupPicture006A4268->SpinYourGlobe();
    }
  }
  if (g_pActiveRandomMapSetupPicture006A4268 != 0) {
    g_pActiveRandomMapSetupPicture006A4268->SpinYourGlobe();
  }
}

// FUNCTION: IMPERIALISM 0x00526710
char TMapMaker::ValidateAllColumnsHaveAssignedRegionClass() {
  bool foundEmptyColumn = false;
  for (int col = 0; col < 0x1b; ++col) {
    if (foundEmptyColumn) {
      break;
    }
    int row = 0;
    while (row < 0xf) {
      if (regionClassGrid10[row][col] != -1) {
        break;
      }
      ++row;
    }
    if (row == 0xf) {
      foundEmptyColumn = true;
    }
  }
  return foundEmptyColumn;
}

// True when every terrain class (0..0x16) that appears on the map has at least one valid
// "seed candidate" tile: a tile of land type {0,1,6,7} one of whose six hex neighbours is a
// city-region tile (tile[0]==5) whose own neighbours all share the seed tile's class. For
// each qualifying class the chosen candidate index is reservoir-sampled with the map-gen LCG.
// Grid is 108 (0x6c) columns x 60 (0x3c) rows, tile stride 0x24, tile[4] = terrain class.
// 0x005267f0.
// FUNCTION: IMPERIALISM 0x00526760
char TMapMaker::ValidateTerrainClassAdjacencyCoverageMask() {
  int classMask = 0;
  int cell;
  // Flat scan over the 15x27 region-class grid, skipping row 0.
  for (cell = 0x1b; cell < 0x17a; ++cell) {
    if (regionClassGrid10[0][cell] != -1) {
      int dir;
      for (dir = 0; dir < 6; ++dir) {
        if (regionClassGrid10[0][GetAdjacentRegionGridCell(cell, dir)] == -1) {
          classMask |= 1 << regionClassGrid10[0][cell];
          break;
        }
      }
    }
  }
  return classMask == 0x7fffff;
}

// FUNCTION: IMPERIALISM 0x005267f0
char TMapMaker::ValidateSeedCandidateExistsForEachTerrainClass() {
  int seedFound[23];
  int seedCandidate[23];
  int i;

  int* pInit = seedFound;
  for (i = 0x17; i != 0; i = i + -1) {
    *pInit = 0;
    pInit = pInit + 1;
  }
  pInit = seedCandidate;
  for (i = 0x17; i != 0; i = i + -1) {
    *pInit = 0;
    pInit = pInit + 1;
  }

  int tileIndex = 0;
  int tileOffset = 0;
  do {
    char* tiles = mapTileGrid08;
    int cls = (int)tiles[tileOffset + 4];
    if ((cls < 0x17) && (-1 < cls)) {
      if (seedFound[cls] == 0) {
        int row = tileIndex / 0x6c;
        int col = tileIndex % 0x6c;
        char wrapFlag = g_pGlobalMapState->hexNeighborWrapHorizontally20;
        bool haveCandidate = false;
        short dir = 0;
        do {
          int idx = (int)dir;
          int nCol;
          if ((row & 1U) == 0) {
            nCol = g_hexColOffsetEvenRow_00697450[idx];
          } else {
            nCol = g_hexColOffsetOddRow_00697480[idx];
          }
          nCol = col + nCol;
          int nRow = row + g_hexRowOffset_00697468[idx];
          short nIdx;
          if (wrapFlag == '\0') {
            if (nCol < 0) {
              nCol = nCol + 0x6c;
            } else if (0x6b < nCol) {
              nCol = nCol + -0x6c;
            }
          LAB_neighbor_index:
            if ((nRow < 0) || (0x3b < nRow))
              goto LAB_neighbor_invalid;
            nIdx = (short)nCol + (short)nRow * 0x6c;
          } else {
            if ((-1 < nCol) && (nCol < 0x6c))
              goto LAB_neighbor_index;
          LAB_neighbor_invalid:
            nIdx = -1;
          }
          if ((nIdx != -1) && (idx = (int)nIdx, tiles[idx * 0x24] == '\x05')) {
            haveCandidate = true;
            int seedRow = idx / 0x6c;
            int seedCol = idx % 0x6c;
            int k = 0;
            do {
              int sCol;
              if ((seedRow & 1U) == 0) {
                sCol = g_hexColOffsetEvenRow_00697450[k];
              } else {
                sCol = g_hexColOffsetOddRow_00697480[k];
              }
              sCol = seedCol + sCol;
              int sRow = seedRow + g_hexRowOffset_00697468[k];
              if (wrapFlag == '\0') {
                if (sCol < 0) {
                  sCol = sCol + 0x6c;
                } else if (0x6b < sCol) {
                  sCol = sCol + -0x6c;
                }
              LAB_seed_neighbor_index:
                if ((sRow < 0) || (0x3b < sRow))
                  goto LAB_seed_neighbor_invalid;
                sCol = sCol + sRow * 0x6c;
              } else {
                if ((-1 < sCol) && (sCol < 0x6c))
                  goto LAB_seed_neighbor_index;
              LAB_seed_neighbor_invalid:
                sCol = -1;
              }
              char nbCls;
              if (((sCol != -1) && (nbCls = tiles[4 + sCol * 0x24], nbCls < '\x17')) &&
                  (nbCls != cls)) {
                haveCandidate = false;
                break;
              }
              k = k + 1;
            } while (k < 6);
            if (haveCandidate) {
              if ((seedCandidate[cls] == 0) ||
                  (g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1,
                   (g_mapGenLcgState_006a38e8 >> 0xc & 0x7fff) % 5 == 3)) {
                seedCandidate[cls] = (int)nIdx;
              }
              break;
            }
          }
          dir = dir + 1;
        } while (dir < 6);
        char typeByte;
        if (haveCandidate &&
            (((typeByte = mapTileGrid08[tileOffset], typeByte == '\0') || (typeByte == '\a')) ||
             ((typeByte == '\x01') || (typeByte == '\x06')))) {
          seedFound[cls] = 1;
        }
      }
    }
    tileOffset = tileOffset + 0x24;
    tileIndex = tileIndex + 1;
    if (0x38f3f < tileOffset) {
      int* p = seedFound;
      for (i = 0; i < 0x17; i = i + 1) {
        if (*p == 0) {
          return '\0';
        }
        p = p + 1;
      }
      return '\x01';
    }
  } while (true);
}

// FUNCTION: IMPERIALISM 0x00526ba0
void TMapMaker::PickRandomRegionGridCell(unsigned int* outColumn, unsigned int* outRow) {
  g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
  *outColumn = (g_mapGenLcgState_006a38e8 >> 12 & 0x7fff) % 27;
  g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
  *outRow = (g_mapGenLcgState_006a38e8 >> 12 & 0x7fff) % 15;
}

// Resets the per-attempt scratch state (region-class grid, union-find group tables),
// then seeds each of the 7 major nations with an 8-cell region at a random unclaimed
// cell, followed by each of the 16 minor nations with a 4-cell region at a random cell
// biased to sit adjacent to an already-claimed region (tried up to 4 times).
// FUNCTION: IMPERIALISM 0x00526c20
void TMapMaker::RunMapGenerationAttempt() {
  memset(regionClassGrid10, -1, sizeof(regionClassGrid10));
  memset(groupMemberLists1a8, -1, sizeof(groupMemberLists1a8));
  cityRegionNextId1fc = -1;
  memset(cityRegionIds200, -1, sizeof(cityRegionIds200));
  lastMinorSeedCandidate29c = -1;

  signed char* regionClassGridFlat = reinterpret_cast<signed char*>(regionClassGrid10);

  for (int classIndex = 0; classIndex < 7; ++classIndex) {
    int assigned;
    do {
      cityRegionIds200[classIndex] = -1;
      for (int cell = 0; cell < 15 * 27; ++cell) {
        if (regionClassGridFlat[cell] == classIndex) {
          regionClassGridFlat[cell] = -1;
        }
      }
      for (int group = 0; group < 7; ++group) {
        for (int member = 0; member < 3; ++member) {
          if (groupMemberLists1a8[group][member] == classIndex) {
            groupMemberLists1a8[group][member] = -1;
          }
        }
      }

      int cellIndex;
      do {
        g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
        cellIndex = static_cast<int>((g_mapGenLcgState_006a38e8 >> 0xc & 0x7fff) % 0x195);
      } while (regionClassGridFlat[cellIndex] != -1);
      assigned = AssignRegionClassToCellAndNeighbors(cellIndex, 8, classIndex, 5);
    } while (assigned != 8);
  }

  for (int minorClassIndex = 7; minorClassIndex < 0x17; ++minorClassIndex) {
    int parity = (minorClassIndex - 7) >> 2;
    int assigned;
    do {
      cityRegionIds200[minorClassIndex] = -1;
      for (int minorCell = 0; minorCell < 15 * 27; ++minorCell) {
        if (regionClassGridFlat[minorCell] == minorClassIndex) {
          regionClassGridFlat[minorCell] = -1;
        }
      }
      for (int minorGroup = 0; minorGroup < 7; ++minorGroup) {
        for (int minorMember = 0; minorMember < 3; ++minorMember) {
          if (groupMemberLists1a8[minorGroup][minorMember] == minorClassIndex) {
            groupMemberLists1a8[minorGroup][minorMember] = -1;
          }
        }
      }

      int cellIndex = 0;
      bool hasAssignedNeighbor = false;
      for (int attempt = 0; attempt < 4 && !hasAssignedNeighbor; ++attempt) {
        unsigned int rngTemp = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
        g_mapGenLcgState_006a38e8 = rngTemp * 0x15a4e35 + 1;
        int roll1 = static_cast<int>((rngTemp >> 0xc & 0x7fff) % 0x1b);
        int roll2 = static_cast<int>((g_mapGenLcgState_006a38e8 >> 0xc & 0x7fff) % 0xf);
        cellIndex =
            roll1 / 2 + ((parity & 1) ? 0xd : 0) + (roll2 / 2 + ((parity < 2) ? 0 : 7)) * 0x1b;
        for (int dir = 0; dir < 6; ++dir) {
          int neighborCell = GetAdjacentRegionGridCell(cellIndex, dir);
          if (neighborCell != -1 && regionClassGridFlat[neighborCell] != -1) {
            hasAssignedNeighbor = true;
          }
        }
      }
      assigned = AssignRegionClassToCellAndNeighbors(cellIndex, 4, minorClassIndex, 5);
    } while (assigned != 4);
  }
}

// Recursively claims `cellIndex` for `classIndex`, then spreads to its hex neighbors by
// weighted-random selection (each neighbor's weight boosted +10 per further neighbor
// already owned by `classIndex`), retrying until `retryBudget` assignments succeed or no
// neighbor remains eligible. Returns the number of successful assignments.
// FUNCTION: IMPERIALISM 0x00527040
int TMapMaker::AssignRegionClassToCellAndNeighbors(int cellIndex, int mode, int classIndex,
                                                   int retryBudget) {
  if (mode == 0 || cellIndex / 27 <= 0 || cellIndex / 27 >= 14 ||
      regionClassGrid10[cellIndex / 27][cellIndex % 27] != -1) {
    return 0;
  }
  if (classIndex < 7) {
    if (!TryMergeRegionGroupWithNeighborsRestrictedToMajors(cellIndex, classIndex)) {
      return 0;
    }
  } else if (!TryMergeRegionGroupWithNeighbors(cellIndex, classIndex)) {
    return 0;
  }

  int remaining = mode - 1;
  regionClassGrid10[cellIndex / 27][cellIndex % 27] = static_cast<signed char>(classIndex);

  bool excluded[6];
  int availableCount = 6;
  for (int dir = 0; dir < 6; ++dir) {
    int neighborCell = GetAdjacentRegionGridCell(cellIndex, dir);
    if (neighborCell == -1 || dir == retryBudget) {
      excluded[dir] = true;
      --availableCount;
    } else {
      excluded[dir] = false;
    }
  }

  int lastCell = cellIndex;
  while (remaining != 0 && availableCount != 0) {
    int weights[6];
    int totalWeight = 0;
    for (int dir = 0; dir < 6; ++dir) {
      if (excluded[dir]) {
        weights[dir] = 0;
      } else {
        int neighborCell = GetAdjacentRegionGridCell(lastCell, dir);
        int weight = (dir != retryBudget) ? 10 : 2;
        for (int dir2 = 0; dir2 < 6; ++dir2) {
          int neighborOfNeighbor = GetAdjacentRegionGridCell(neighborCell, dir2);
          if (neighborOfNeighbor != -1 &&
              regionClassGrid10[neighborOfNeighbor / 27][neighborOfNeighbor % 27] == classIndex) {
            weight += 10;
          }
        }
        weights[dir] = weight;
      }
      totalWeight += weights[dir];
    }

    g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
    int roll = static_cast<int>((g_mapGenLcgState_006a38e8 >> 0xc & 0x7fff) % totalWeight);
    int selectedDir = 0;
    if (weights[0] < roll) {
      int cumulative = weights[0];
      do {
        int nextWeight = weights[selectedDir + 1];
        weights[selectedDir + 1] = nextWeight + cumulative;
        cumulative = nextWeight + cumulative;
        ++selectedDir;
      } while (cumulative < roll);
    }

    int neighborCell = GetAdjacentRegionGridCell(lastCell, selectedDir);
    int assigned =
        AssignRegionClassToCellAndNeighbors(neighborCell, remaining, classIndex, selectedDir);
    remaining -= assigned;
    excluded[selectedDir] = true;
    --availableCount;
    lastCell = neighborCell;
  }
  return mode - remaining;
}

// Union-find merge of classIndex's region group against each coarse-grid hex
// neighbor's assigned class: if a neighbor has a different already-assigned class,
// join the two classes into one group (allocating a new group id, adopting the
// neighbor's group, or absorbing the neighbor into this class's group -- in any
// direction, tracking up to 3 member classes per group in groupMemberLists1a8).
// Returns false the moment two neighbors' classes already belong to two DIFFERENT
// established groups (a genuine conflict) or a group's member list is full.
// FUNCTION: IMPERIALISM 0x00527300
char TMapMaker::TryMergeRegionGroupWithNeighborsRestrictedToMajors(int cellIndex, int classIndex) {
  for (int dir = 0; dir < 6; ++dir) {
    int neighborCell = GetAdjacentRegionGridCell(cellIndex, dir);
    int neighborClass =
        (neighborCell != -1) ? regionClassGrid10[neighborCell / 27][neighborCell % 27] : -1;
    if (neighborClass == -1 || neighborClass == classIndex) {
      continue;
    }
    int myGroupId = cityRegionIds200[classIndex];
    int neighborGroupId = cityRegionIds200[neighborClass];
    if (myGroupId == -1) {
      if (neighborGroupId == -1) {
        int newGroupId = ++cityRegionNextId1fc;
        groupMemberLists1a8[newGroupId][0] = classIndex;
        groupMemberLists1a8[newGroupId][1] = neighborClass;
        cityRegionIds200[classIndex] = newGroupId;
        cityRegionIds200[neighborClass] = newGroupId;
      } else {
        int slot = 0;
        while (slot < 3 && groupMemberLists1a8[neighborGroupId][slot] != -1) {
          ++slot;
        }
        if (slot == 3) {
          return 0;
        }
        groupMemberLists1a8[neighborGroupId][slot] = classIndex;
        cityRegionIds200[classIndex] = neighborGroupId;
      }
    } else if (neighborGroupId == -1) {
      int slot = 0;
      while (slot < 3 && groupMemberLists1a8[myGroupId][slot] != -1) {
        ++slot;
      }
      if (slot == 3) {
        return 0;
      }
      groupMemberLists1a8[myGroupId][slot] = neighborClass;
      cityRegionIds200[neighborClass] = myGroupId;
    } else if (myGroupId != neighborGroupId) {
      return 0;
    }
  }
  return 1;
}

// Same union-find neighbor-merge as TryMergeRegionGroupWithNeighborsRestrictedToMajors
// above, but without the groupMemberLists1a8 bookkeeping: a class with an existing
// group can only merge by adopting a neighbor's group (or forming a new one when
// neither has one yet) -- if this class already has a group and the neighbor doesn't,
// that's treated as a conflict rather than expanding this class's group.
// FUNCTION: IMPERIALISM 0x005274d0
char TMapMaker::TryMergeRegionGroupWithNeighbors(int cellIndex, int classIndex) {
  for (int dir = 0; dir < 6; ++dir) {
    int neighborCell = GetAdjacentRegionGridCell(cellIndex, dir);
    int neighborClass =
        (neighborCell != -1) ? regionClassGrid10[neighborCell / 27][neighborCell % 27] : -1;
    if (neighborClass == -1 || neighborClass == classIndex) {
      continue;
    }
    int myGroupId = cityRegionIds200[classIndex];
    int neighborGroupId = cityRegionIds200[neighborClass];
    if (myGroupId == -1) {
      if (neighborGroupId == -1) {
        int newGroupId = ++cityRegionNextId1fc;
        cityRegionIds200[classIndex] = newGroupId;
        cityRegionIds200[neighborClass] = newGroupId;
      } else {
        cityRegionIds200[classIndex] = neighborGroupId;
      }
    } else if (myGroupId != neighborGroupId) {
      return 0;
    }
  }
  return 1;
}

// FUNCTION: IMPERIALISM 0x005275a0
void TMapMaker::MapGenPassSlot0E() {
  int cityRecordIndex = 0;
  int coarseIndex;
  for (coarseIndex = 0; coarseIndex < 0x195; ++coarseIndex) {
    signed char regionClass = regionClassGrid10[coarseIndex / 0x1b][coarseIndex % 0x1b];
    signed char ownerNation;
    signed char terrainType;
    short linkedCityRecord;

    if (regionClass == -1 || regionClass == 100) {
      ownerNation = -1;
      terrainType = 5;
      linkedCityRecord = -1;
    } else {
      ownerNation = regionClass;
      terrainType = 0;
      linkedCityRecord = static_cast<short>(cityRecordIndex);
      ++cityRecordIndex;
      cityScoreTable0c[linkedCityRecord].ownerNationCode00 = ownerNation;
      cityScoreTable0c[linkedCityRecord].regionClassA3 =
          static_cast<signed char>(cityRegionIds200[static_cast<short>(ownerNation)]);
    }

    int coarseRow = coarseIndex / 0x1b;
    int coarseColumn = coarseIndex % 0x1b;
    TTerrainStateRecordView* tile = reinterpret_cast<TTerrainStateRecordView*>(mapTileGrid08) +
                                    (coarseRow * 4 * 108 + coarseColumn * 4);
    if ((coarseRow & 1) != 0) {
      tile -= 2;
    }

    if ((coarseRow & 1) != 0 && coarseColumn == 0) {
      tile += 2;
      int block;
      for (block = 0; block < 4; ++block) {
        int column;
        for (column = 0; column < 2; ++column) {
          tile->ownerNationTag04 = ownerNation;
          tile->terrainType00 = terrainType;
          tile->cityRecordIndex = linkedCityRecord;
          ++tile;
        }
        tile += 104;
        for (column = 0; column < 2; ++column) {
          tile->ownerNationTag04 = ownerNation;
          tile->terrainType00 = terrainType;
          tile->cityRecordIndex = linkedCityRecord;
          ++tile;
        }
      }
    } else {
      int row;
      for (row = 0; row < 4; ++row) {
        int column;
        for (column = 0; column < 4; ++column) {
          tile->ownerNationTag04 = ownerNation;
          tile->terrainType00 = terrainType;
          tile->cityRecordIndex = linkedCityRecord;
          ++tile;
        }
        tile += 104;
      }
    }
  }
}

// Lays mountain-range-shaped features (ForwardParam) up to g_mapGenMountainQuota_
// 006a3470 tiles, then spreads hills (terrain 2) around each laid tile with a 40%
// per-neighbor chance (up to g_mapGenHillsQuota_006a38c0 tiles, falling back to
// direct random placement once the spread pass can't find more room), places
// city-marker features (PlaceCityMarkerAndSpreadNeighbors) up to
// g_mapGenForestQuota_006a38f8 times, and finally fills the remaining swamp quota
// (g_mapGenSwampQuota_006a38e0) with random tiles (terrain 7) or -- once that quota
// is exhausted -- random-walks mountain-range extensions (terrain 4, via slot 0x58)
// from tiles adjacent to exactly one already-placed marker tile.
// FUNCTION: IMPERIALISM 0x00527730
void TMapMaker::MapGenPassSlot0F() {
  int forestQuota = g_mapGenForestQuota_006a38f8;
  int swampQuota = g_mapGenSwampQuota_006a38e0;
  int hillsQuota = g_mapGenHillsQuota_006a38c0;

  for (int remaining = g_mapGenMountainQuota_006a3470; remaining > 0;) {
    g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
    unsigned int seedHigh = g_mapGenLcgState_006a38e8 >> 0xc;
    int tileIndex;
    do {
      g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
      tileIndex = static_cast<int>((g_mapGenLcgState_006a38e8 >> 0xc & 0x7fff) % 0x1950);
    } while (mapTileGrid08[tileIndex * 0x24] != 0);
    g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
    int retryBudget = static_cast<int>((seedHigh & 0x7fff) % 0xc) + 3;
    int featureType = static_cast<int>((g_mapGenLcgState_006a38e8 >> 0xc & 0x7fff) % 6);
    remaining -= ForwardParam(tileIndex, retryBudget, featureType);
  }

  for (int hillsSrcTile = 0; hillsSrcTile < 0x1950; ++hillsSrcTile) {
    if (mapTileGrid08[hillsSrcTile * 0x24] != 3) {
      continue;
    }
    for (int hillsDir = 0; hillsDir < 6; ++hillsDir) {
      int neighborTile = ComputeHexAdjacentFullGridTileIndex(hillsSrcTile, hillsDir);
      if (neighborTile != -1 && mapTileGrid08[neighborTile * 0x24] == 0) {
        g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
        if (static_cast<int>((g_mapGenLcgState_006a38e8 >> 0xc & 0x7fff) % 100) < 0x28) {
          mapTileGrid08[neighborTile * 0x24] = 2;
          --hillsQuota;
        }
      }
    }
  }

  while (hillsQuota > 0) {
    g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
    int hillsFallbackTile = static_cast<int>((g_mapGenLcgState_006a38e8 >> 0xc & 0x7fff) % 0x1950);
    if (mapTileGrid08[hillsFallbackTile * 0x24] == 0) {
      mapTileGrid08[hillsFallbackTile * 0x24] = 2;
      --hillsQuota;
    }
  }

  CreateDeserts();

  bool urgentFlag = false;
  while (forestQuota > 0) {
    g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
    int forestTile = static_cast<int>((g_mapGenLcgState_006a38e8 >> 0xc & 0x7fff) % 0x1950);
    forestQuota -= PlaceCityMarkerAndSpreadNeighbors(forestTile, 7, static_cast<char>(urgentFlag));
    if (forestQuota < g_mapGenForestQuota_006a38f8 * 2 / 3) {
      urgentFlag = true;
    }
  }

  for (;;) {
    if (swampQuota < 1) {
      for (int fillTile = 0; fillTile < 0x1950; ++fillTile) {
        if (mapTileGrid08[fillTile * 0x24] == 0) {
          g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
          if (static_cast<int>((g_mapGenLcgState_006a38e8 >> 0xc & 0x7fff) % 100) < 0x2d) {
            mapTileGrid08[fillTile * 0x24] = 7;
          }
        }
      }
      CreateRivers();
      return;
    }

    int swampTile;
    do {
      g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
      swampTile = static_cast<int>((g_mapGenLcgState_006a38e8 >> 0xc & 0x7fff) % 0x1950);
    } while (mapTileGrid08[swampTile * 0x24] != 0);

    bool allNeighborsClear = true;
    for (int swampDir = 0; swampDir < 6; ++swampDir) {
      int neighborTile = ComputeHexAdjacentFullGridTileIndex(swampTile, swampDir);
      if (neighborTile != -1 && mapTileGrid08[neighborTile * 0x24] == 6) {
        allNeighborsClear = false;
      }
    }
    if (allNeighborsClear) {
      --swampQuota;
      mapTileGrid08[swampTile * 0x24] = 4;
    }
  }
}

// FUNCTION: IMPERIALISM 0x00527d00
void TMapMaker::CreateRivers() {
  int riversRemaining = g_mapGenRiverCount_006a38e4;
  int attemptsRemaining = 5000000;
  while (riversRemaining != 0) {
    int tileIndex;
    do {
      g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
      tileIndex = static_cast<int>((g_mapGenLcgState_006a38e8 >> 12 & 0x7fff) % 0x1950);
      --attemptsRemaining;
      if (attemptsRemaining == 0) {
        return;
      }
    } while (mapTileGrid08[tileIndex * 0x24] != 3);

    g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
    int firstDirection = static_cast<int>((g_mapGenLcgState_006a38e8 >> 12 & 0x7fff) % 5);
    int direction = firstDirection;
    int neighbor;
    do {
      direction = direction == 5 ? 0 : direction + 1;
      neighbor = ComputeHexAdjacentFullGridTileIndex(tileIndex, direction);
    } while (mapTileGrid08[neighbor * 0x24] == 3 && direction != firstDirection);

    if (direction != firstDirection && GrowRiver(tileIndex, direction, 6, 0, 1)) {
      --riversRemaining;
    }
  }
}

// FUNCTION: IMPERIALISM 0x00527ed0
char TMapMaker::GrowRiver(long tileIndex, long incomingDirection, long outgoingDirection,
                          long depth, unsigned char startedOnHills) {
  char* tile = mapTileGrid08 + tileIndex * 0x24;
  char terrainType = *tile;
  char beganOnHills = terrainType == 2;
  if (tile[2] != 0 || (terrainType == 3 && depth != 0) ||
      (terrainType == 2 && startedOnHills == 0)) {
    return 0;
  }
  if (terrainType == 5) {
    if (depth < 5) {
      return 0;
    }
    tile[2] = static_cast<char>(outgoingDirection + 0x10);
    return 1;
  }

  long oppositeDirection = outgoingDirection;
  long nextDirection = incomingDirection;
  if (outgoingDirection < 6) {
    oppositeDirection = outgoingDirection + 3;
    if (oppositeDirection > 5) {
      oppositeDirection -= 6;
    }
    do {
      g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
      nextDirection =
          incomingDirection - static_cast<long>((g_mapGenLcgState_006a38e8 >> 12 & 0x7fff) % 3) + 1;
      if (nextDirection > 5) {
        nextDirection -= 6;
      } else if (nextDirection < 0) {
        nextDirection += 6;
      }
    } while (g_riverConnectionTypeByDirectionPair_00697568[nextDirection][oppositeDirection] == 0);
  }

  int neighbor = ComputeHexAdjacentFullGridTileIndex(static_cast<int>(tileIndex),
                                                     static_cast<int>(nextDirection));
  if (!GrowRiver(neighbor, incomingDirection, nextDirection, depth + 1, beganOnHills)) {
    return 0;
  }
  if (depth == 0) {
    tile[2] = static_cast<char>(nextDirection + 10);
  } else {
    tile[2] = static_cast<char>(
        g_riverConnectionTypeByDirectionPair_00697568[nextDirection][oppositeDirection]);
  }
  return 1;
}

// Same hex-neighbor math as TMapMgr::ComputeHexNeighborTileIndices, but over
// TMapMaker's own full-resolution generation grid (mapTileGrid08, 108x60, stride
// 0x24) rather than the coarse 15x27 region grid.
static __inline int ComputeHexAdjacentFullGridTileIndex(int tileIndex, int direction) {
  int parity = tileIndex / 0x6c;
  int colOffset = (parity & 1) == 0 ? g_hexColOffsetEvenRow_00697450[direction]
                                    : g_hexColOffsetOddRow_00697480[direction];
  int col = tileIndex % 0x6c + colOffset;
  int row = parity + g_hexRowOffset_00697468[direction];
  if (g_pGlobalMapState->hexNeighborWrapHorizontally20 == 0) {
    if (col < 0) {
      col += 0x6c;
    } else if (col > 0x6b) {
      col -= 0x6c;
    }
    if (row < 0 || row > 0x3b) {
      return -1;
    }
    return col + row * 0x6c;
  }
  if (col >= 0 && col < 0x6c) {
    return col + row * 0x6c;
  }
  return -1;
}

// Recursively claims `tileIndex` (marking it 1, plus a variant byte at +0x13 chosen by
// `markerVariant`), refuses if any hex neighbor is already a marker (byte 6), then
// spreads to hex neighbors with a 46% chance each until `retryBudget` spreads succeed.
// Returns the number of successful spreads.
// FUNCTION: IMPERIALISM 0x00528140
int TMapMaker::PlaceCityMarkerAndSpreadNeighbors(int tileIndex, int retryBudget,
                                                 char markerVariant) {
  if (mapTileGrid08[tileIndex * 0x24] != 0) {
    return 0;
  }
  for (int dir = 0; dir < 6; ++dir) {
    int neighborTile = ComputeHexAdjacentFullGridTileIndex(tileIndex, dir);
    if (neighborTile != -1 && mapTileGrid08[neighborTile * 0x24] == 6) {
      return 0;
    }
  }

  mapTileGrid08[tileIndex * 0x24] = 1;
  mapTileGrid08[tileIndex * 0x24 + 0x13] = (markerVariant == 0) ? 0xd : 0xf;

  int remaining = retryBudget - 1;
  for (int spreadDir = 0; spreadDir < 6; ++spreadDir) {
    int neighborTile = ComputeHexAdjacentFullGridTileIndex(tileIndex, spreadDir);
    g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
    if (static_cast<int>((g_mapGenLcgState_006a38e8 >> 0xc & 0x7fff) % 100) < 0x46 &&
        remaining != 0) {
      remaining -= PlaceCityMarkerAndSpreadNeighbors(neighborTile, 1, markerVariant);
    }
  }
  return retryBudget - remaining;
}

// Recursively lays a linear terrain feature (river/road-shaped) across the
// full-resolution generation grid: claims `tileIndex` (marking it 3), refuses if any
// hex neighbor is water (terrain type 5), then randomly perturbs `featureType`
// (0..5, the hex direction to continue in -- more volatile when featureType is 1 or
// 4) and recurses into that neighbor with `retryBudget` decremented. Returns the
// number of tiles successfully placed.
// FUNCTION: IMPERIALISM 0x005283c0
int TMapMaker::ForwardParam(int tileIndex, int retryBudget, int featureType) {
  if (tileIndex < 0 || tileIndex > 0x1950) {
    return 0;
  }
  if (mapTileGrid08[tileIndex * 0x24] != 0) {
    return 0;
  }
  for (int dir = 0; dir < 6; ++dir) {
    int neighborTile = ComputeHexAdjacentFullGridTileIndex(tileIndex, dir);
    if (neighborTile != -1 && mapTileGrid08[neighborTile * 0x24] == 5) {
      return 0;
    }
  }

  mapTileGrid08[tileIndex * 0x24] = 3;

  int nextFeatureType = featureType;
  if (featureType == 1 || featureType == 4) {
    g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
    int roll = static_cast<int>((g_mapGenLcgState_006a38e8 >> 0xc & 0x7fff) % 100);
    if (roll > 0x27) {
      if (roll < 0x46) {
        nextFeatureType = (featureType == 0) ? 5 : featureType - 1;
      } else if (featureType == 5) {
        nextFeatureType = 0;
      } else {
        nextFeatureType = featureType + 1;
      }
    }
  } else {
    g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
    int roll = static_cast<int>((g_mapGenLcgState_006a38e8 >> 0xc & 0x7fff) % 100);
    if (roll > 0x3b) {
      if (roll < 0x50) {
        nextFeatureType = (featureType == 0) ? 5 : featureType - 1;
      } else if (featureType == 5) {
        nextFeatureType = 0;
      } else {
        nextFeatureType = featureType + 1;
      }
    }
  }

  int nextTile = ComputeHexAdjacentFullGridTileIndex(tileIndex, nextFeatureType);
  int placed = 1;
  if (retryBudget != 1 && nextTile != -1) {
    // Note: the original recurses with the un-adjusted featureType, not
    // nextFeatureType -- the random perturbation above only picks which neighbor
    // to step into this call, not the direction future steps inherit.
    placed += ForwardParam(nextTile, retryBudget - 1, featureType);
  }
  return placed;
}

// FUNCTION: IMPERIALISM 0x00528670
void TMapMaker::CreateDeserts() {
  int remaining = 250;
  int chanceStep = 5;
  int upperRow = 0;
  int lowerRow = 59;
  int chance = 120;

  while (chance > 90 && remaining > 0) {
    remaining -= TundraBand(upperRow, chance);
    remaining -= TundraBand(lowerRow, chance);
    ++upperRow;
    --lowerRow;
    chance -= 5;
  }

  if (remaining > 0) {
    int row = 25;
    while (row > 4 && remaining > 0) {
      int neighborChance = (abs(chanceStep - 7) + 12) * 5;
      remaining -= DesertBand(row, neighborChance);
      remaining -= DesertBand(chanceStep + 30, neighborChance);
      chanceStep += 2;
      row -= 2;
    }
  }
}

// FUNCTION: IMPERIALISM 0x00528780
int TMapMaker::TundraBand(int row, int percentChance) {
  char* tile = mapTileGrid08 + row * 0xf30;
  int column = 0;
  while (*tile != 5 && column < 0x6c) {
    tile += 0x24;
    ++column;
  }
  if (column == 0x6c) {
    return 0;
  }

  int marked = 0;
  int ringState = 0;
  int remaining = 0x6b;
  do {
    ++column;
    tile += 0x24;
    if (column == 0x6c) {
      column = 0;
    }
    if (ringState == 0 && *tile != 5) {
      ringState = 1;
    }
    if (ringState == 1) {
      if (*tile == 0) {
        g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
        if (static_cast<int>((g_mapGenLcgState_006a38e8 >> 12 & 0x7fff) % 100) < percentChance) {
          *tile = 6;
          tile[0x13] = 12;
          ++marked;
        }
      } else if (*tile == 5) {
        ringState = 0;
      }
    } else if (ringState == 2 && *tile == 5) {
      ringState = 0;
    }
    --remaining;
  } while (remaining != 0);
  return marked;
}

// FUNCTION: IMPERIALISM 0x005288a0
int TMapMaker::DesertBand(int row, int percentChance) {
  char* tile = mapTileGrid08 + row * 0xf30;
  int column = 0;
  while (*tile != 5 && column < 0x6c) {
    tile += 0x24;
    ++column;
  }
  if (column == 0x6c) {
    return 0;
  }

  int marked = 0;
  int ringState = 0;
  int remaining = 0x6b;
  do {
    ++column;
    tile += 0x24;
    if (column == 0x6c) {
      column = 0;
    }
    if (ringState == 0 && *tile != 5) {
      ringState = 1;
    }
    if (ringState == 1) {
      if (*tile == 0) {
        g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
        if (static_cast<int>((g_mapGenLcgState_006a38e8 >> 12 & 0x7fff) % 100) < percentChance) {
          int tileIndex = column + row * 0x6c;
          *tile = 6;
          tile[0x13] = 11;
          ++marked;

          int neighbor = ComputeHexAdjacentFullGridTileIndex(tileIndex, 5);
          char* neighborTile = mapTileGrid08 + neighbor * 0x24;
          if (*neighborTile == 0) {
            g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
            if (static_cast<int>((g_mapGenLcgState_006a38e8 >> 12 & 0x7fff) % 100) <
                percentChance) {
              *neighborTile = 6;
              tile[0x13] = 11;
              ++marked;
            }
          }

          neighbor = ComputeHexAdjacentFullGridTileIndex(tileIndex, 3);
          neighborTile = mapTileGrid08 + neighbor * 0x24;
          if (*neighborTile == 0) {
            g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
            if (static_cast<int>((g_mapGenLcgState_006a38e8 >> 12 & 0x7fff) % 100) <
                percentChance) {
              *neighborTile = 6;
              tile[0x13] = 11;
              ++marked;
            }
          }
        }
      } else if (*tile == 5) {
        ringState = 0;
      }
    } else if (ringState == 2 && *tile == 5) {
      ringState = 0;
    }
    --remaining;
  } while (remaining != 0);
  return marked;
}

// FUNCTION: IMPERIALISM 0x00528ce0
int TMapMaker::GetAdjacentRegionGridCell(int cell, int direction) {
  int column = cell % 0x1b;
  int row = cell / 0x1b;
  if ((row & 1) == 0) {
    column += g_coarseHexColOffsetEvenRow_00697498[direction];
  } else {
    column += g_coarseHexColOffsetOddRow_006974c8[direction];
  }
  row += g_coarseHexRowOffset_006974b0[direction];

  if (column < 0) {
    column += 0x1b;
  } else if (column >= 0x1b) {
    column -= 0x1b;
  }

  if (row < 0 || row > 0x3c) {
    return -1;
  }
  int neighbor = column + row * 0x1b;
  if (neighbor < 0 || neighbor >= 0x195) {
    return -1;
  }
  return neighbor;
}

// Two-pass ownership smoothing over the full-resolution generation grid (rows 1..58
// only, skipping the border rows). Pass 1: for each tile with 0, 1 (50% chance), or 2
// (75% chance) same-owner hex neighbors, if a differing-owner neighbor exists, copy
// that neighbor's whole 0x24-byte record onto this tile. Pass 2: for each tile with NO
// same-owner neighbor at all, copy a uniformly-random neighbor's record onto it.
// FUNCTION: IMPERIALISM 0x00528e50
void TMapMaker::SmoothCityRegionOwnershipByNeighborSampling() {
  for (int tileIndex = 0x6c; tileIndex < 0x1950 - 0x6c; ++tileIndex) {
    int sameOwnerCount = 0;
    int differingNeighborDir = -1;
    for (int dir = 0; dir < 6; ++dir) {
      int neighborTile = ComputeHexAdjacentFullGridTileIndex(tileIndex, dir);
      char neighborOwner = (neighborTile != -1) ? mapTileGrid08[neighborTile * 0x24 + 4] : -1;
      if (neighborOwner == mapTileGrid08[tileIndex * 0x24 + 4]) {
        ++sameOwnerCount;
      } else if (neighborOwner != -1) {
        differingNeighborDir = dir;
      }
    }

    bool erode = false;
    if (sameOwnerCount == 0) {
      erode = true;
    } else if (sameOwnerCount == 1) {
      g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
      erode = (g_mapGenLcgState_006a38e8 >> 0xc & 1) != 0;
    } else if (sameOwnerCount == 2) {
      g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
      erode = (g_mapGenLcgState_006a38e8 >> 0xc & 4) == 0;
    }
    if (erode && differingNeighborDir != -1) {
      int neighborTile = ComputeHexAdjacentFullGridTileIndex(tileIndex, differingNeighborDir);
      memcpy(&mapTileGrid08[tileIndex * 0x24], &mapTileGrid08[neighborTile * 0x24], 0x24);
    }
  }

  for (int isolatedTile = 0x6c; isolatedTile < 0x1950 - 0x6c; ++isolatedTile) {
    bool hasSameOwnerNeighbor = false;
    for (int isoDir = 0; isoDir < 6; ++isoDir) {
      int neighborTile = ComputeHexAdjacentFullGridTileIndex(isolatedTile, isoDir);
      char neighborOwner = (neighborTile != -1) ? mapTileGrid08[neighborTile * 0x24 + 4] : -1;
      if (neighborOwner == mapTileGrid08[isolatedTile * 0x24 + 4]) {
        hasSameOwnerNeighbor = true;
      }
    }
    if (!hasSameOwnerNeighbor) {
      g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
      int randomDir = static_cast<int>((g_mapGenLcgState_006a38e8 >> 0xc & 0x7fff) % 6);
      int neighborTile = ComputeHexAdjacentFullGridTileIndex(isolatedTile, randomDir);
      memcpy(&mapTileGrid08[isolatedTile * 0x24], &mapTileGrid08[neighborTile * 0x24], 0x24);
    }
  }
}

// FUNCTION: IMPERIALISM 0x005292f0
void TMapMaker::MapGenPassSlot1E() {
  int coarseIndex;
  for (coarseIndex = 0; coarseIndex < 0x17a; ++coarseIndex) {
    unsigned short baseClass =
        static_cast<unsigned short>(static_cast<signed char>(regionClassGrid10[0][coarseIndex]));

    GetAdjacentRegionGridCell(coarseIndex, 0);
    GetAdjacentRegionGridCell(coarseIndex, 5);

    int neighbor = GetAdjacentRegionGridCell(coarseIndex, 1);
    unsigned short class1 =
        static_cast<unsigned short>(static_cast<signed char>(regionClassGrid10[0][neighbor]));
    neighbor = GetAdjacentRegionGridCell(coarseIndex, 2);
    unsigned short class2 =
        static_cast<unsigned short>(static_cast<signed char>(regionClassGrid10[0][neighbor]));
    neighbor = GetAdjacentRegionGridCell(coarseIndex, 3);
    unsigned short class3 =
        static_cast<unsigned short>(static_cast<signed char>(regionClassGrid10[0][neighbor]));
    GetAdjacentRegionGridCell(coarseIndex, 4);

    RandomizeRegionTemplateBanksForMismatchedNeighborClasses(coarseIndex, baseClass, class1, class3,
                                                             class2);
  }

  if (g_pActiveRandomMapSetupPicture006A4268 != 0) {
    g_pActiveRandomMapSetupPicture006A4268->SpinYourGlobe();
  }
  SmoothCityRegionOwnershipByNeighborSampling();
}

// FUNCTION: IMPERIALISM 0x005296a0
void TMapMaker::CopyRegionTemplateBankWithRandomVariant(int coarseIndex, int arg2, int arg3,
                                                        int arg4, int arg5) {
  (void)arg3;
  char* cell = reinterpret_cast<char*>(GetFineGridCellBasePointerFromCoarseIndex(coarseIndex));

  if (static_cast<short>(arg4) == static_cast<short>(arg2)) {
    g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
    if ((g_mapGenLcgState_006a38e8 >> 0xc & 1) != 0) {
      memcpy(cell - 0xee8, cell, 0x24);
      g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
      if ((g_mapGenLcgState_006a38e8 >> 0xc & 3) == 0) {
        memcpy(cell - 0x1e18, cell, 0x24);
      }
    } else {
      memcpy(cell + 0x48, cell - 0xf0c, 0x24);
    }
  } else {
    memcpy(cell - 0xf30, cell, 0x24);
    g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
    if ((g_mapGenLcgState_006a38e8 >> 0xc & 1) != 0) {
      memcpy(cell - 0xf54, cell, 0x24);
      g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
      if ((g_mapGenLcgState_006a38e8 >> 0xc & 1) != 0) {
        memcpy(cell - 0x1e60, cell, 0x24);
      }
    }
  }

  if (static_cast<short>(arg5) != static_cast<short>(arg2)) {
    memcpy(cell + 0x6c, cell - 0xee8, 0x24);
  }
}

// FUNCTION: IMPERIALISM 0x005297e0
void TMapMaker::CopyRegionTemplateBankToNeighborCell(int coarseIndex, int arg2, int arg3, int arg4,
                                                     int arg5) {
  (void)arg3;
  (void)arg5;
  int neighbor = GetAdjacentRegionGridCell(coarseIndex, 2);
  char* cell = reinterpret_cast<char*>(GetFineGridCellBasePointerFromCoarseIndex(neighbor));
  char* source = cell - 0xf30;

  if (static_cast<short>(arg4) == static_cast<short>(arg2)) {
    memcpy(cell, source, 0x24);
  } else if (static_cast<short>(arg2) != 1) {
    memcpy(cell - 0x24, source, 0x24);
    g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
    if ((g_mapGenLcgState_006a38e8 >> 0xc & 0x7fff) == 0) {
      memcpy(cell - 0x48, source, 0x24);
    }
  }
}

// FUNCTION: IMPERIALISM 0x005298a0
int TMapMaker::GetFineGridCellBasePointerFromCoarseIndex(int coarseIndex) {
  int cell =
      (static_cast<short>(coarseIndex % 0x1b) + static_cast<short>(coarseIndex / 0x1b) * 0x6c) *
          0x90 +
      reinterpret_cast<int>(mapTileGrid08);
  if ((coarseIndex / 0x1b & 1U) != 0) {
    cell = cell + -0x48;
  }
  return cell;
}

// FUNCTION: IMPERIALISM 0x00529f60
void TMapMaker::MapGenFinalizePassSlot19(int mode) {
  if (static_cast<unsigned char>(mode) != 0) {
    int i;
    cityRegionCount2a4 = 0;
    for (i = 0; i < 0x100; ++i) {
      g_cityRegionIdRemapTable_006a3498[i] = -1;
    }

    int tileOffset;
    for (tileOffset = 0; tileOffset < 0x38f40; tileOffset += 0x24) {
      char* tile = mapTileGrid08 + tileOffset;
      int oldRegionId = -1;
      if (tileOffset >= 0 && tile[0] == 5) {
        oldRegionId = static_cast<signed char>(tile[4]) - 0x17;
      }
      if (oldRegionId > -1) {
        if (g_cityRegionIdRemapTable_006a3498[oldRegionId] == -1) {
          g_cityRegionIdRemapTable_006a3498[oldRegionId] = cityRegionCount2a4++;
        }
        tile[4] = static_cast<char>(g_cityRegionIdRemapTable_006a3498[oldRegionId] + 0x17);
      }
    }
  } else {
    GenerateCityRegionIdsBySeedAndNeighborPropagation();
  }

  if (g_pActiveRandomMapSetupPicture006A4268 != 0) {
    g_pActiveRandomMapSetupPicture006A4268->SpinYourGlobe();
  }
  BuildCityRegionBorderOverlaySegments();
  if (g_pActiveRandomMapSetupPicture006A4268 != 0) {
    g_pActiveRandomMapSetupPicture006A4268->SpinYourGlobe();
  }
  BuildOverlaySpanRecordsFromQuadBorderLinks();
  if (g_pActiveRandomMapSetupPicture006A4268 != 0) {
    g_pActiveRandomMapSetupPicture006A4268->SpinYourGlobe();
  }
  MergeSmallCityRegionsAndCompactIds();
  if (g_pActiveRandomMapSetupPicture006A4268 != 0) {
    g_pActiveRandomMapSetupPicture006A4268->SpinYourGlobe();
  }
}

// FUNCTION: IMPERIALISM 0x0052a670
int TMapMaker::GetCityRegionIdAtTileIndex(int tileIndex) {
  if (tileIndex >= 0) {
    char* tile = mapTileGrid08 + tileIndex * 0x24;
    if (*tile == '\x05') {
      return tile[4] - 0x17;
    }
  }
  return -1;
}

// FUNCTION: IMPERIALISM 0x0052e840
char TMapMaker::ErrorCheck() {
  EraseZones(0);
  char failed = 0;
  signed char* cell = &regionClassGrid10[0][0];
  int remaining = 0x195;
  do {
    if (*cell == -1) {
      *cell = 100;
      failed = 1;
    } else if (*cell == -9) {
      *cell = -1;
    }
    ++cell;
    --remaining;
  } while (remaining != 0);
  return failed;
}

// FUNCTION: IMPERIALISM 0x0052e890
void TMapMaker::EraseZones(long coarseIndex) {
  regionClassGrid10[0][coarseIndex] = -9;
  int direction;
  for (direction = 0; direction < 6; ++direction) {
    int neighbor = GetAdjacentRegionGridCell(coarseIndex, direction);
    if (neighbor != -1 && regionClassGrid10[0][neighbor] == -1) {
      EraseZones(neighbor);
    }
  }
}

// FUNCTION: IMPERIALISM 0x0052e900
void TMapMaker::TargetValidationSucceeded() {}
