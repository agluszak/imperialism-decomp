#include "game/TMapMaker.h"
#include "game/CString.h"
#include "game/TObject.h"
#include "game/TControl.h"
#include "game/TMapMgr.h"
#include "game/TSetupRandomMapPicture.h"
#include "game/global_data_tables.h"

// SYNTHETIC: IMPERIALISM 0x00525950
// TMapMaker::GetRuntimeClass
IMPLEMENT_DYNAMIC(TMapMaker, TObject)

// FUNCTION: IMPERIALISM 0x00525970
TMapMaker::TMapMaker() : TObject() {}

// SYNTHETIC: IMPERIALISM 0x00525990
// TMapMaker::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x005259c0
TMapMaker::~TMapMaker() {}

undefined4 GetCurrentLocalEpochSecondsWithTimezoneCache(void);

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
void TMapMaker::GenerateMapFromTuningStringAndApplyScenarioOverrides(
    char* tileGrid, TGlobalMapCityScoreRecord* cityTable, CString* tuningString) {
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
    // Genuine __cdecl free function declared (void); the guardrail-sanctioned
    // arg-adjust cast pushes the ignored argument the original passes.
    seed = reinterpret_cast<unsigned int(__cdecl*)(int)>(
        GetCurrentLocalEpochSecondsWithTimezoneCache)(seed);
  }
  seed = seed * 0x15a4e35 + 1;
  g_mapGenLcgState_006a38e8 = seed;
  g_zoneStatusCodePrngSeed_006a5aec = (static_cast<unsigned int>(seed) >> 12) & 0x7fff;
  if (g_zoneStatusCodePrngSeed_006a5aec == 0) {
    g_zoneStatusCodePrngSeed_006a5aec = reinterpret_cast<unsigned int(__cdecl*)(int)>(
        GetCurrentLocalEpochSecondsWithTimezoneCache)(0);
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
      retryAttempt = HasMapGenerationFailed();
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
char TMapMaker::GetBoolSlot28() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00526c20
void TMapMaker::RunMapGenerationAttempt() {}

// FUNCTION: IMPERIALISM 0x00527040
TEventHandler* TMapMaker::QueryStepValue() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00527300
void TMapMaker::DispatchQueuedUiCommandAndRelease(void* payload) {}

// FUNCTION: IMPERIALISM 0x005274d0
void TMapMaker::DispatchEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  (void)commandId;
  (void)sourceHandler;
  (void)event;
}

// FUNCTION: IMPERIALISM 0x005275a0
void TMapMaker::MapGenPassSlot0E() {}

// FUNCTION: IMPERIALISM 0x00527730
void TMapMaker::MapGenPassSlot0F() {}

// FUNCTION: IMPERIALISM 0x00527d00
char TMapMaker::vmethod_0023() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00527ed0
char TMapMaker::GetDeactivateVetoCode() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00528140
class TView* TMapMaker::OwnerPanel() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005283c0
void TMapMaker::ForwardParam(int param) {}

// FUNCTION: IMPERIALISM 0x00528670
char TMapMaker::DoIdle(int action) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00528780
int TMapMaker::GetCityDialogValueDword10() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005288a0
void TMapMaker::SetCityDialogValueDword10(int value) {}

// FUNCTION: IMPERIALISM 0x00528ce0
int TMapMaker::GetAdjacentRegionGridCell(int cell, int direction) {
  (void)cell;
  (void)direction;
  return 0;
}

// FUNCTION: IMPERIALISM 0x00528e50
void TMapMaker::vmethod_0017(int param) {}

// FUNCTION: IMPERIALISM 0x005292f0
void TMapMaker::MapGenPassSlot1E() {}

// FUNCTION: IMPERIALISM 0x005296a0
char TMapMaker::ActivateCityProductionViewIfAllowed() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005297e0
char TMapMaker::TryDeactivateActiveView() {
  return 0;
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
  (void)mode;
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
char TMapMaker::HasMapGenerationFailed() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x0052e890
void TMapMaker::DispatchUiCommand19ToParent() {}

// FUNCTION: IMPERIALISM 0x0052e900
void TMapMaker::HandleCityProductionNoOp() {}
