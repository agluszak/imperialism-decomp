#include <stdlib.h>
#include "decomp_types.h"
#include "game/map/map_overlay_geometry.h"
#include <math.h>
#include "game/mfc.h"
#include "game/gfx/ui_invalidation_guard.h"
#include <stdio.h>
#include <string.h>
#include "game/strategic_terrain.h"
#include "game/ui_tags_common.h"
#include <time.h>
#include "game/navy/TOcean.h"
#include "game/map/TZone.h"

#include "game/map_generation/TMapMaker.h"
#include "game/core/runtime_prng_seed.h"
#include "game/core/CString.h"
#include "game/app/TObject.h"
#include "game/ui_core/TControl.h"
#include "game/map/TMapMgr.h"
#include "game/ui_screens/TSetupRandomMapPicture.h"
#include "game/globals/global_types.h"
#include "game/globals/map_globals.h"
#include "game/globals/map_ui_globals.h"
#include "game/globals/shared_globals.h"
#include "game/map/sea_geometry.h"

#ifdef IMPERIALISM_RUNTIME_TESTS
#include "RuntimeCoarseMapOracle.h"
#endif

IMPLEMENT_DYNCREATE(TMapMaker, TControl)

// FUNCTION: IMPERIALISM 0x00525970
TMapMaker::TMapMaker() : TObject() {}

// FUNCTION: IMPERIALISM 0x005259c0
TMapMaker::~TMapMaker() {}

bool TuningKeywordMatches(const char* keyword, const char* text) {
  while (*keyword != 0) {
    if (*keyword++ != *text++) {
      return false;
    }
  }
  return *text == 0 || *text == ' ';
}

// FUNCTION: IMPERIALISM 0x00525a30
void TMapMaker::GenerateNewMap(char* tileGrid, Province* cityTable, CString* tuningString) {
  mapTileGrid = tileGrid;
  cityScoreTable = cityTable;
  g_mapGenDesertQuota = 200;
  g_mapGenMountainQuota = 150;
  g_mapGenHillsQuota = 250;
  g_mapGenForestQuota = 250;
  g_mapGenSwampQuota = 150;
  g_mapGenRiverCount = 10;
  g_regionSeedGridRows = 14;
  g_regionSeedGridCols = 8;

  // Parse the tuning string: option letters only count after the "@^>" marker.
  int budget = 1000;
  const char* p = static_cast<LPCSTR>(*tuningString);
  bool armed = false;
  char c = *p;
  while (c != 0) {
    if (!armed) {
      if (c == '@') {
        c = *++p;
        if (c == '^') {
          c = *++p;
          armed = (c == '>');
        }
      }
    }
    if (armed) {
      switch (c) {
      case 'D':
        g_mapGenDesertQuota = 300;
        break;
      case 'd':
        g_mapGenDesertQuota = 100;
        break;
      case 'M':
        g_mapGenMountainQuota = 300;
        break;
      case 'm':
        g_mapGenMountainQuota = 100;
        break;
      case 'H':
        g_mapGenHillsQuota = 500;
        break;
      case 'h':
        g_mapGenHillsQuota = 100;
        break;
      case 'F':
        g_mapGenForestQuota = 500;
        break;
      case 'f':
        g_mapGenForestQuota = 100;
        break;
      case 'S':
        g_mapGenSwampQuota = 300;
        break;
      case 's':
        g_mapGenSwampQuota = 100;
        break;
      case 'P':
        budget = 750;
        break;
      case 'p':
        budget = 1500;
        break;
      case 'R':
        g_mapGenRiverCount = 20;
        break;
      case 'r':
        g_mapGenRiverCount = 5;
        break;
      case 'c':
        g_regionSeedGridRows = 18;
        g_regionSeedGridCols = 10;
        break;
      case 'C':
        g_regionSeedGridRows = 10;
        g_regionSeedGridCols = 6;
        break;
      default:
        break;
      }
    }
    c = *++p;
  }

  // Rescale the five class quotas to the chosen budget.
  int quotaSum = g_mapGenSwampQuota + g_mapGenHillsQuota + g_mapGenForestQuota +
                 g_mapGenDesertQuota + g_mapGenMountainQuota;
  if (quotaSum != budget) {
    g_mapGenDesertQuota = budget * g_mapGenDesertQuota / quotaSum;
    g_mapGenMountainQuota = budget * g_mapGenMountainQuota / quotaSum;
    g_mapGenHillsQuota = budget * g_mapGenHillsQuota / quotaSum;
    g_mapGenForestQuota = budget * g_mapGenForestQuota / quotaSum;
    g_mapGenSwampQuota = budget * g_mapGenSwampQuota / quotaSum;
  }

  const char* h = static_cast<LPCSTR>(*tuningString);
  int seed = kControlTagNada;
  for (char hc = *h; hc != 0; hc = *++h) {
    seed = (seed >> 16) + seed * 2 + hc;
  }
  g_mapGenLcgState = seed;
  if (seed == 0) {
    // CRT time(); seed is 0 on this path, so the original's pushed arg is NULL.
    seed = ClockDerivedPrngSeed();
  }
  seed = seed * 0x15a4e35 + 1;
  g_mapGenLcgState = seed;
  g_zoneStatusCodePrngSeed = (static_cast<unsigned int>(seed) >> 12) & 0x7fff;
  if (g_zoneStatusCodePrngSeed == 0) {
    g_zoneStatusCodePrngSeed = ClockDerivedPrngSeed();
  }

#ifdef IMPERIALISM_RUNTIME_TESTS
  RuntimeCoarseMapOracleReset(g_mapGenLcgState);
  RuntimeTerrainMapOracleReset(
      g_mapGenLcgState, static_cast<int>(g_pGlobalMapState->hexNeighborWrapHorizontally),
      g_mapGenDesertQuota, g_mapGenMountainQuota, g_mapGenHillsQuota, g_mapGenForestQuota,
      g_mapGenSwampQuota, g_mapGenRiverCount, g_regionSeedGridRows, g_regionSeedGridCols);
#endif

  for (;;) {
#ifdef IMPERIALISM_RUNTIME_TESTS
    RuntimeCoarseMapOracleBeginGenerationAttempt(g_mapGenLcgState);
#endif
    char retryAttempt;
    do {
      if (g_pActiveRandomMapSetupPicture != 0) {
        g_pActiveRandomMapSetupPicture->SpinYourGlobe();
      }
#ifdef IMPERIALISM_RUNTIME_TESTS
      RuntimeCoarseMapOracleBeginAttempt();
#endif
      RunMapGenerationAttempt();
#ifdef IMPERIALISM_RUNTIME_TESTS
      RuntimeCoarseMapOracleCaptureSeededAttempt(this, g_mapGenLcgState);
      int errorCheckFailed = ErrorCheck();
      int hasContinuousOceanColumn = -1;
      int frontierMaskComplete = -1;
      retryAttempt = static_cast<char>(errorCheckFailed);
      if (retryAttempt != 0) {
        retryAttempt = 1;
      } else {
        hasContinuousOceanColumn = ValidateAllColumnsHaveAssignedRegionClass();
        if (hasContinuousOceanColumn == 0) {
          retryAttempt = 1;
        } else {
          frontierMaskComplete = ValidateTerrainClassAdjacencyCoverageMask();
          retryAttempt = (frontierMaskComplete == 0);
        }
      }
      RuntimeCoarseMapOracleFinishAttempt(this, errorCheckFailed, hasContinuousOceanColumn,
                                          frontierMaskComplete, retryAttempt == 0,
                                          g_mapGenLcgState);
#else
      retryAttempt = ErrorCheck();
      if (retryAttempt != 0) {
        retryAttempt = 1;
      } else if (!ValidateAllColumnsHaveAssignedRegionClass()) {
        retryAttempt = 1;
      } else {
        retryAttempt = (!ValidateTerrainClassAdjacencyCoverageMask());
      }
#endif
    } while (retryAttempt != 0);

    // Backfill the unassigned city-region id slots.
    if (g_pActiveRandomMapSetupPicture != 0) {
      g_pActiveRandomMapSetupPicture->SpinYourGlobe();
    }
    for (int i = 0; i < 0x17; ++i) {
      if (cityRegionIds[i] == -1) {
        cityRegionIds[i] = ++cityRegionNextId;
      }
    }

    if (g_pActiveRandomMapSetupPicture != 0) {
      g_pActiveRandomMapSetupPicture->SpinYourGlobe();
    }
    ExpandRegionGridIntoTilesAndAllocateCityRecords();
#ifdef IMPERIALISM_RUNTIME_TESTS
    RuntimeCoarseMapOracleCaptureExpansion(this, g_mapGenLcgState);
    RuntimeTerrainMapOracleBeginAttempt(this, g_mapGenLcgState);
#endif
    if (g_pActiveRandomMapSetupPicture != 0) {
      g_pActiveRandomMapSetupPicture->SpinYourGlobe();
    }
    if (g_pActiveRandomMapSetupPicture != 0) {
      g_pActiveRandomMapSetupPicture->SpinYourGlobe();
    }
    RandomizeRegionTemplatesAndSmoothOwnership();
#ifdef IMPERIALISM_RUNTIME_TESTS
    RuntimeTerrainMapOracleCaptureStage("after_templates", this, g_mapGenLcgState);
#endif
    if (g_pActiveRandomMapSetupPicture != 0) {
      g_pActiveRandomMapSetupPicture->SpinYourGlobe();
    }
    PlaceTerrainFeatureQuotas();
#ifdef IMPERIALISM_RUNTIME_TESTS
    RuntimeTerrainMapOracleCaptureStage("after_features", this, g_mapGenLcgState);
#endif
    if (g_pActiveRandomMapSetupPicture != 0) {
      g_pActiveRandomMapSetupPicture->SpinYourGlobe();
    }
    RotateMapColumnsByPeakWaterTileDensity();
#ifdef IMPERIALISM_RUNTIME_TESTS
    RuntimeTerrainMapOracleCaptureStage("after_rotation", this, g_mapGenLcgState);
#endif
    if (g_pActiveRandomMapSetupPicture != 0) {
      g_pActiveRandomMapSetupPicture->SpinYourGlobe();
    }
    AssignOrCompactCityRegionIdsAndRebuildBorders(0);

    const char* text = static_cast<LPCSTR>(*tuningString);
    if (TuningKeywordMatches("Dune", text)) {
      for (int t = 0; t < kStrategicTileCount; ++t) {
        char* tile = mapTileGrid + t * 0x24;
        if (*tile != kStrategicTerrainWater) {
          g_mapGenLcgState = g_mapGenLcgState * 0x15a4e35 + 1;
          if (static_cast<int>((g_mapGenLcgState >> 12) & 0x7fff) % 10 != 0) {
            *tile = kStrategicTerrainDesert;
          }
        }
      }
    }
    text = static_cast<LPCSTR>(*tuningString);
    if (TuningKeywordMatches("Congo", text)) {
      for (int t = 0; t < kStrategicTileCount; ++t) {
        char* tile = mapTileGrid + t * 0x24;
        if (*tile != kStrategicTerrainWater) {
          g_mapGenLcgState = g_mapGenLcgState * 0x15a4e35 + 1;
          if (static_cast<int>((g_mapGenLcgState >> 12) & 0x7fff) % 10 != 0) {
            *tile = kStrategicTerrainForest;
            tile[0x13] = 0xd;
          }
        }
      }
    }
    text = static_cast<LPCSTR>(*tuningString);
    if (TuningKeywordMatches("Mirkwood", text)) {
      for (int t = 0; t < kStrategicTileCount; ++t) {
        char* tile = mapTileGrid + t * 0x24;
        if (*tile != kStrategicTerrainWater) {
          g_mapGenLcgState = g_mapGenLcgState * 0x15a4e35 + 1;
          if (static_cast<int>((g_mapGenLcgState >> 12) & 0x7fff) % 10 != 0) {
            *tile = kStrategicTerrainForest;
            g_mapGenLcgState = g_mapGenLcgState * 0x15a4e35 + 1;
            tile[0x13] = static_cast<char>(((~(g_mapGenLcgState >> 12) & 1) << 1) | 0xd);
          }
        }
      }
    }
    text = static_cast<LPCSTR>(*tuningString);
    if (TuningKeywordMatches("Yucatan", text) ||
        TuningKeywordMatches("Siberia", static_cast<LPCSTR>(*tuningString))) {
      for (int t = 0; t < kStrategicTileCount; ++t) {
        char* tile = mapTileGrid + t * 0x24;
        if (*tile != kStrategicTerrainWater) {
          g_mapGenLcgState = g_mapGenLcgState * 0x15a4e35 + 1;
          if (static_cast<int>((g_mapGenLcgState >> 12) & 0x7fff) % 10 != 0) {
            *tile = kStrategicTerrainForest;
            tile[0x13] = 0xf;
          }
        }
      }
    }
    text = static_cast<LPCSTR>(*tuningString);
    if (TuningKeywordMatches("Antarctica", text)) {
      for (int t = 0; t < kStrategicTileCount; ++t) {
        char* tile = mapTileGrid + t * 0x24;
        if (*tile != kStrategicTerrainWater) {
          g_mapGenLcgState = g_mapGenLcgState * 0x15a4e35 + 1;
          if (static_cast<int>((g_mapGenLcgState >> 12) & 0x7fff) % 10 != 0) {
            *tile = kStrategicTerrainDesert;
            tile[0x13] = 0xc;
          }
        }
      }
    }
    text = static_cast<LPCSTR>(*tuningString);
    if (TuningKeywordMatches("Kansas", text)) {
      for (int t = 0; t < kStrategicTileCount; ++t) {
        char* tile = mapTileGrid + t * 0x24;
        if (*tile != kStrategicTerrainWater) {
          g_mapGenLcgState = g_mapGenLcgState * 0x15a4e35 + 1;
          if (static_cast<int>((g_mapGenLcgState >> 12) & 0x7fff) % 10 != 0) {
            *tile = kStrategicTerrainPlains;
          }
        }
      }
    }
    text = static_cast<LPCSTR>(*tuningString);
    if (TuningKeywordMatches("Eden", text)) {
      for (int t = 0; t < kStrategicTileCount; ++t) {
        char* tile = mapTileGrid + t * 0x24;
        if (*tile != kStrategicTerrainWater) {
          g_mapGenLcgState = g_mapGenLcgState * 0x15a4e35 + 1;
          if (static_cast<int>((g_mapGenLcgState >> 12) & 0x7fff) % 10 != 0) {
            *tile = kStrategicTerrainFarmland;
          }
        }
      }
    }
    text = static_cast<LPCSTR>(*tuningString);
    if (TuningKeywordMatches("Everglades", text)) {
      for (int t = 0; t < kStrategicTileCount; ++t) {
        char* tile = mapTileGrid + t * 0x24;
        if (*tile != kStrategicTerrainWater) {
          g_mapGenLcgState = g_mapGenLcgState * 0x15a4e35 + 1;
          if (static_cast<int>((g_mapGenLcgState >> 12) & 0x7fff) % 5 != 0) {
            *tile = kStrategicTerrainSwamp;
          }
        }
      }
    }
    text = static_cast<LPCSTR>(*tuningString);
    if (TuningKeywordMatches("Nepal", text)) {
      for (int t = 0; t < kStrategicTileCount; ++t) {
        char* tile = mapTileGrid + t * 0x24;
        if (*tile != kStrategicTerrainWater) {
          g_mapGenLcgState = g_mapGenLcgState * 0x15a4e35 + 1;
          if (static_cast<int>((g_mapGenLcgState >> 12) & 0x7fff) % 5 != 0) {
            *tile = kStrategicTerrainMountain;
          }
        }
      }
    }
    text = static_cast<LPCSTR>(*tuningString);
    if (TuningKeywordMatches("Scotland", text)) {
      for (int t = 0; t < kStrategicTileCount; ++t) {
        char* tile = mapTileGrid + t * 0x24;
        if (*tile != kStrategicTerrainWater) {
          g_mapGenLcgState = g_mapGenLcgState * 0x15a4e35 + 1;
          if (static_cast<int>((g_mapGenLcgState >> 12) & 0x7fff) % 5 != 0) {
            *tile = kStrategicTerrainHills;
          }
        }
      }
    }
    text = static_cast<LPCSTR>(*tuningString);
    if (TuningKeywordMatches("Eclectia", text)) {
      for (int t = 0; t < kStrategicTileCount; ++t) {
        char* tile = mapTileGrid + t * 0x24;
        int bucket = tile[4] % 7;
        if (bucket > 4) {
          ++bucket;
        }
        if (*tile != kStrategicTerrainWater) {
          g_mapGenLcgState = g_mapGenLcgState * 0x15a4e35 + 1;
          if (static_cast<int>((g_mapGenLcgState >> 12) & 0x7fff) % 5 != 0) {
            *tile = static_cast<char>(bucket);
            if (bucket == kStrategicTerrainForest) {
              tile[0x13] = 0xf;
            }
          }
        }
      }
    }

    if (g_pActiveRandomMapSetupPicture != 0) {
      g_pActiveRandomMapSetupPicture->SpinYourGlobe();
    }
#ifdef IMPERIALISM_RUNTIME_TESTS
    RuntimeTerrainMapOracleCaptureKeywordStage(this, g_mapGenLcgState);
    int seedCandidatesAccepted = ValidateSeedCandidateExistsForEachTerrainClass();
    RuntimeTerrainMapOracleFinishAttempt(seedCandidatesAccepted, g_mapGenLcgState);
    if (seedCandidatesAccepted != 0) {
#else
    if (ValidateSeedCandidateExistsForEachTerrainClass() != 0) {
#endif
      break;
    }
    g_pGlobalMapState->AllocateAndResetTerrainAndCityScoreTables();
    if (g_pActiveRandomMapSetupPicture != 0) {
      g_pActiveRandomMapSetupPicture->SpinYourGlobe();
    }
  }
  if (g_pActiveRandomMapSetupPicture != 0) {
    g_pActiveRandomMapSetupPicture->SpinYourGlobe();
  }
}

// FUNCTION: IMPERIALISM 0x00526620
bool TMapMaker::CheckProvs() {
  if (ErrorCheck()) {
    return true;
  }

  bool foundEmptyColumn = false;
  int column = 0;
  signed char* columnBase = &regionClassGrid[0][0];
  do {
    if (foundEmptyColumn) {
      break;
    }
    int row = 0;
    signed char* cell = columnBase;
    do {
      if (*cell != -1) {
        break;
      }
      ++row;
      cell += 0x1b;
    } while (row < 0xf);
    if (row == 0xf) {
      foundEmptyColumn = true;
    }
    ++column;
    ++columnBase;
  } while (column < 0x1b);

  if (!foundEmptyColumn) {
    return true;
  }

  int classMask = 0;
  int cellIndex = 0x1b;
  do {
    signed char regionClass = regionClassGrid[0][cellIndex];
    if (regionClass != -1) {
      int direction = 0;
      do {
        int neighbor = GetAdjacentRegionGridCell(cellIndex, direction);
        if (regionClassGrid[0][neighbor] == -1) {
          classMask |= 1 << regionClass;
          break;
        }
        ++direction;
      } while (direction < 6);
    }
    ++cellIndex;
  } while (cellIndex < 0x17a);

  return classMask != 0x7fffff;
}

// FUNCTION: IMPERIALISM 0x00526710
bool TMapMaker::ValidateAllColumnsHaveAssignedRegionClass() {
  bool foundEmptyColumn = false;
  for (int col = 0; col < 0x1b; ++col) {
    if (foundEmptyColumn) {
      break;
    }
    int row = 0;
    while (row < 0xf) {
      if (regionClassGrid[row][col] != -1) {
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

// FUNCTION: IMPERIALISM 0x00526760
bool TMapMaker::ValidateTerrainClassAdjacencyCoverageMask() {
  int classMask = 0;
  int cell;
  // Flat scan over the 15x27 region-class grid, skipping row 0.
  for (cell = 0x1b; cell < 0x17a; ++cell) {
    if (regionClassGrid[0][cell] != -1) {
      int dir;
      for (dir = 0; dir < 6; ++dir) {
        if (regionClassGrid[0][GetAdjacentRegionGridCell(cell, dir)] == -1) {
          classMask |= 1 << regionClassGrid[0][cell];
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
#ifdef IMPERIALISM_RUNTIME_TESTS
  RuntimeTerrainMapOracleResetSeedCandidates();
#endif

  int* pInit = seedFound;
  for (i = 0x17; i != 0; i = i - 1) {
    *pInit = 0;
    ++pInit;
  }
  pInit = seedCandidate;
  for (i = 0x17; i != 0; i = i - 1) {
    *pInit = 0;
    ++pInit;
  }

  int tileIndex = 0;
  int tileOffset = 0;
  do {
    char* tiles = mapTileGrid;
    int cls = (int)tiles[tileOffset + 4];
    if ((cls < 0x17) && (-1 < cls)) {
      if (seedFound[cls] == 0) {
        int row = tileIndex / kStrategicMapColumns;
        int col = tileIndex % kStrategicMapColumns;
        char wrapFlag = g_pGlobalMapState->hexNeighborWrapHorizontally;
        bool haveCandidate = false;
        short dir = 0;
        do {
          int idx = (int)dir;
          int nCol;
          if ((row & 1U) == 0) {
            nCol = g_hexColOffsetEvenRow[idx];
          } else {
            nCol = g_hexColOffsetOddRow[idx];
          }
          nCol = col + nCol;
          int nRow = row + g_hexRowOffset[idx];
          if (wrapFlag == '\0') {
            if (nCol < 0) {
              nCol += kStrategicMapColumns;
            } else if (0x6b < nCol) {
              nCol -= kStrategicMapColumns;
            }
          }
          short nIdx = -1;
          if ((wrapFlag == '\0' || (nCol >= 0 && nCol < kStrategicMapColumns)) && nRow >= 0 &&
              nRow <= 0x3b) {
            nIdx = (short)nCol + (short)nRow * kStrategicMapColumns;
          }
          if ((nIdx != -1) && (idx = (int)nIdx, tiles[idx * 0x24] == kStrategicTerrainWater)) {
            haveCandidate = true;
            int seedRow = idx / kStrategicMapColumns;
            int seedCol = idx % kStrategicMapColumns;
            int k = 0;
            do {
              int sCol;
              if ((seedRow & 1U) == 0) {
                sCol = g_hexColOffsetEvenRow[k];
              } else {
                sCol = g_hexColOffsetOddRow[k];
              }
              sCol = seedCol + sCol;
              int sRow = seedRow + g_hexRowOffset[k];
              if (wrapFlag == '\0') {
                if (sCol < 0) {
                  sCol += kStrategicMapColumns;
                } else if (0x6b < sCol) {
                  sCol -= kStrategicMapColumns;
                }
              }
              if ((wrapFlag == '\0' || (sCol >= 0 && sCol < kStrategicMapColumns)) && sRow >= 0 &&
                  sRow <= 0x3b) {
                sCol = sCol + sRow * kStrategicMapColumns;
              } else {
                sCol = -1;
              }
              char nbCls;
              if (((sCol != -1) && (nbCls = tiles[4 + sCol * 0x24], nbCls < '\x17')) &&
                  (nbCls != cls)) {
                haveCandidate = false;
                break;
              }
              ++k;
            } while (k < 6);
            if (haveCandidate) {
              if ((seedCandidate[cls] == 0) || (g_mapGenLcgState = g_mapGenLcgState * 0x15a4e35 + 1,
                                                (g_mapGenLcgState >> 0xc & 0x7fff) % 5 == 3)) {
                seedCandidate[cls] = (int)nIdx;
#ifdef IMPERIALISM_RUNTIME_TESTS
                RuntimeTerrainMapOracleRecordSeedCandidate(cls, static_cast<int>(nIdx));
#endif
              }
              break;
            }
          }
          ++dir;
        } while (dir < 6);
        char typeByte;
        if (haveCandidate &&
            (((typeByte = mapTileGrid[tileOffset], typeByte == kStrategicTerrainPlains) ||
              (typeByte == kStrategicTerrainFarmland)) ||
             ((typeByte == kStrategicTerrainForest) || (typeByte == kStrategicTerrainDesert)))) {
          seedFound[cls] = 1;
        }
      }
    }
    tileOffset += 0x24;
    ++tileIndex;
    if (0x38f3f < tileOffset) {
      int* p = seedFound;
      for (i = 0; i < 0x17; i = i + 1) {
        if (*p == 0) {
          return '\0';
        }
        ++p;
      }
      return '\x01';
    }
  } while (true);
}

// FUNCTION: IMPERIALISM 0x00526ba0
void TMapMaker::PickRandomRegionGridCell(unsigned int* outColumn, unsigned int* outRow) {
  g_mapGenLcgState = g_mapGenLcgState * 0x15a4e35 + 1;
  *outColumn = (g_mapGenLcgState >> 12 & 0x7fff) % 27;
  g_mapGenLcgState = g_mapGenLcgState * 0x15a4e35 + 1;
  *outRow = (g_mapGenLcgState >> 12 & 0x7fff) % 15;
}

// FUNCTION: IMPERIALISM 0x00526c20
void TMapMaker::RunMapGenerationAttempt() {
  memset(regionClassGrid, -1, sizeof(regionClassGrid));
  memset(groupMemberLists, -1, sizeof(groupMemberLists));
  cityRegionNextId = -1;
  memset(cityRegionIds, -1, sizeof(cityRegionIds));
  lastMinorSeedCandidate = -1;

  signed char* regionClassGridFlat = &regionClassGrid[0][0];

  for (int classIndex = 0; classIndex < 7; ++classIndex) {
    if (g_pActiveRandomMapSetupPicture != 0) {
      g_pActiveRandomMapSetupPicture->SpinYourGlobe();
    }
    int assigned;
    do {
      cityRegionIds[classIndex] = -1;
      for (int cell = 0; cell < 15 * 27; ++cell) {
        if (regionClassGridFlat[cell] == classIndex) {
          regionClassGridFlat[cell] = -1;
        }
      }
      for (int group = 0; group < 7; ++group) {
        for (int member = 0; member < 3; ++member) {
          if (groupMemberLists[group][member] == classIndex) {
            groupMemberLists[group][member] = -1;
          }
        }
      }

      int cellIndex;
      do {
        g_mapGenLcgState = g_mapGenLcgState * 0x15a4e35 + 1;
#ifdef IMPERIALISM_RUNTIME_TESTS
        RuntimeCoarseMapOracleRecordDraw();
#endif
        cellIndex = static_cast<int>((g_mapGenLcgState >> 0xc & 0x7fff) % 0x195);
      } while (regionClassGridFlat[cellIndex] != -1);
      assigned = SelectGPZone(cellIndex, 8, classIndex, 5);
    } while (assigned != 8);
  }

  for (int minorClassIndex = 7; minorClassIndex < 0x17; ++minorClassIndex) {
    if (g_pActiveRandomMapSetupPicture != 0) {
      g_pActiveRandomMapSetupPicture->SpinYourGlobe();
    }
    int parity = (minorClassIndex - 7) >> 2;
    int assigned;
    do {
      cityRegionIds[minorClassIndex] = -1;
      for (int minorCell = 0; minorCell < 15 * 27; ++minorCell) {
        if (regionClassGridFlat[minorCell] == minorClassIndex) {
          regionClassGridFlat[minorCell] = -1;
        }
      }
      for (int minorGroup = 0; minorGroup < 7; ++minorGroup) {
        for (int minorMember = 0; minorMember < 3; ++minorMember) {
          if (groupMemberLists[minorGroup][minorMember] == minorClassIndex) {
            groupMemberLists[minorGroup][minorMember] = -1;
          }
        }
      }

      int cellIndex = 0;
      bool hasAssignedNeighbor = false;
      for (int attempt = 0; attempt < 4 && !hasAssignedNeighbor; ++attempt) {
        unsigned int rngTemp = g_mapGenLcgState * 0x15a4e35 + 1;
        g_mapGenLcgState = rngTemp * 0x15a4e35 + 1;
#ifdef IMPERIALISM_RUNTIME_TESTS
        RuntimeCoarseMapOracleRecordDraw();
        RuntimeCoarseMapOracleRecordDraw();
#endif
        int roll1 = static_cast<int>((rngTemp >> 0xc & 0x7fff) % 0x1b);
        int roll2 = static_cast<int>((g_mapGenLcgState >> 0xc & 0x7fff) % 0xf);
        cellIndex =
            roll1 / 2 + ((parity & 1) ? 0xd : 0) + (roll2 / 2 + ((parity < 2) ? 0 : 7)) * 0x1b;
        for (int dir = 0; dir < 6; ++dir) {
          int neighborCell = GetAdjacentRegionGridCell(cellIndex, dir);
          if (neighborCell != -1 && regionClassGridFlat[neighborCell] != -1) {
            hasAssignedNeighbor = true;
          }
        }
      }
      assigned = SelectGPZone(cellIndex, 4, minorClassIndex, 5);
    } while (assigned != 4);
  }
}

// FUNCTION: IMPERIALISM 0x00527040
int TMapMaker::SelectGPZone(int cellIndex, int mode, int classIndex, int retryBudget) {
  if (mode == 0 || cellIndex / 27 <= 0 || cellIndex / 27 >= 14 ||
      regionClassGrid[cellIndex / 27][cellIndex % 27] != -1) {
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
  regionClassGrid[cellIndex / 27][cellIndex % 27] = static_cast<signed char>(classIndex);

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
              regionClassGrid[neighborOfNeighbor / 27][neighborOfNeighbor % 27] == classIndex) {
            weight += 10;
          }
        }
        weights[dir] = weight;
      }
      totalWeight += weights[dir];
    }

    g_mapGenLcgState = g_mapGenLcgState * 0x15a4e35 + 1;
#ifdef IMPERIALISM_RUNTIME_TESTS
    RuntimeCoarseMapOracleRecordDraw();
#endif
    int roll = static_cast<int>((g_mapGenLcgState >> 0xc & 0x7fff) % totalWeight);
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
    int assigned = SelectGPZone(neighborCell, remaining, classIndex, selectedDir);
    remaining -= assigned;
    excluded[selectedDir] = true;
    --availableCount;
    lastCell = neighborCell;
  }
  return mode - remaining;
}

// FUNCTION: IMPERIALISM 0x005272c0
void TMapMaker::TranslateZones() {
  int* zone = cityRegionIds;
  for (int remaining = 0; remaining < 0x17; ++remaining) {
    if (*zone == -1) {
      *zone = ++cityRegionNextId;
    }
    ++zone;
  }
}

// FUNCTION: IMPERIALISM 0x00527300
bool TMapMaker::TryMergeRegionGroupWithNeighborsRestrictedToMajors(int cellIndex, int classIndex) {
  for (int dir = 0; dir < 6; ++dir) {
    int neighborCell = GetAdjacentRegionGridCell(cellIndex, dir);
    int neighborClass =
        (neighborCell != -1) ? regionClassGrid[neighborCell / 27][neighborCell % 27] : -1;
    if (neighborClass == -1 || neighborClass == classIndex) {
      continue;
    }
    int myGroupId = cityRegionIds[classIndex];
    int neighborGroupId = cityRegionIds[neighborClass];
    if (myGroupId == -1) {
      if (neighborGroupId == -1) {
        int newGroupId = ++cityRegionNextId;
        groupMemberLists[newGroupId][0] = classIndex;
        groupMemberLists[newGroupId][1] = neighborClass;
        cityRegionIds[classIndex] = newGroupId;
        cityRegionIds[neighborClass] = newGroupId;
      } else {
        int slot = 0;
        while (slot < 3 && groupMemberLists[neighborGroupId][slot] != -1) {
          ++slot;
        }
        if (slot == 3) {
          return false;
        }
        groupMemberLists[neighborGroupId][slot] = classIndex;
        cityRegionIds[classIndex] = neighborGroupId;
      }
    } else if (neighborGroupId == -1) {
      int slot = 0;
      while (slot < 3 && groupMemberLists[myGroupId][slot] != -1) {
        ++slot;
      }
      if (slot == 3) {
        return false;
      }
      groupMemberLists[myGroupId][slot] = neighborClass;
      cityRegionIds[neighborClass] = myGroupId;
    } else if (myGroupId != neighborGroupId) {
      return false;
    }
  }
  return true;
}

// FUNCTION: IMPERIALISM 0x005274d0
bool TMapMaker::TryMergeRegionGroupWithNeighbors(int cellIndex, int classIndex) {
  for (int dir = 0; dir < 6; ++dir) {
    int neighborCell = GetAdjacentRegionGridCell(cellIndex, dir);
    int neighborClass =
        (neighborCell != -1) ? regionClassGrid[neighborCell / 27][neighborCell % 27] : -1;
    if (neighborClass == -1 || neighborClass == classIndex) {
      continue;
    }
    int myGroupId = cityRegionIds[classIndex];
    int neighborGroupId = cityRegionIds[neighborClass];
    if (myGroupId == -1) {
      if (neighborGroupId == -1) {
        int newGroupId = ++cityRegionNextId;
        cityRegionIds[classIndex] = newGroupId;
        cityRegionIds[neighborClass] = newGroupId;
      } else {
        cityRegionIds[classIndex] = neighborGroupId;
      }
    } else if (myGroupId != neighborGroupId) {
      return false;
    }
  }
  return true;
}

// FUNCTION: IMPERIALISM 0x005275a0
void TMapMaker::ExpandRegionGridIntoTilesAndAllocateCityRecords() {
  int cityRecordIndex = 0;
  int coarseIndex;
  for (coarseIndex = 0; coarseIndex < 0x195; ++coarseIndex) {
    signed char regionClass = regionClassGrid[coarseIndex / 0x1b][coarseIndex % 0x1b];
    signed char ownerNation;
    StrategicTerrainKind terrainKind;
    short linkedCityRecord;

    if (regionClass == -1 || regionClass == 100) {
      ownerNation = -1;
      terrainKind = kStrategicTerrainWater;
      linkedCityRecord = -1;
    } else {
      ownerNation = regionClass;
      terrainKind = kStrategicTerrainPlains;
      linkedCityRecord = static_cast<short>(cityRecordIndex);
      ++cityRecordIndex;
      cityScoreTable[linkedCityRecord].ownerNationCode = ownerNation;
      cityScoreTable[linkedCityRecord].regionClass =
          static_cast<signed char>(cityRegionIds[static_cast<short>(ownerNation)]);
    }

    int coarseRow = coarseIndex / 0x1b;
    int coarseColumn = coarseIndex % 0x1b;
    TTerrainStateRecord* tile = static_cast<TTerrainStateRecord*>(static_cast<void*>(mapTileGrid)) +
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
          tile->ownerNationTag = ownerNation;
          tile->SetTerrainKind(terrainKind);
          tile->cityRecordIndex = linkedCityRecord;
          ++tile;
        }
        tile += 104;
        for (column = 0; column < 2; ++column) {
          tile->ownerNationTag = ownerNation;
          tile->SetTerrainKind(terrainKind);
          tile->cityRecordIndex = linkedCityRecord;
          ++tile;
        }
      }
    } else {
      int row;
      for (row = 0; row < 4; ++row) {
        int column;
        for (column = 0; column < 4; ++column) {
          tile->ownerNationTag = ownerNation;
          tile->SetTerrainKind(terrainKind);
          tile->cityRecordIndex = linkedCityRecord;
          ++tile;
        }
        tile += 104;
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x00527730
void TMapMaker::PlaceTerrainFeatureQuotas() {
  int forestQuota = g_mapGenForestQuota;
  int swampQuota = g_mapGenSwampQuota;
  int hillsQuota = g_mapGenHillsQuota;

  for (int remaining = g_mapGenMountainQuota; remaining > 0;) {
    g_mapGenLcgState = g_mapGenLcgState * 0x15a4e35 + 1;
    unsigned int seedHigh = g_mapGenLcgState >> 0xc;
    int tileIndex;
    do {
      g_mapGenLcgState = g_mapGenLcgState * 0x15a4e35 + 1;
      tileIndex = static_cast<int>((g_mapGenLcgState >> 0xc & 0x7fff) % kStrategicTileCount);
    } while (mapTileGrid[tileIndex * 0x24] != kStrategicTerrainPlains);
    g_mapGenLcgState = g_mapGenLcgState * 0x15a4e35 + 1;
    int retryBudget = static_cast<int>((seedHigh & 0x7fff) % 0xc) + 3;
    int direction = static_cast<int>((g_mapGenLcgState >> 0xc & 0x7fff) % 6);
    remaining -= SeedMountainRange(tileIndex, retryBudget, direction);
  }
  if (g_pActiveRandomMapSetupPicture != 0) {
    g_pActiveRandomMapSetupPicture->SpinYourGlobe();
  }

  for (int hillsSrcTile = 0; hillsSrcTile < kStrategicTileCount; ++hillsSrcTile) {
    if (mapTileGrid[hillsSrcTile * 0x24] != kStrategicTerrainMountain) {
      continue;
    }
    for (int hillsDir = 0; hillsDir < 6; ++hillsDir) {
      int neighborTile = GetNeighborTileIndexOnMap108x60(hillsSrcTile, hillsDir);
      if (neighborTile != -1 && mapTileGrid[neighborTile * 0x24] == kStrategicTerrainPlains) {
        g_mapGenLcgState = g_mapGenLcgState * 0x15a4e35 + 1;
        if (static_cast<int>((g_mapGenLcgState >> 0xc & 0x7fff) % 100) < 0x28) {
          mapTileGrid[neighborTile * 0x24] = kStrategicTerrainHills;
          --hillsQuota;
        }
      }
    }
  }
  if (g_pActiveRandomMapSetupPicture != 0) {
    g_pActiveRandomMapSetupPicture->SpinYourGlobe();
  }

  while (hillsQuota > 0) {
    g_mapGenLcgState = g_mapGenLcgState * 0x15a4e35 + 1;
    int hillsFallbackTile =
        static_cast<int>((g_mapGenLcgState >> 0xc & 0x7fff) % kStrategicTileCount);
    if (mapTileGrid[hillsFallbackTile * 0x24] == kStrategicTerrainPlains) {
      mapTileGrid[hillsFallbackTile * 0x24] = kStrategicTerrainHills;
      --hillsQuota;
    }
  }
  if (g_pActiveRandomMapSetupPicture != 0) {
    g_pActiveRandomMapSetupPicture->SpinYourGlobe();
  }

  CreateDeserts();
  if (g_pActiveRandomMapSetupPicture != 0) {
    g_pActiveRandomMapSetupPicture->SpinYourGlobe();
  }

  bool urgentFlag = false;
  while (forestQuota > 0) {
    g_mapGenLcgState = g_mapGenLcgState * 0x15a4e35 + 1;
    int forestTile = static_cast<int>((g_mapGenLcgState >> 0xc & 0x7fff) % kStrategicTileCount);
    forestQuota -= PlantForestCluster(forestTile, 7, static_cast<char>(urgentFlag));
    if (forestQuota < g_mapGenForestQuota * 2 / 3) {
      urgentFlag = true;
    }
  }
  if (g_pActiveRandomMapSetupPicture != 0) {
    g_pActiveRandomMapSetupPicture->SpinYourGlobe();
  }

  for (;;) {
    if (swampQuota < 1) {
      if (g_pActiveRandomMapSetupPicture != 0) {
        g_pActiveRandomMapSetupPicture->SpinYourGlobe();
      }
      for (int fillTile = 0; fillTile < kStrategicTileCount; ++fillTile) {
        if (mapTileGrid[fillTile * 0x24] == kStrategicTerrainPlains) {
          g_mapGenLcgState = g_mapGenLcgState * 0x15a4e35 + 1;
          if (static_cast<int>((g_mapGenLcgState >> 0xc & 0x7fff) % 100) < 0x2d) {
            mapTileGrid[fillTile * 0x24] = kStrategicTerrainFarmland;
          }
        }
      }
      if (g_pActiveRandomMapSetupPicture != 0) {
        g_pActiveRandomMapSetupPicture->SpinYourGlobe();
      }
      CreateRivers();
      return;
    }

    int swampTile;
    do {
      g_mapGenLcgState = g_mapGenLcgState * 0x15a4e35 + 1;
      swampTile = static_cast<int>((g_mapGenLcgState >> 0xc & 0x7fff) % kStrategicTileCount);
    } while (mapTileGrid[swampTile * 0x24] != kStrategicTerrainPlains);

    bool allNeighborsClear = true;
    for (int swampDir = 0; swampDir < 6; ++swampDir) {
      int neighborTile = GetNeighborTileIndexOnMap108x60(swampTile, swampDir);
      if (neighborTile != -1 && mapTileGrid[neighborTile * 0x24] == kStrategicTerrainDesert) {
        allNeighborsClear = false;
      }
    }
    if (allNeighborsClear) {
      --swampQuota;
      mapTileGrid[swampTile * 0x24] = kStrategicTerrainSwamp;
    }
  }
}

// FUNCTION: IMPERIALISM 0x00527d00
void TMapMaker::CreateRivers() {
  int riversRemaining = g_mapGenRiverCount;
  int attemptsRemaining = 5000000;
  while (riversRemaining != 0) {
    int tileIndex;
    do {
      g_mapGenLcgState = g_mapGenLcgState * 0x15a4e35 + 1;
      tileIndex = static_cast<int>((g_mapGenLcgState >> 12 & 0x7fff) % kStrategicTileCount);
      --attemptsRemaining;
      if (attemptsRemaining == 0) {
        return;
      }
    } while (mapTileGrid[tileIndex * 0x24] != kStrategicTerrainMountain);

    g_mapGenLcgState = g_mapGenLcgState * 0x15a4e35 + 1;
    int firstDirection = static_cast<int>((g_mapGenLcgState >> 12 & 0x7fff) % 5);
    int direction = firstDirection;
    int neighbor;
    do {
      direction = direction == 5 ? 0 : direction + 1;
      neighbor = GetNeighborTileIndexOnMap108x60(tileIndex, direction);
    } while (mapTileGrid[neighbor * 0x24] == kStrategicTerrainMountain &&
             direction != firstDirection);

    if (direction != firstDirection && GrowRiver(tileIndex, direction, 6, 0, true)) {
      --riversRemaining;
    }
  }
}

// FUNCTION: IMPERIALISM 0x00527ed0
bool TMapMaker::GrowRiver(long tileIndex, long incomingDirection, long outgoingDirection,
                          long depth, bool startedOnHills) {
  char* tile = mapTileGrid + tileIndex * 0x24;
  StrategicTerrainKind terrainKind = static_cast<StrategicTerrainKind>(*tile);
  bool beganOnHills = terrainKind == kStrategicTerrainHills;
  if (tile[2] != 0 || (terrainKind == kStrategicTerrainMountain && depth != 0) ||
      (terrainKind == kStrategicTerrainHills && !startedOnHills)) {
    return false;
  }
  if (terrainKind == kStrategicTerrainWater) {
    if (depth < 5) {
      return false;
    }
    tile[2] = static_cast<char>(outgoingDirection + 0x10);
    return true;
  }

  long oppositeDirection = outgoingDirection;
  long nextDirection = incomingDirection;
  if (outgoingDirection < 6) {
    oppositeDirection = outgoingDirection + 3;
    if (oppositeDirection > 5) {
      oppositeDirection -= 6;
    }
    do {
      g_mapGenLcgState = g_mapGenLcgState * 0x15a4e35 + 1;
      nextDirection =
          incomingDirection - static_cast<long>((g_mapGenLcgState >> 12 & 0x7fff) % 3) + 1;
      if (nextDirection > 5) {
        nextDirection -= 6;
      } else if (nextDirection < 0) {
        nextDirection += 6;
      }
    } while (g_riverConnectionTypeByDirectionPair[nextDirection][oppositeDirection] == 0);
  }

  int neighbor =
      GetNeighborTileIndexOnMap108x60(static_cast<int>(tileIndex), static_cast<int>(nextDirection));
  if (!GrowRiver(neighbor, incomingDirection, nextDirection, depth + 1, beganOnHills)) {
    return false;
  }
  if (depth == 0) {
    tile[2] = static_cast<char>(nextDirection + 10);
  } else {
    tile[2] =
        static_cast<char>(g_riverConnectionTypeByDirectionPair[nextDirection][oppositeDirection]);
  }
  return true;
}

// FUNCTION: IMPERIALISM 0x00528140
int TMapMaker::PlantForestCluster(int tileIndex, int retryBudget, bool markerVariant) {
  if (mapTileGrid[tileIndex * 0x24] != kStrategicTerrainPlains) {
    return 0;
  }
  for (int dir = 0; dir < 6; ++dir) {
    int neighborTile = GetNeighborTileIndexOnMap108x60(tileIndex, dir);
    if (neighborTile != -1 && mapTileGrid[neighborTile * 0x24] == kStrategicTerrainDesert) {
      return 0;
    }
  }

  mapTileGrid[tileIndex * 0x24] = kStrategicTerrainForest;
  mapTileGrid[tileIndex * 0x24 + 0x13] = (!markerVariant) ? 0xd : 0xf;

  int remaining = retryBudget - 1;
  for (int spreadDir = 0; spreadDir < 6; ++spreadDir) {
    int neighborTile = GetNeighborTileIndexOnMap108x60(tileIndex, spreadDir);
    g_mapGenLcgState = g_mapGenLcgState * 0x15a4e35 + 1;
    if (static_cast<int>((g_mapGenLcgState >> 0xc & 0x7fff) % 100) < 0x46 && remaining != 0) {
      remaining -= PlantForestCluster(neighborTile, 1, markerVariant);
    }
  }
  return retryBudget - remaining;
}

// FUNCTION: IMPERIALISM 0x005283c0
int TMapMaker::SeedMountainRange(int tileIndex, int retryBudget, int direction) {
  if (tileIndex < 0 || tileIndex > kStrategicTileCount) {
    return 0;
  }
  if (mapTileGrid[tileIndex * 0x24] != kStrategicTerrainPlains) {
    return 0;
  }
  for (int dir = 0; dir < 6; ++dir) {
    int neighborTile = GetNeighborTileIndexOnMap108x60(tileIndex, dir);
    if (neighborTile != -1 && mapTileGrid[neighborTile * 0x24] == kStrategicTerrainWater) {
      return 0;
    }
  }

  mapTileGrid[tileIndex * 0x24] = kStrategicTerrainMountain;

  int nextDirection = direction;
  if (direction == 1 || direction == 4) {
    g_mapGenLcgState = g_mapGenLcgState * 0x15a4e35 + 1;
    int roll = static_cast<int>((g_mapGenLcgState >> 0xc & 0x7fff) % 100);
    if (roll > 0x27) {
      if (roll < 0x46) {
        nextDirection = (direction == 0) ? 5 : direction - 1;
      } else if (direction == 5) {
        nextDirection = 0;
      } else {
        nextDirection = direction + 1;
      }
    }
  } else {
    g_mapGenLcgState = g_mapGenLcgState * 0x15a4e35 + 1;
    int roll = static_cast<int>((g_mapGenLcgState >> 0xc & 0x7fff) % 100);
    if (roll > 0x3b) {
      if (roll < 0x50) {
        nextDirection = (direction == 0) ? 5 : direction - 1;
      } else if (direction == 5) {
        nextDirection = 0;
      } else {
        nextDirection = direction + 1;
      }
    }
  }

  int nextTile = GetNeighborTileIndexOnMap108x60(tileIndex, nextDirection);
  int placed = 1;
  if (retryBudget != 1 && nextTile != -1) {
    // MATCH: the original recurses with the unadjusted direction, not nextDirection;
    // the random perturbation above only picks which neighbor
    // to step into this call, not the direction future steps inherit.
    placed += SeedMountainRange(nextTile, retryBudget - 1, direction);
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
  char* tile = mapTileGrid + row * 0xf30;
  int column = 0;
  while (*tile != kStrategicTerrainWater && column < kStrategicMapColumns) {
    tile += 0x24;
    ++column;
  }
  if (column == 0x6c) {
    return 0;
  }

  int marked = 0;
  int ringState = 0;
  for (int remaining = 0; remaining < 0x6b; ++remaining) {
    ++column;
    tile += 0x24;
    if (column == 0x6c) {
      column = 0;
    }
    if (ringState == 0 && *tile != kStrategicTerrainWater) {
      ringState = 1;
    }
    if (ringState == 1) {
      if (*tile == kStrategicTerrainPlains) {
        g_mapGenLcgState = g_mapGenLcgState * 0x15a4e35 + 1;
        if (static_cast<int>((g_mapGenLcgState >> 12 & 0x7fff) % 100) < percentChance) {
          *tile = kStrategicTerrainDesert;
          tile[0x13] = 12;
          ++marked;
        }
      } else if (*tile == kStrategicTerrainWater) {
        ringState = 0;
      }
    } else if (ringState == 2 && *tile == kStrategicTerrainWater) {
      ringState = 0;
    }
  }
  return marked;
}

// FUNCTION: IMPERIALISM 0x005288a0
int TMapMaker::DesertBand(int row, int percentChance) {
  char* tile = mapTileGrid + row * 0xf30;
  int column = 0;
  while (*tile != kStrategicTerrainWater && column < kStrategicMapColumns) {
    tile += 0x24;
    ++column;
  }
  if (column == 0x6c) {
    return 0;
  }

  int marked = 0;
  int ringState = 0;
  for (int remaining = 0; remaining < 0x6b; ++remaining) {
    ++column;
    tile += 0x24;
    if (column == 0x6c) {
      column = 0;
    }
    if (ringState == 0 && *tile != kStrategicTerrainWater) {
      ringState = 1;
    }
    if (ringState == 1) {
      if (*tile == kStrategicTerrainPlains) {
        g_mapGenLcgState = g_mapGenLcgState * 0x15a4e35 + 1;
        if (static_cast<int>((g_mapGenLcgState >> 12 & 0x7fff) % 100) < percentChance) {
          int tileIndex = column + row * kStrategicMapColumns;
          *tile = kStrategicTerrainDesert;
          tile[0x13] = 11;
          ++marked;

          int neighbor = GetNeighborTileIndexOnMap108x60(tileIndex, 5);
          char* neighborTile = mapTileGrid + neighbor * 0x24;
          if (*neighborTile == kStrategicTerrainPlains) {
            g_mapGenLcgState = g_mapGenLcgState * 0x15a4e35 + 1;
            if (static_cast<int>((g_mapGenLcgState >> 12 & 0x7fff) % 100) < percentChance) {
              *neighborTile = kStrategicTerrainDesert;
              tile[0x13] = 11;
              ++marked;
            }
          }

          neighbor = GetNeighborTileIndexOnMap108x60(tileIndex, 3);
          neighborTile = mapTileGrid + neighbor * 0x24;
          if (*neighborTile == kStrategicTerrainPlains) {
            g_mapGenLcgState = g_mapGenLcgState * 0x15a4e35 + 1;
            if (static_cast<int>((g_mapGenLcgState >> 12 & 0x7fff) % 100) < percentChance) {
              *neighborTile = kStrategicTerrainDesert;
              tile[0x13] = 11;
              ++marked;
            }
          }
        }
      } else if (*tile == kStrategicTerrainWater) {
        ringState = 0;
      }
    } else if (ringState == 2 && *tile == kStrategicTerrainWater) {
      ringState = 0;
    }
  }
  return marked;
}

// FUNCTION: IMPERIALISM 0x00528ce0
int TMapMaker::GetAdjacentRegionGridCell(int cell, int direction) {
  int column = cell % 0x1b;
  int row = cell / 0x1b;
  if ((row & 1) == 0) {
    column += g_coarseHexColOffsetEvenRow[direction];
  } else {
    column += g_coarseHexColOffsetOddRow[direction];
  }
  row += g_coarseHexRowOffset[direction];

  if (column < 0) {
    column += 0x1b;
  } else if (column >= 0x1b) {
    column -= 0x1b;
  }

  if (row < 0 || row > kStrategicMapRows) {
    return -1;
  }
  int neighbor = column + row * 0x1b;
  if (neighbor < 0 || neighbor >= 0x195) {
    return -1;
  }
  return neighbor;
}

// FUNCTION: IMPERIALISM 0x00528d80
void ComputeHexTilePixelCenter(int tileIndex, int* outX, int* outY, int cellSize) {
  int xOffset;
  *outY = tileIndex / kStrategicMapColumns;
  if ((tileIndex / kStrategicMapColumns & 1) != 0) {
    xOffset = cellSize;
  } else {
    xOffset = cellSize / 2;
  }
  *outX = tileIndex % kStrategicMapColumns * cellSize + xOffset;
  *outY = *outY * cellSize + cellSize / 2;
}

// FUNCTION: IMPERIALISM 0x00528e00
void TMapMaker::WriteTileGridToFile(const char* path) {
  FILE* file = fopen(path, g_szLiteralWb);
  fwrite(mapTileGrid, 0x6540, 1, file);
  fclose(file);
}

// FUNCTION: IMPERIALISM 0x00528e50
void TMapMaker::SmoothCityRegionOwnershipByNeighborSampling() {
  short owner;
  for (int tileIndex = 0x6c; tileIndex < kStrategicTileCount - 0x6c; ++tileIndex) {
    int sameOwnerCount = 0;
    int differingNeighborDir = -1;
    owner = static_cast<signed char>(mapTileGrid[tileIndex * 0x24 + 4]);
    for (int dir = 0; dir < 6; ++dir) {
      int neighborTile = GetNeighborTileIndexOnMap108x60(tileIndex, dir);
      short neighborOwner = (neighborTile != -1)
                                ? static_cast<signed char>(mapTileGrid[neighborTile * 0x24 + 4])
                                : -1;
      if (neighborOwner == owner) {
        ++sameOwnerCount;
      } else if (neighborOwner != -1) {
        differingNeighborDir = dir;
      }
    }

    if (sameOwnerCount == 0) {
      // Always replace an unsupported ownership cell.
    } else if (sameOwnerCount == 1) {
      g_mapGenLcgState = g_mapGenLcgState * 0x15a4e35 + 1;
      if ((g_mapGenLcgState >> 0xc & 1) == 0) {
        continue;
      }
    } else if (sameOwnerCount == 2) {
      g_mapGenLcgState = g_mapGenLcgState * 0x15a4e35 + 1;
      if ((g_mapGenLcgState >> 0xc & 4) != 0) {
        continue;
      }
    } else {
      continue;
    }
    if (differingNeighborDir != -1) {
      int neighborTile = GetNeighborTileIndexOnMap108x60(tileIndex, differingNeighborDir);
      memcpy(&mapTileGrid[tileIndex * 0x24], &mapTileGrid[neighborTile * 0x24], 0x24);
    }
  }

  for (int isolatedTile = 0x6c; isolatedTile < kStrategicTileCount - 0x6c; ++isolatedTile) {
    bool hasSameOwnerNeighbor = false;
    owner = static_cast<signed char>(mapTileGrid[isolatedTile * 0x24 + 4]);
    for (int isoDir = 0; isoDir < 6; ++isoDir) {
      int neighborTile = GetNeighborTileIndexOnMap108x60(isolatedTile, isoDir);
      short neighborOwner = (neighborTile != -1)
                                ? static_cast<signed char>(mapTileGrid[neighborTile * 0x24 + 4])
                                : -1;
      if (neighborOwner == owner) {
        hasSameOwnerNeighbor = true;
      }
    }
    if (!hasSameOwnerNeighbor) {
      g_mapGenLcgState = g_mapGenLcgState * 0x15a4e35 + 1;
      short randomDir = static_cast<short>(static_cast<int>(g_mapGenLcgState >> 0xc & 0x7fff) % 6);
      int neighborTile = GetNeighborTileIndexOnMap108x60(isolatedTile, randomDir);
      memcpy(&mapTileGrid[isolatedTile * 0x24], &mapTileGrid[neighborTile * 0x24], 0x24);
    }
  }
}

// FUNCTION: IMPERIALISM 0x005292f0
void TMapMaker::RandomizeRegionTemplatesAndSmoothOwnership() {
  int coarseIndex;
  for (coarseIndex = 0; coarseIndex < 0x17a; ++coarseIndex) {
    unsigned short baseClass =
        static_cast<unsigned short>(static_cast<signed char>(regionClassGrid[0][coarseIndex]));

    GetAdjacentRegionGridCell(coarseIndex, 0);
    GetAdjacentRegionGridCell(coarseIndex, 5);

    int neighbor = GetAdjacentRegionGridCell(coarseIndex, 1);
    unsigned short class1 =
        static_cast<unsigned short>(static_cast<signed char>(regionClassGrid[0][neighbor]));
    neighbor = GetAdjacentRegionGridCell(coarseIndex, 2);
    unsigned short class2 =
        static_cast<unsigned short>(static_cast<signed char>(regionClassGrid[0][neighbor]));
    neighbor = GetAdjacentRegionGridCell(coarseIndex, 3);
    unsigned short class3 =
        static_cast<unsigned short>(static_cast<signed char>(regionClassGrid[0][neighbor]));
    GetAdjacentRegionGridCell(coarseIndex, 4);

    RandomizeRegionTemplateBanksForMismatchedNeighborClasses(coarseIndex, baseClass, class1, class3,
                                                             class2);
  }

  if (g_pActiveRandomMapSetupPicture != 0) {
    g_pActiveRandomMapSetupPicture->SpinYourGlobe();
  }
  SmoothCityRegionOwnershipByNeighborSampling();
}

// FUNCTION: IMPERIALISM 0x005293d0
unsigned int TMapMaker::RandomizeRegionTemplateBanksForMismatchedNeighborClasses(
    int coarseIndex, unsigned short baseClass, unsigned short class3, unsigned short class4,
    unsigned short class5) {
  unsigned int result = class3;
  if (class3 != baseClass) {
    MapGeneratorTileRecord* cell = GetFineGridCellBasePointerFromCoarseIndex(coarseIndex);
    g_mapGenLcgState = g_mapGenLcgState * 0x15a4e35 + 1;
    MapGeneratorTileRecord* dst = NULL;
    MapGeneratorTileRecord* src = NULL;
    bool copy = true;
    switch ((g_mapGenLcgState >> 0xc & 0x7fff) % 5) {
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
    g_mapGenLcgState = g_mapGenLcgState * 0x15a4e35 + 1;
    unsigned int r = g_mapGenLcgState >> 0xc & 0x7fff;
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
    unsigned int r = g_mapGenLcgState * 0x15a4e35 + 1;
    if ((r >> 0xc & 1) != 0) {
      dst = &cell[325];
    }
    g_mapGenLcgState = r * 0x15a4e35 + 1;
    unsigned int r2 = g_mapGenLcgState >> 0xc & 0x7fff;
    result = r2 / 7;
    MapGeneratorTileRecord* src = NULL;
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
      dst += 108;
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
    unsigned int r = g_mapGenLcgState * 0x15a4e35 + 1;
    if ((r >> 0xc & 1) != 0) {
      dst = &cell[327];
    }
    g_mapGenLcgState = r * 0x15a4e35 + 1;
    unsigned int r2 = g_mapGenLcgState >> 0xc & 0x7fff;
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

namespace {

bool LinkIsEmpty(const SeaSegment* rec) {
  return rec->x0 == rec->x1 && rec->y0 == rec->y1;
}

} // namespace

// FUNCTION: IMPERIALISM 0x005296a0
void TMapMaker::CopyRegionTemplateBankWithRandomVariant(int coarseIndex, short regionClass,
                                                        short unusedClass, short northClass,
                                                        short southClass) {
  MapGeneratorTileRecord* cell = GetFineGridCellBasePointerFromCoarseIndex(coarseIndex);

  if (northClass == regionClass) {
    g_mapGenLcgState = g_mapGenLcgState * 0x15a4e35 + 1;
    unsigned int randomBits = g_mapGenLcgState >> 0xc;
    if ((randomBits & 1) != 0) {
      memcpy(cell - 106, cell, sizeof(*cell));
      g_mapGenLcgState = g_mapGenLcgState * 0x15a4e35 + 1;
      randomBits = g_mapGenLcgState >> 0xc;
      if ((randomBits & 3) == 0) {
        memcpy(cell - 214, cell, sizeof(*cell));
      }
    } else {
      memcpy(cell + 2, cell - 107, sizeof(*cell));
    }
  } else {
    memcpy(cell - 108, cell, sizeof(*cell));
    g_mapGenLcgState = g_mapGenLcgState * 0x15a4e35 + 1;
    unsigned int randomBits = g_mapGenLcgState >> 0xc;
    if ((randomBits & 1) != 0) {
      memcpy(cell - 109, cell, sizeof(*cell));
      g_mapGenLcgState = g_mapGenLcgState * 0x15a4e35 + 1;
      randomBits = g_mapGenLcgState >> 0xc;
      if ((randomBits & 1) != 0) {
        memcpy(cell - 216, cell, sizeof(*cell));
      }
    }
  }

  if (southClass != regionClass) {
    memcpy(cell + 3, cell - 106, sizeof(*cell));
  }
}

// FUNCTION: IMPERIALISM 0x005297e0
void TMapMaker::CopyRegionTemplateBankToNeighborCell(int coarseIndex, short regionClass,
                                                     short unusedClass, short northClass,
                                                     short unusedClass2) {
  int neighbor = GetAdjacentRegionGridCell(coarseIndex, 2);
  MapGeneratorTileRecord* cell = GetFineGridCellBasePointerFromCoarseIndex(neighbor);
  MapGeneratorTileRecord* source = cell - 108;

  if (northClass == regionClass) {
    memcpy(cell, source, sizeof(*cell));
  } else if (regionClass != 1) {
    memcpy(cell - 1, source, sizeof(*cell));
    g_mapGenLcgState = g_mapGenLcgState * 0x15a4e35 + 1;
    unsigned int randomBits = g_mapGenLcgState >> 0xc;
    if ((randomBits & 0x7fff) == 0) {
      memcpy(cell - 2, source, sizeof(*cell));
    }
  }
}

// FUNCTION: IMPERIALISM 0x005298a0
MapGeneratorTileRecord* TMapMaker::GetFineGridCellBasePointerFromCoarseIndex(int coarseIndex) {
  char* cell = (static_cast<short>(coarseIndex % 0x1b) +
                static_cast<short>(coarseIndex / 0x1b) * kStrategicMapColumns) *
                   0x90 +
               mapTileGrid;
  if ((coarseIndex / 0x1b & 1U) != 0) {
    cell -= 0x48;
  }
  return static_cast<MapGeneratorTileRecord*>(static_cast<void*>(cell));
}

// FUNCTION: IMPERIALISM 0x00529910
int TMapMaker::CountSeaTilesInColumn(int columnIndex) {
  int count = 0;
  int rows = 0x3c;
  char* tile = mapTileGrid + columnIndex * 0x24;
  do {
    if (*tile == kStrategicTerrainWater) {
      ++count;
    }
    tile += 0xf30;
    --rows;
  } while (rows != 0);
  return count;
}

// FUNCTION: IMPERIALISM 0x00529960
void TMapMaker::RotateMapColumnsByPeakWaterTileDensity() {
  int total = 0;
  int windowPos = 0;
  int bestDensity = -1;
  int bestColumn = 0;
  int window[3];

  // Prime the 3-column sliding sum with the columns preceding column 0 (wrap-around).
  int* w = window;
  int columnIndex = 104;
  for (int prime = 0; prime < 3; ++prime) {
    int count = CountSeaTilesInColumn(columnIndex);
    *w = count;
    total += count;
    ++columnIndex;
    ++w;
  }

  // Slide across all 108 columns, tracking the peak 3-column sum.
  int scanCol = 0;
  columnIndex = 0;
  do {
    int count = CountSeaTilesInColumn(columnIndex);
    total += count;
    if (bestDensity < total) {
      bestColumn = scanCol;
      bestDensity = total;
    }
    int evicted = window[windowPos];
    window[windowPos] = count;
    total -= evicted;
    ++windowPos;
    if (2 < windowPos) {
      windowPos = 0;
    }
    ++scanCol;
    ++columnIndex;
  } while (scanCol < kStrategicMapColumns);

  if (CountSeaTilesInColumn(bestColumn) == 0) {
    int leftCol = bestColumn - 1;
    if (leftCol < 0) {
      leftCol = bestColumn + 0x6b;
    }
    ++bestColumn;
    if (0x6b < bestColumn) {
      bestColumn = 0;
    }
    while (CountSeaTilesInColumn(leftCol) == 0) {
      --leftCol;
      if (leftCol < 0) {
        leftCol = 0x6b;
      }
    }
    while (CountSeaTilesInColumn(bestColumn) == 0) {
      ++bestColumn;
      if (0x6b < bestColumn) {
        bestColumn = 0;
      }
    }
    ++leftCol;
    if (0x6b < leftCol) {
      leftCol = 0;
    }
    int rightCol = bestColumn - 1;
    if (rightCol < 0) {
      rightCol = bestColumn + 0x6b;
    }
    if (rightCol < leftCol) {
      bestColumn = (leftCol + kStrategicMapColumns + rightCol) / 2;
      if (0x6c < bestColumn) {
        bestColumn -= kStrategicMapColumns;
      }
    } else {
      bestColumn = (rightCol + leftCol) / 2;
    }
  }
#ifdef IMPERIALISM_RUNTIME_TESTS
  RuntimeTerrainMapOracleRecordRotationColumn(bestColumn);
#endif

  // Copy the whole grid, then write it back rotated so the chosen column band leads.
  int* scratch = new int[0xe3d0];
  if (scratch == NULL) {
    FailNilPointerWithAssert("D:\\Ambit\\Cross\\UMapper.cpp", 0x904);
  }

  int destByte = 0;
  int sourceCol = bestColumn + 0x6b;
  memcpy(scratch, mapTileGrid, 0x38f40);
  do {
    int rows = 0x3c;
    int* scratchRow = scratch + (sourceCol % kStrategicMapColumns) * 9;
    int rowByte = destByte;
    do {
      --rows;
      memcpy(mapTileGrid + rowByte, scratchRow, 0x24);
      scratchRow += 0x3cc;
      rowByte += 0xf30;
    } while (rows != 0);
    destByte += 0x24;
    ++sourceCol;
  } while (destByte < 0xf30);

  if (scratch != NULL) {
    delete[] scratch;
  }
}
// FUNCTION: IMPERIALISM 0x00529c80
int TMapMaker::ZoneCorner(long nationCode) {
  int longestRun = 0;
  int selectedRow = 0;
  int currentRun = 0;
  int tileIndex = 0;
  char* owner = mapTileGrid + 4;

  do {
    if (*owner == nationCode) {
      ++currentRun;
    } else {
      if (longestRun < currentRun) {
        longestRun = currentRun;
        selectedRow = tileIndex / kStrategicMapColumns;
      }
      currentRun = 0;
    }
    ++tileIndex;
    owner += 0x24;
  } while (tileIndex < kStrategicTileCount);

  int leftEdgeCount = 0;
  int rightEdgeCount = 0;
  int columnSum = 0;
  int matchCount = 0;
  int column = 0;
  int selectedRowTile = selectedRow * kStrategicMapColumns;
  owner = mapTileGrid + selectedRowTile * 0x24 + 4;
  do {
    if (*owner == nationCode) {
      if (column < 0x19) {
        ++leftEdgeCount;
      }
      if (0x53 < column) {
        ++rightEdgeCount;
      }
      columnSum += column;
      ++matchCount;
    }
    ++column;
    owner += 0x24;
  } while (column < kStrategicMapColumns);

  if (0 < leftEdgeCount && 0 < rightEdgeCount) {
    columnSum = columnSum + leftEdgeCount * 0x6c;
  }
  if (matchCount == 0) {
    return -1;
  }
  return (columnSum / matchCount) % kStrategicMapColumns + selectedRowTile;
}

// FUNCTION: IMPERIALISM 0x00529d90
int TMapMaker::ComputeOwnedTerritoryCentroidTile(int nationCode, char useWrapOffset) {
  int columnSum = 0;
  int rowSum = 0;
  int matchCount = 0;
  int tileIndex = 0;
  char* ownerBase = mapTileGrid + 4;
  char leftEdgeCount = '\0';
  char rightEdgeCount = '\0';

  char* owner = ownerBase;
  do {
    if (*owner == nationCode) {
      int column = tileIndex % kStrategicMapColumns;
      if (column < 0x19) {
        leftEdgeCount = leftEdgeCount + '\x01';
      }
      if (0x53 < column) {
        rightEdgeCount = rightEdgeCount + '\x01';
      }
      columnSum += column;
      rowSum = rowSum + tileIndex / kStrategicMapColumns;
      ++matchCount;
    }
    ++tileIndex;
    owner += 0x24;
  } while (tileIndex < kStrategicTileCount);

  bool wrapsHorizontally;
  if (leftEdgeCount < '\x01' || rightEdgeCount < '\x01') {
    wrapsHorizontally = false;
  } else {
    wrapsHorizontally = true;
    if (useWrapOffset == '\0') {
      columnSum = 0;
      rowSum = 0;
      matchCount = 0;
      tileIndex = 0;
      owner = ownerBase;
      do {
        if (*owner == nationCode) {
          int column = tileIndex % kStrategicMapColumns;
          if (column < 0x36 && leftEdgeCount < rightEdgeCount) {
            column = 0x6b;
          }
          if (0x36 < column && rightEdgeCount < leftEdgeCount) {
            column = 0;
          }
          columnSum += column;
          rowSum = rowSum + tileIndex / kStrategicMapColumns;
          ++matchCount;
        }
        ++tileIndex;
        owner += 0x24;
      } while (tileIndex < kStrategicTileCount);
      if (matchCount != 0) {
        return (columnSum / matchCount) % kStrategicMapColumns +
               (rowSum / matchCount) * kStrategicMapColumns;
      }
      return -1;
    }
  }
  if (wrapsHorizontally && useWrapOffset != '\0') {
    columnSum = columnSum + leftEdgeCount * 0x6c;
  }
  if (matchCount != 0) {
    return (columnSum / matchCount) % kStrategicMapColumns +
           (rowSum / matchCount) * kStrategicMapColumns;
  }
  return -1;
}

// FUNCTION: IMPERIALISM 0x00529f60
void TMapMaker::AssignOrCompactCityRegionIdsAndRebuildBorders(int mode) {
  if (static_cast<unsigned char>(mode) != 0) {
    int i;
    cityRegionCount = 0;
    for (i = 0; i < 0x100; ++i) {
      g_cityRegionIdRemapTable[i] = -1;
    }

    int tileOffset;
    for (tileOffset = 0; tileOffset < 0x38f40; tileOffset += 0x24) {
      char* tile = mapTileGrid + tileOffset;
      int oldRegionId = -1;
      if (tileOffset >= 0 && tile[0] == kStrategicTerrainWater) {
        oldRegionId = static_cast<signed char>(tile[4]) - 0x17;
      }
      if (oldRegionId > -1) {
        if (g_cityRegionIdRemapTable[oldRegionId] == -1) {
          g_cityRegionIdRemapTable[oldRegionId] = cityRegionCount++;
        }
        tile[4] = static_cast<char>(g_cityRegionIdRemapTable[oldRegionId] + 0x17);
      }
    }
  } else {
    GenerateWaterRegionIdsBySeedAndNeighborPropagation();
  }

  if (g_pActiveRandomMapSetupPicture != 0) {
    g_pActiveRandomMapSetupPicture->SpinYourGlobe();
  }
  BuildCityRegionBorderOverlaySegments();
  if (g_pActiveRandomMapSetupPicture != 0) {
    g_pActiveRandomMapSetupPicture->SpinYourGlobe();
  }
  BuildOverlaySpanRecordsFromQuadBorderLinks();
  if (g_pActiveRandomMapSetupPicture != 0) {
    g_pActiveRandomMapSetupPicture->SpinYourGlobe();
  }
  MergeSmallCityRegionsAndCompactIds();
  if (g_pActiveRandomMapSetupPicture != 0) {
    g_pActiveRandomMapSetupPicture->SpinYourGlobe();
  }
}

// Mac oracle: IsSeaTile.
// FUNCTION: IMPERIALISM 0x0052a0a0
void TMapMaker::CompactCityRegionIds() {
  cityRegionCount = 0;

  int* remapCursor = g_cityRegionIdRemapTable;
  for (int remaining = 0x100; remaining != 0; remaining = remaining - 1) {
    *remapCursor = -1;
    ++remapCursor;
  }

  int byteOffset = 0;
  do {
    int regionClass;
    if (byteOffset < 0 || mapTileGrid[byteOffset] != '\x05') {
      regionClass = -1;
    } else {
      regionClass = mapTileGrid[byteOffset + 4] - 0x17;
    }
    if (-1 < regionClass) {
      if (g_cityRegionIdRemapTable[regionClass] == -1) {
        g_cityRegionIdRemapTable[regionClass] = cityRegionCount;
        ++cityRegionCount;
      }
      mapTileGrid[byteOffset + 4] =
          static_cast<char>(g_cityRegionIdRemapTable[regionClass]) + '\x17';
    }
    byteOffset += 0x24;
  } while (byteOffset < 0x38f40);
}

// FUNCTION: IMPERIALISM 0x0052a160
void TMapMaker::GenerateWaterRegionIdsBySeedAndNeighborPropagation() {
  short* labels = new short[kStrategicTileCount];

  // Phase 1: seed a label per tile: -1 for water tiles, -2 otherwise.
  int i = 0;
  short* p = labels;
  do {
    short index = static_cast<short>(i);
    ++i;
    *p = (g_pGlobalMapState->terrainStateTable[index].GetTerrainKind() == kStrategicTerrainWater) -
         2;
    ++p;
  } while (i < kStrategicTileCount);
  cityRegionCount = 0;

  if (0 < g_regionSeedGridRows) {
    int rowBase = 0;
    int cols = g_regionSeedGridCols;
    int rows = g_regionSeedGridRows;
    int rowIdx = 0;
    do {
      int colIdx = 0;
      if (0 < cols) {
        int colBase = 0;
        do {
          unsigned int r = g_mapGenLcgState * 0x15a4e35 + 1;
          g_mapGenLcgState = r * 0x15a4e35 + 1;
          int col = rowBase / rows + 2 + (r >> 0xc & 0x7fff) % 5;
          int row = colBase / cols + 2 + (g_mapGenLcgState >> 0xc & 0x7fff) % 5;
          if ((colIdx & 1) != 0) {
            col = col + rows / 2;
            if (0x6b < col) {
              col -= kStrategicMapColumns;
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
              neighbor = col + row * kStrategicMapColumns;
            }
            if (neighbor != -1 && labels[neighbor] == -1) {
              labels[neighbor] = static_cast<short>(cityRegionCount);
              ++cityRegionCount;
              break;
            }
            ++radius;
            if (ring <= radius) {
              radius = 0;
              ++direction;
              if (5 < direction) {
                ++ring;
                direction = 0;
                TMapMgr::StepHexRowColByDirectionWithWrapRules(&row, &col, 4);
              }
            }
            TMapMgr::StepHexRowColByDirectionWithWrapRules(&row, &col, direction);
          }
          ++colIdx;
          colBase += kStrategicMapColumns;
          cols = g_regionSeedGridCols;
          rows = g_regionSeedGridRows;
        } while (colIdx < g_regionSeedGridCols);
      }
      ++rowIdx;
      rowBase += 0x6c;
    } while (rowIdx < rows);
  }

  do {
    int changed = 0;
    int j = 0;
    short* pj = labels;
    do {
      if (*pj == -1) {
        for (int direction = 0; direction < 6; ++direction) {
          int neighbor = GetNeighborTileIndexOnMap108x60(j, direction);
          if (neighbor != -1) {
            short nl = labels[neighbor];
            if (-1 < nl && nl < 0x400) {
              *pj = nl + 0x400;
              ++changed;
            }
          }
        }
      }
      ++j;
      ++pj;
    } while (j < kStrategicTileCount);

    int k = kStrategicTileCount;
    short* pk = labels;
    do {
      if (0x3ff < *pk) {
        *pk = *pk - 0x400;
      }
      ++pk;
      --k;
    } while (k != 0);

    if (changed < 1) {
      int off = 0;
      short* pw = labels;
      do {
        if (-1 < *pw) {
          *(mapTileGrid + 4 + off) = static_cast<char>(*pw) + '\x17';
        }
        off += 0x24;
        ++pw;
      } while (off < 0x38f40);
#ifdef IMPERIALISM_RUNTIME_TESTS
      RuntimeTerrainMapOracleCaptureStage("after_water_regions", this, g_mapGenLcgState);
#endif
      delete[] labels;
      return;
    }
  } while (true);
}

// FUNCTION: IMPERIALISM 0x0052a600
bool TMapMaker::IsSeaTile(int tileIndex) {
  return mapTileGrid[tileIndex * 0x24] == kStrategicTerrainWater;
}

// FUNCTION: IMPERIALISM 0x0052a630
bool TMapMaker::IsSeaTile(int column, int row) {
  return mapTileGrid[(column + row * kStrategicMapColumns) * 0x24] == kStrategicTerrainWater;
}

// FUNCTION: IMPERIALISM 0x0052a670
int TMapMaker::GetCityRegionIdAtTileIndex(int tileIndex) {
  if (tileIndex >= 0) {
    char* tile = mapTileGrid + tileIndex * 0x24;
    if (*tile == kStrategicTerrainWater) {
      return tile[4] - 0x17;
    }
  }
  return -1;
}

// Mac oracle: SetSeaZoneIndex.
// FUNCTION: IMPERIALISM 0x0052a6b0
void TMapMaker::SetSeaZoneIndex(int tileIndex, char zoneIndex) {
  mapTileGrid[tileIndex * 0x24 + 4] = static_cast<char>(zoneIndex + 0x17);
}

namespace {
const char kUMapperPath[] = "D:\\Ambit\\Cross\\UMapper.cpp";

void AppendBorderQuad(int tileIndex, int regionA, int regionB, int sideCode) {
  Seapoint sp;
  sp.InitSorted(ConvertTileIndexToOverlayCoord216BySide(tileIndex, 1), regionA, regionB, sideCode);
  stretch<Seapoint>* quad = &g_seapointQuadTable;
  quad->Add(sp);
}

} // namespace

// FUNCTION: IMPERIALISM 0x0052b820
void TMapMaker::AssignRegionIdsToUnclaimedBorderSegmentSides() {
  cityRegionCount = 0;

  unsigned int index = 0;
  unsigned int count = g_regionBorderLinkTable.count;
  if (index < count) {
    do {
      if (g_regionBorderLinkTable.At(index)->attrBySide[0] == -1) {
        int regionId = cityRegionCount;
        cityRegionCount = regionId + 1;
        AssignRegionIdAlongBorderSegmentChain(index, '\x01', static_cast<short>(regionId));
        count = g_regionBorderLinkTable.count;
      }
      if (g_regionBorderLinkTable.At(index)->attrBySide[1] == -1) {
        int regionId = cityRegionCount;
        cityRegionCount = regionId + 1;
        AssignRegionIdAlongBorderSegmentChain(index, '\0', static_cast<short>(regionId));
        count = g_regionBorderLinkTable.count;
      }
      ++index;
    } while (index < count);
  }

  index = 0;
  if (index < count) {
    do {
      g_regionBorderLinkTable[index];
      ++index;
    } while (index < static_cast<unsigned int>(g_regionBorderLinkTable.count));
  }
}

// FUNCTION: IMPERIALISM 0x0052b9b0
void TMapMaker::AssignWaterRegionIdsFromOverlayScanlineIntersections() {
  SeaSegmentStretch& segments = g_regionBorderLinkTable;

  int cellX = 0;
  int leftCol = 0;
  int scanY = 0;
  int firstX = -1;
  short region = -1;
  int rowBase = 0;

  do {
    SeaSegment* best = NULL;
    unsigned int si = 0;
    if (segments.Count() != 0) {
      int leftEdge = (scanY & 1) + leftCol * 2;
      int rightEdge = (scanY & 1) + cellX * 2;
      do {
        SeaSegment* seg = segments.At(si);
        int spanLo = leftEdge;
        int spanHi = rightEdge;
        if (rightEdge < leftEdge) {
          spanLo = rightEdge;
          spanHi = leftEdge;
        }
        bool crosses = false;
        if (leftEdge != rightEdge && seg->y0 != seg->y1 && scanY >= seg->y0 && seg->y1 > scanY) {
          if (seg->x0 != seg->x1) {
            int dx;
            if (seg->wrap == 0) {
              dx = seg->x1 - seg->x0;
            } else {
              if (spanLo < 0x6c) {
                spanLo += 0xd8;
              }
              if (spanHi < 0x6c) {
                spanHi += 0xd8;
              }
              // The wrapped branch measures the crossing across the 0xd8-wide seam.
              dx = -0xd8;
            }
            int slope = dx / (seg->y1 - seg->y0);
            double crossX = static_cast<double>(scanY) * slope +
                            (static_cast<double>(seg->x0) - static_cast<double>(seg->y0) * slope);
            if (spanLo <= crossX && crossX < spanHi) {
              crosses = true;
            }
          } else if (seg->x0 >= spanLo && spanHi > seg->x0) {
            crosses = true;
          }
        }

        if (crosses) {
          if (best == NULL) {
            best = segments.At(si);
          } else {
            SeaSegment* cur = segments.At(si);
            MapEdgePoint curStart = {cur->x0, cur->y0};
            WrapExtendedMapXCoordinateInPlace(&curStart.x);
            MapEdgePoint bestStart = {best->x0, best->y0};
            WrapExtendedMapXCoordinateInPlace(&bestStart.x);
            if (curStart.Equals(&bestStart)) {
              if (static_cast<unsigned short>(cur->angle) <
                  static_cast<unsigned short>(best->angle)) {
                best = segments.At(si);
              }
            } else {
              MapEdgePoint curEnd = {cur->x1, cur->y1};
              WrapExtendedMapXCoordinateInPlace(&curEnd.x);
              int endpoint[2];
              best->ExtractWrappedEndpoint(endpoint, '\0');
              MapEdgePoint bestEnd = {endpoint[0], endpoint[1]};
              if (curEnd.Equals(&bestEnd) == 0) {
                if (g_bOverlayScanlineFillAssertSuppressed == 0) {
                  TemporarilyClearAndRestoreUiInvalidationFlag(kUMapperPath, 0xda1);
                }
              } else if (static_cast<unsigned short>(best->angle) <
                         static_cast<unsigned short>(cur->angle)) {
                best = segments.At(si);
              }
            }
          }
        }
        ++si;
      } while (si < static_cast<unsigned int>(segments.Count()));
    }

    if (best != NULL) {
      region = static_cast<short>(best->SelectAttrByAngle());
      if (firstX < 0) {
        firstX = cellX;
      }
    }

    int col = cellX;
    if (0x6b < cellX) {
      col = cellX - 0x6c;
    }
    char* tile = mapTileGrid + (col + rowBase) * 0x24;
    if (*tile == kStrategicTerrainWater && region != -1) {
      tile[4] = static_cast<char>(region) + '\x17';
    }
    leftCol = col;
    cellX = col + 1;
    if (firstX == cellX) {
      leftCol = 0;
      ++scanY;
      rowBase += 0x6c;
      cellX = 0;
      region = -1;
      firstX = -1;
    }
    if (0x194f < rowBase) {
      return;
    }
  } while (true);
}

// FUNCTION: IMPERIALISM 0x0052c1a0
void TMapMaker::BuildCityRegionBorderOverlaySegments() {

  // Reset the overlay-quad table.
  if (g_seapointQuadTable.Data() != NULL) {
    free(g_seapointQuadTable.Detach());
  }

  // Phase 1: row 0 tiles, direction-4 edges.
  int tileIdx = 0;
  int byteOffset = 0;
  do {
    int region1 = GetCityRegionIdAtTileIndex(tileIdx);
    int region2 = GetCityRegionIdAtTileIndex(GetNeighborTileIndexOnMap108x60(tileIdx, 4));
    if (region1 != region2 && region1 != -1 && region2 != -1) {
      AppendBorderQuad(tileIdx, region1, region2, 2);
    }
    byteOffset += 0x24;
    tileIdx += 1;
  } while (byteOffset < 0xf30);

  // Phase 2: remaining tiles, directions 4 and 5, with triple-junction emission.
  if (tileIdx < kStrategicTileCount) {
    byteOffset = tileIdx * 0x24;
    do {
      int thisRegion = GetCityRegionIdAtTileIndex(tileIdx);
      int dir4region = GetCityRegionIdAtTileIndex(GetNeighborTileIndexOnMap108x60(tileIdx, 4));
      int dir5region = GetCityRegionIdAtTileIndex(GetNeighborTileIndexOnMap108x60(tileIdx, 5));

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

  int t3 = 0;
  int off3 = 0;
  do {
    int rThis = GetCityRegionIdAtTileIndex(t3);
    int dir1region = GetCityRegionIdAtTileIndex(GetNeighborTileIndexOnMap108x60(t3, 1));
    int dir2region = GetCityRegionIdAtTileIndex(GetNeighborTileIndexOnMap108x60(t3, 2));

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
      for (; t3 < kStrategicTileCount; t3 += 1) {
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

namespace {

const int kMapWidth = 0x6c;         // 108 columns
const int kMapHeight = 0x3c;        // 60 rows
const int kTileStride = 0x24;       // 36 bytes / tile
const int kTileGridBytes = 0x38f40; // 6480 * 0x24
const int kRegionIdBias = 0x17;     // tile[4] region id is biased by +0x17

// region id for the city-region tile at byte offset `off` in the grid (-1 if offset negative).
int TileRegionId(char* grid, int off) {
  if (off < 0) {
    return -1;
  }
  return static_cast<unsigned char>(grid[off + 4]) - kRegionIdBias;
}

} // namespace

// FUNCTION: IMPERIALISM 0x0052cae0
void TMapMaker::BuildOverlaySpanRecordsFromQuadBorderLinks() {
  SeaSegmentStretch& seg = g_regionBorderLinkTable;
  SeapointStretch& quad = g_seapointQuadTable;

  // Reset the output segment table.
  if (seg.data != NULL) {
    free(seg.Detach());
  }

  unsigned int i = 0;
  if (quad.count == 0) {
    return;
  }
  do {
    bool isInvalid = quad[i].coord00 == -1;
    if (isInvalid) {
      ++i;
      continue;
    }
    quad[i];
    quad[i];
    unsigned int j = i + 1;
    unsigned int bestPrimary = 0xffffffff;
    unsigned int bestSecondary = 0xffffffff;
    if (j < static_cast<unsigned int>(quad.count)) {
      do {
        Seapoint* a = &quad[i];
        Seapoint* b = &quad[j];
        bool sameEdge = a->lo04 == b->lo04 && a->hi08 == b->hi08;
        if (sameEdge) {
          int dirDelta = ((b->f0c - a->f0c) + 6) % 6;
          bool isPrimaryDirection = dirDelta >= 2 && dirDelta <= 4;
          if (isPrimaryDirection) {
            if (bestPrimary == 0xffffffff) {
              bestPrimary = j;
            } else {
              Seapoint* pa = &quad[i];
              Seapoint* pb = &quad[j];
              int rowDelta = pa->coord00 / 0xd8 - pb->coord00 / 0xd8;
              if (rowDelta < 0) {
                rowDelta = -rowDelta;
              }
              int colDelta = ((pa->coord00 % 0xd8 - pb->coord00 % 0xd8) + 0xd8) % 0xd8;
              if (0x6c < colDelta) {
                colDelta = 0xd7 - colDelta;
              }
              float candidateDist = static_cast<float>(
                  sqrt(static_cast<double>(colDelta * colDelta * rowDelta * rowDelta)));
              if ((&quad[bestPrimary])->WrappedDeltaMetric((&quad[i])) > candidateDist) {
                bestPrimary = j;
              }
            }
          } else if (bestPrimary == 0xffffffff) {
            if (bestSecondary == 0xffffffff) {
              bestSecondary = j;
            } else {
              float candidateDist = static_cast<float>((&quad[j])->WrappedDeltaMetric((&quad[i])));
              if ((&quad[bestSecondary])->WrappedDeltaMetric((&quad[i])) > candidateDist) {
                bestSecondary = j;
              }
            }
          }
        }
        ++j;
      } while (j < static_cast<unsigned int>(quad.count));
    }
    if (bestPrimary == 0xffffffff) {
      bestPrimary = bestSecondary;
    }
    if (bestPrimary == 0xffffffff) {
      Seapoint* p = (&quad[i]);
      p->coord00 = -1;
      p->hi08 = -1;
      p->lo04 = -1;
    } else {
      SeaSegment tmp;
      tmp.InitFromPoints((&quad[bestPrimary]), (&quad[i]));
      stretch<SeaSegment>* out = &seg;
      out->Add(tmp);
      Seapoint* pi = (&quad[i]);
      pi->coord00 = -1;
      pi->hi08 = -1;
      pi->lo04 = -1;
      Seapoint* pm = (&quad[bestPrimary]);
      pm->coord00 = -1;
      pm->hi08 = -1;
      pm->lo04 = -1;
    }
  } while (i < static_cast<unsigned int>(quad.count));
}

// FUNCTION: IMPERIALISM 0x0052d1f0
void TMapMaker::ReindexContiguousCityRegionIds() {
  short labels[kStrategicTileCount];

  // Phase 1: seed a label per tile.
  char* tile = mapTileGrid;
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
    ++i;
    tile += 0x24;
    ++p;
  } while (i < kStrategicTileCount);

  int newCount = 0;
  do {
    // Assign the next compacted id to the first tile carrying each old label value.
    int remaining = cityRegionCount;
    int assigned = 0;
    if (remaining > 0) {
      int label = -2;
      do {
        int j = 0;
        short* pj = labels;
        do {
          if (label == *pj) {
            labels[j] = static_cast<short>(newCount);
            ++newCount;
            ++assigned;
            break;
          }
          ++j;
          ++pj;
        } while (j < kStrategicTileCount);
        --label;
        --remaining;
      } while (remaining != 0);
    }

    if (assigned == 0) {
      // Write the compacted ids back into the tiles and store the new count.
      unsigned int off = 0;
      short* pw = labels;
      do {
        char* t = mapTileGrid + off;
        if (*t == kStrategicTerrainWater) {
          t[4] = static_cast<char>(*pw) + '\x17';
        }
        off += 0x24;
        ++pw;
      } while (off < 0x38f40);
      cityRegionCount = newCount;
      return;
    }

    int changed;
    do {
      int j = 0;
      short* pj = labels;
      changed = 0;
      do {
        if (*pj < -1) {
          for (int direction = 0; direction < 6; ++direction) {
            int neighbor = GetNeighborTileIndexOnMap108x60(j, direction);
            if (-1 < neighbor && -1 < labels[neighbor]) {
              if (GetCityRegionIdAtTileIndex(j) == GetCityRegionIdAtTileIndex(neighbor)) {
                *pj = labels[neighbor];
                ++changed;
                break;
              }
            }
          }
        }
        ++j;
        ++pj;
      } while (j < kStrategicTileCount);
    } while (changed != 0);
  } while (true);
}

// FUNCTION: IMPERIALISM 0x0052d4b0
int TMapMaker::RepairOrphanedTileValuesFromNeighbors(short* tileValues) {
  int repairedCount = 0;
  int tileIndex = 0;
  int byteOffset = 0;
  short* cursor = tileValues;

  do {
    if (*cursor < -1) {
      int direction = 0;
      do {
        int neighbor = GetNeighborTileIndexOnMap108x60(tileIndex, direction);
        if (-1 < neighbor && -1 < tileValues[neighbor]) {
          int ownClass;
          char* ownRecord;
          if (byteOffset < 0 || (ownRecord = mapTileGrid + byteOffset, *ownRecord != '\x05')) {
            ownClass = -1;
          } else {
            ownClass = ownRecord[4] - 0x17;
          }

          char* neighborRecord = mapTileGrid + neighbor * 0x24;
          int neighborClass;
          if (*neighborRecord == '\x05') {
            neighborClass = neighborRecord[4] - 0x17;
          } else {
            neighborClass = -1;
          }

          if (ownClass == neighborClass) {
            *cursor = tileValues[neighbor];
            ++repairedCount;
            break;
          }
        }
        ++direction;
      } while (direction < 6);
    }
    byteOffset += 0x24;
    ++tileIndex;
    ++cursor;
  } while (byteOffset <= 0x38f3f);

  return repairedCount;
}

// FUNCTION: IMPERIALISM 0x0052d6b0
int TMapMaker::AssignSequentialValuesToRegionPlaceholders(short* tileValues, int* nextValue) {
  int regionOrdinal = 0;
  int assignedCount = 0;

  if (0 < cityRegionCount) {
    int placeholder = -2;
    do {
      int tileIndex = 0;
      short* cursor = tileValues;
      do {
        if (placeholder == *cursor) {
          tileValues[tileIndex] = static_cast<short>(*nextValue);
          ++assignedCount;
          *nextValue = *nextValue + 1;
          break;
        }
        ++tileIndex;
        ++cursor;
      } while (tileIndex < kStrategicTileCount);
      ++regionOrdinal;
      --placeholder;
    } while (regionOrdinal < cityRegionCount);
  }

  return assignedCount;
}

// FUNCTION: IMPERIALISM 0x0052d750
void TMapMaker::MergeSmallCityRegionsAndCompactIds() {
  int* tileCounts = new int[cityRegionCount];
  if (tileCounts == NULL) {
    FailNilPointerWithAssert("D:\\Ambit\\Cross\\UMapper.cpp", 0x11c5);
  }
  char* mergedFlags = new char[cityRegionCount];
  if (mergedFlags == NULL) {
    FailNilPointerWithAssert("D:\\Ambit\\Cross\\UMapper.cpp", 0x11c8);
  }

  for (int r = cityRegionCount - 1; r >= 0; --r) {
    tileCounts[r] = 0;
    mergedFlags[r] = 0;
  }

  // Phase 1: count city-region tiles per region id.
  for (int off = 0; off < kTileGridBytes; off += kTileStride) {
    if (mapTileGrid[off] == kStrategicTerrainWater) {
      ++tileCounts[TileRegionId(mapTileGrid, off)];
    }
  }

  int region = cityRegionCount;
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

      for (unsigned int li = 0; li < static_cast<unsigned int>(g_regionBorderLinkTable.Count());
           ++li) {
        SeaSegment* link = &g_regionBorderLinkTable[li];
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
        link = &g_regionBorderLinkTable[li];

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

      bool unresolved = false;
      if (mergeTarget == -1) {
        if (tileCounts[region] < 7) {
          int tileIdx = 0;
          for (int off = 0; off < kTileGridBytes && mergeTarget == -1;
               off += kTileStride, ++tileIdx) {
            char* grid = mapTileGrid;
            if (grid[off] != kStrategicTerrainWater || TileRegionId(grid, off) != region) {
              continue;
            }
            for (int dir = 0; dir < 6; ++dir) {
              int col =
                  tileIdx % kMapWidth + ((tileIdx / kMapWidth & 1) ? g_hexColOffsetOddRow[dir]
                                                                   : g_hexColOffsetEvenRow[dir]);
              int row = tileIdx / kMapWidth + g_hexRowOffset[dir];
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
              char* nTile = grid + neighbor * kTileStride;
              if (*nTile != kStrategicTerrainWater) {
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
          if (mapTileGrid[off] == kStrategicTerrainWater &&
              TileRegionId(mapTileGrid, off) == region) {
            mapTileGrid[off + 4] = static_cast<char>(mergeTarget) + kRegionIdBias;
          }
        }
        if (static_cast<int>(bestLink) >= 0) {
          SeaSegmentStretch& t = g_regionBorderLinkTable;
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
        for (unsigned int li = 0; li < static_cast<unsigned int>(g_regionBorderLinkTable.Count());
             ++li) {
          SeaSegment* link = &g_regionBorderLinkTable[li];
          if (link->BorderRegionA() == region) {
            link = &g_regionBorderLinkTable[li];
            link->BorderRegionA() = static_cast<short>(mergeTarget);
          }
          link = &g_regionBorderLinkTable[li];
          if (link->BorderRegionB() == region) {
            link = &g_regionBorderLinkTable[li];
            link->BorderRegionB() = static_cast<short>(mergeTarget);
          }
        }
      }
    }

    // Phase 3: if this region ended up empty, compact by swapping in the last active region.
    if (tileCounts[region] == 0) {
      int last = cityRegionCount - 1;
      cityRegionCount = last;
      tileCounts[region] = tileCounts[last];
      mergedFlags[region] = mergedFlags[cityRegionCount];
      for (int off = 0; off < kTileGridBytes; off += kTileStride) {
        if (mapTileGrid[off] == kStrategicTerrainWater &&
            TileRegionId(mapTileGrid, off) == cityRegionCount) {
          mapTileGrid[off + 4] = static_cast<char>(regionByte) + kRegionIdBias;
        }
      }
      for (unsigned int li = 0; li < static_cast<unsigned int>(g_regionBorderLinkTable.Count());
           ++li) {
        SeaSegment* link = &g_regionBorderLinkTable[li];
        if (link->BorderRegionA() == cityRegionCount) {
          link = &g_regionBorderLinkTable[li];
          link->BorderRegionA() = static_cast<short>(regionByte);
        }
        link = &g_regionBorderLinkTable[li];
        if (link->BorderRegionB() == cityRegionCount) {
          link = &g_regionBorderLinkTable[li];
          link->BorderRegionB() = static_cast<short>(regionByte);
        }
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x0052e350
void TMapMaker::RebuildUMapperRouteRecordsAndActiveMapRects() {
  SeaSegmentStretch& links = g_regionBorderLinkTable;

  // --- Pass 1: collapse degenerate links, count the live ones ---
  int liveCount = 0;
  unsigned int i = 0;
  for (i = 0; i < static_cast<unsigned int>(links.Count()); ++i) {
    if (links.At(i)->attrBySide[0] == links.At(i)->attrBySide[1]) {
      SeaSegment* rec = links.At(i);
      rec->attrBySide[1] = -1;
      rec->y1 = 0;
      rec->y0 = 0;
      rec->x1 = 0;
      rec->x0 = 0;
      rec->attrBySide[0] = -1;
      rec->coord1 = -1;
      rec->coord0 = -1;
    }
    if (!LinkIsEmpty(links.At(i))) {
      ++liveCount;
    }
  }

  g_pActiveMapOrderContext->AllocateRouteNodeStateBufferByCount(static_cast<short>(liveCount));

  // --- Pass 2: emit a CRect route record per live link ---
  short routeIndex = 0;
  for (i = 0; i < static_cast<unsigned int>(links.Count()); ++i) {
    if (!LinkIsEmpty(links.At(i))) {
      if (links.At(i)->attrBySide[0] == -1 || links.At(i)->attrBySide[1] == -1) {
        if (g_bOverlayRouteRebuildAssertSuppressed == 0) {
          TemporarilyClearAndRestoreUiInvalidationFlag(kUMapperPath, 0x128f);
        }
      }
    }
    if (!LinkIsEmpty(links.At(i))) {
      SeaSegment* rec = &links[i];
      CRect rect(rec->x0, rec->y0, rec->x1, rec->y1);
      g_pActiveMapOrderContext->routeSegments[routeIndex] = rect;
      ++routeIndex;
    }
  }

  g_pActiveMapOrderContext->InitializeMapActionContextsForNationCountUsingCostField(
      cityRegionCount);

  // --- Pass 3: wire mutual primary-neighbour adjacency between each link's two contexts ---
  int k = 0;
  for (k = 0; k < links.Count(); ++k) {
    if (LinkIsEmpty(links.At(k))) {
      continue;
    }
    SeaSegment* rec = &links[k];
    TZone* contextHi =
        g_pActiveMapOrderContext->GetMapActionContextEntryByIndex(rec->attrBySide[1]);
    TZone* contextLo =
        g_pActiveMapOrderContext->GetMapActionContextEntryByIndex(rec->attrBySide[0]);
    contextLo->AppendUniquePrimaryNeighbor(contextHi);
    TZone* backLo = g_pActiveMapOrderContext->GetMapActionContextEntryByIndex(
        links[static_cast<unsigned int>(k)].attrBySide[0]);
    TZone* backHi = g_pActiveMapOrderContext->GetMapActionContextEntryByIndex(
        links[static_cast<unsigned int>(k)].attrBySide[1]);
    backHi->AppendUniquePrimaryNeighbor(backLo);
  }

  PopulatePortZoneAdjacencyToNearbyCityContexts();
  RegenerateAllMapActionContextStatusCodes();
}

// FUNCTION: IMPERIALISM 0x0052e840
bool TMapMaker::ErrorCheck() {
  EraseZones(0);
  bool failed = false;
  signed char* cell = &regionClassGrid[0][0];
  for (int remaining = 0; remaining < 0x195; ++remaining) {
    if (*cell == -1) {
      *cell = 100;
      failed = true;
    } else if (*cell == -9) {
      *cell = -1;
    }
    ++cell;
  }
  return failed;
}

// FUNCTION: IMPERIALISM 0x0052e890
void TMapMaker::EraseZones(long coarseIndex) {
  regionClassGrid[0][coarseIndex] = -9;
  int direction;
  for (direction = 0; direction < 6; ++direction) {
    int neighbor = GetAdjacentRegionGridCell(coarseIndex, direction);
    if (neighbor != -1 && regionClassGrid[0][neighbor] == -1) {
      EraseZones(neighbor);
    }
  }
}

// FUNCTION: IMPERIALISM 0x0052e900
void TMapMaker::TargetValidationSucceeded() {
  signed char* grid = &regionClassGrid[0][0];
  for (int cell = 0; cell < 0x195; ++cell) {
    if (grid[cell] == 0x64) {
      int cur = cell;
      for (;;) {
        int next = GetAdjacentRegionGridCell(cur, 4);
        grid[cur] = grid[next];
        if (grid[next] == -1) {
          break;
        }
        cur = next;
      }
    }
  }
}
