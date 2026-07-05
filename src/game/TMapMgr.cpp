#include "game/TMapMgr.h"

#include "game/CString.h"
#include "game/TCountry.h"
#include "game/TSortedList.h"
#include "game/TMinor.h"
#include "game/TCivUnit.h"
#include "game/TPortZone.h"
#include "game/TOcean.h"
#include "game/TZone.h"
#include "game/global_data_tables.h"
#include "game/TTradeMgr.h"
#include "game/TTechMgr.h"

void EnsurePortZoneForTile(short nTileIndex);
void RemovePortZoneByTile(short nTileIndex);
short TraceTerrainFlowToNearestSeaTile(short tileIndex);
void NormalizeWrappedMapCoord217x60(short* xCoord, short* yCoord);

// FUNCTION: IMPERIALISM 0x004a4190
TMilitaryUnit* TMapMgr::ValidateGridIndexRange0To17F(short index) {
  if (index < 0 || index >= 0x180) {
    return nullptr;
  }
  return cityScoreTable[index].stationedUnitChain98;
}

// Hex direction (0-6) from sourceTile to destTile on the 0x6c(108)-wide map, via each tile's
// doubled-hex-coordinate ("diagonal") position: diag = (row & 1) + col*2. Ghidra's decompile
// hand-emulates row/col with a magic-multiply division and a sign-correcting parity dance for
// negative row indices; map tile indices are never negative in practice, so that correction
// collapses to a plain `row & 1` here (a faithful simplification, not a shortcut of behavior).

// SYNTHETIC: IMPERIALISM 0x0050e2f0
// TMapMgr::CreateObject

// SYNTHETIC: IMPERIALISM 0x0050e3b0
// TMapMgr::GetRuntimeClass

IMPLEMENT_DYNCREATE(TMapMgr, TObject)

TMapMgr::TMapMgr() {}

TMapMgr::~TMapMgr() {}

void TMapMgr::Free() {}

void TMapMgr::ReadFrom(TStream* stream) {}

void TMapMgr::WriteTo(TStream* stream) {}

undefined TMapMgr::WrapperFor_AllocateWithFallbackHandler_At0050e8b0() {
  return 0;
}

undefined TMapMgr::BuildOrLoadGlobalMapStateForSession(CString param_1, char* param_2) {
  return 0;
}

undefined TMapMgr::LoadPoliticalMapRegionSubtypeTableFromResourceStream() {
  return 0;
}

undefined TMapMgr::UpdateTilePrimaryAndSecondaryNeighborLinksByPriority(int param_1) {
  return 0;
}

undefined TMapMgr::UpdateTileNeighborBorderInfluenceCounters(short param_1, short param_2) {
  return 0;
}

undefined TMapMgr::InitializeTileNeighborConnectionMaskIfNeeded(int param_1) {
  return 0;
}

undefined TMapMgr::OrphanLeaf_NoCall_Ins01_00511610(short param_1) {
  return 0;
}

undefined TMapMgr::TMapMaker_EnsureRegionClassHasSubtype3And4AssignmentsWithRng() {
  return 0;
}

undefined TMapMgr::TMapMaker_EnsureMapDataStreamOpenedAndMaybeTickUiProgress() {
  return 0;
}

undefined TMapMgr::DispatchTurnEvent7DDForActiveNation() {
  return 0;
}

undefined
TMapMgr::ForwardComputeRepresentativeTileIndexForTerrainTypeWithWrapBias(undefined4 param_1) {
  ComputeRepresentativeTileIndexForTerrainTypeWithWrapBias(static_cast<short>(param_1), 1);
  return 0;
}

undefined TMapMgr::TMapMaker_CheckTerrainTypePairReachabilityByRegionClassMask(short param_1,
                                                                               short param_2) {
  return 0;
}

undefined TMapMgr::IsNodeTypeLinkUnavailableAndNoActiveMapActionContext(int param_1,
                                                                        short param_2) {
  return 0;
}

undefined TMapMgr::IsShiftKeyDown() {
  return 0;
}

undefined TMapMgr::IsAltKeyDown() {
  return 0;
}

undefined TMapMgr::OrphanCallChain_C3_I43_00513170(short param_1) {
  return 0;
}

undefined TMapMgr::DispatchFormationEntryActionsAndMaybeCreateTurnEvent12(short param_1,
                                                                          undefined4 param_2) {
  return 0;
}

undefined TMapMgr::SetTileOwnerAndInvalidateNeighborState(short param_1, short param_2) {
  return 0;
}

undefined TMapMgr::OrphanCallChain_C1_I29_005135a0(short param_1, char param_2) {
  return 0;
}

undefined TMapMgr::OrphanLeaf_NoCall_Ins14_00513610(short param_1, short param_2) {
  return 0;
}

byte TMapMgr::GetTileCivilianWorkOrderCostClassNibble(short nTileIndex, char fUseHighNibble) {
  return 0;
}

undefined TMapMgr::OrphanLeaf_NoCall_Ins35_005136a0(short param_1, char param_2, byte param_3,
                                                    char param_4) {
  return 0;
}

undefined TMapMgr::OrphanLeaf_NoCall_Ins37_00513720(short param_1, char param_2, int param_3) {
  return 0;
}

undefined TMapMgr::SetHexAdjacencyDirectionFlagsForTilePair(short param_1, short param_2) {
  return 0;
}

undefined TMapMgr::OrphanLeaf_NoCall_Ins18_00514310(short param_1, short param_2) {
  return 0;
}

undefined TMapMgr::OrphanLeaf_NoCall_Ins31_00514360(short param_1, short param_2, short param_3) {
  return 0;
}

void TMapMgr::FloodFillTileRegionMarker(short nTileIndex, short nOwnerNationId) {}

int TMapMgr::QueueDepotConstructionOrder(int* pMapContext, short nTileIndex, short nNationId,
                                         undefined2 param_4) {
  return 0;
}

void TMapMgr::QueuePortConstructionOrder(int* pMapContext, short nTileIndex, short nNationId,
                                         undefined2 param_4) {}

void TMapMgr::SetProvinceCapitalTileFlagBit08(short nProvinceId) {}

void TMapMgr::SetTileTransportFlagsTo0x37AndRefreshNeighbors(short nTileIndex) {}

undefined TMapMgr::WrapperFor_IsValidSecondaryNationHomeTileCandidate_At00514dc0(short param_1) {
  return 0;
}

undefined TMapMgr::OrphanLeaf_NoCall_Ins15_00514e40(short param_1) {
  return 0;
}

undefined TMapMgr::OrphanLeaf_NoCall_Ins28_00514e80() {
  return 0;
}

undefined TMapMgr::OrphanLeaf_NoCall_Ins09_00514ef0() {
  return 0;
}

undefined TMapMgr::OrphanCallChain_C5_I115_00514f20(int param_1) {
  return 0;
}

undefined TMapMgr::OrphanCallChain_C1_I159_005150e0(int* param_1, short param_2) {
  return 0;
}

undefined TMapMgr::WrapperFor_LookupOrderCompatibilityMatrixValue_At00515330(int param_1) {
  return 0;
}

undefined TMapMgr::WrapperFor_LookupOrderCompatibilityMatrixValue_At00515460(int param_1) {
  return 0;
}

undefined TMapMgr::OrphanLeaf_NoCall_Ins83_005155c0(int param_1) {
  return 0;
}

undefined TMapMgr::MarkType5NeighborTilesUnavailableByNationCapability(int param_1) {
  return 0;
}

undefined TMapMgr::OrphanLeaf_NoCall_Ins69_00515890(int param_1) {
  return 0;
}

undefined TMapMgr::MarkSeedNeighborTilesUnavailableByCapabilityMaskProfileA(int param_1) {
  return 0;
}

undefined TMapMgr::MarkSeedNeighborTilesUnavailableByCapabilityMaskProfileB(int param_1) {
  return 0;
}

undefined TMapMgr::ApplyUnitMovementClassForTileIfValid(int param_1) {
  return 0;
}

undefined TMapMgr::OrphanRetStub_00515de0() {
  return 0;
}

undefined TMapMgr::SetRegionTileSubtypeAndRefreshNeighborFlags(int param_1, int param_2) {
  return 0;
}

undefined TMapMgr::OrphanLeaf_NoCall_Ins27_00516090(int param_1, int param_2) {
  return 0;
}

undefined TMapMgr::OrphanLeaf_NoCall_Ins18_00516100(int param_1) {
  return 0;
}

undefined TMapMgr::OrphanLeaf_NoCall_Ins14_00516150(short param_1) {
  return 0;
}

undefined TMapMgr::OrphanLeaf_NoCall_Ins12_005161a0(short param_1) {
  return 0;
}

undefined TMapMgr::OrphanLeaf_NoCall_Ins10_005161e0(short param_1) {
  return 0;
}

undefined TMapMgr::OrphanLeaf_NoCall_Ins09_00516220(short param_1) {
  return 0;
}

undefined TMapMgr::OrphanLeaf_NoCall_Ins464_00516260(char param_1, char param_2) {
  return 0;
}

undefined TMapMgr::OrphanCallChain_C3_I41_00517410(char param_1) {
  return 0;
}

undefined TMapMgr::OrphanCallChain_C3_I49_00517480() {
  return 0;
}

undefined TMapMgr::OrphanVtableAssignStub_00517520() {
  return 0;
}

undefined TMapMgr::OrphanLeaf_NoCall_Ins55_00517540(short param_1, short param_2) {
  return 0;
}

undefined TMapMgr::OrphanCallChain_C1_I46_00517600(short param_1) {
  return 0;
}

undefined TMapMgr::OrphanLeaf_NoCall_Ins04_005176a0(int param_1) {
  return 0;
}

undefined TMapMgr::OrphanLeaf_NoCall_Ins04_005176c0(int param_1) {
  return 0;
}

undefined TMapMgr::GetMapImprovementTierBucketOffset(short param_1) {
  return 0;
}

undefined TMapMgr::ApplyMapImprovementSelectionState(void* param_1) {
  return 0;
}

undefined TMapMgr::GetMapImprovementSpriteBaseOffset(short param_1, char param_2, char param_3) {
  return 0;
}

undefined TMapMgr::GetMapImprovementTileOffsetFromClass(char param_1) {
  return 0;
}

undefined TMapMgr::GetMapImprovementTileSpriteOffset(short param_1) {
  return 0;
}

undefined TMapMgr::OrphanLeaf_NoCall_Ins08_005178c0() {
  return 0;
}

// Recompute a tile's per-direction adjacency masks (bytes 0x0a/0x0b) and its sprite-variant
// code (byte 2) from its six hex neighbors, using the map-gen LCG for random tie-breaks.
// Branches on terrain type (byte 0): type 5 = water/coast, else land. Returns the last EAX
// value (a tile-byte pointer or an incidental scalar); callers ignore it.
// FUNCTION: IMPERIALISM 0x00510210
unsigned char* TMapMgr::UpdateMapTileAdjacencyMasksAndVariantForTile(uint param_1) {
  short tileIndex = (short)param_1;
  short neighbors[6];
  unsigned char* result;

  if (terrainStateTable[tileIndex].pad00[0] != 5) {
    ComputeHexNeighborTileIndices(param_1, neighbors, hexNeighborWrapHorizontally20);
    result = reinterpret_cast<unsigned char*>(terrainStateTable);
    for (int d = 0; d < 6; ++d) {
      if (neighbors[d] != -1 &&
          terrainStateTable[neighbors[d]].gateFlag == terrainStateTable[tileIndex].gateFlag) {
        terrainStateTable[tileIndex].adjacencyMaskA0a |=
            (unsigned char)g_hexDirectionBitMasks_00696e40[d];
      }
    }
    if (terrainStateTable[tileIndex].pad00[0] == 2) {
      for (int d = 0; d < 6; ++d) {
        if (neighbors[d] != -1) {
          if (terrainStateTable[neighbors[d]].pad00[0] == 3) {
            terrainStateTable[tileIndex].adjacencyMaskB0b |=
                (unsigned char)g_hexDirectionBitMasks_00696e40[d];
          }
          if (terrainStateTable[neighbors[d]].pad00[0] == 2) {
            terrainStateTable[tileIndex].adjacencyMaskA0a |=
                (unsigned char)g_hexDirectionBitMasks_00696e40[d];
          }
        }
      }
    }
    if (terrainStateTable[tileIndex].pad00[0] == 3) {
      for (int d = 0; d < 6; ++d) {
        if (neighbors[d] != -1 && terrainStateTable[neighbors[d]].pad00[0] == 2) {
          terrainStateTable[tileIndex].adjacencyMaskB0b |=
              (unsigned char)g_hexDirectionBitMasks_00696e40[d];
        }
      }
    }
    if (terrainStateTable[tileIndex].pad00[0] == 3) {
      g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
      result = 0;
      if ((g_mapGenLcgState_006a38e8 >> 0xc & 1) != 0) {
        result = reinterpret_cast<unsigned char*>(terrainStateTable);
        terrainStateTable[tileIndex].pad00[1] = 1;
      }
    }
    if (terrainStateTable[tileIndex].gateFlag == 0xb) {
      for (short d = 0; d < 6; ++d) {
        if (terrainStateTable[neighbors[d]].gateFlag == 0xb) {
          short next = (d == 5) ? 0 : (short)(d + 1);
          short prev = (d != 0) ? (short)(d - 1) : 5;
          unsigned char prevTag = terrainStateTable[neighbors[prev]].gateFlag;
          if (prevTag == 0xb) {
          check_next_run:
            if (terrainStateTable[neighbors[next]].gateFlag == 0xb) {
              terrainStateTable[tileIndex].pad00[1] = 1;
            } else {
              if (prevTag != 0xb) {
                goto check_next_only;
              }
              if (terrainStateTable[neighbors[next]].gateFlag != 0xb) {
                terrainStateTable[tileIndex].pad00[1] = 2;
              }
            }
          } else if (terrainStateTable[neighbors[next]].gateFlag == 0xb) {
            if (prevTag == 0xb) {
              goto check_next_run;
            }
          check_next_only:
            if (terrainStateTable[neighbors[next]].gateFlag == 0xb) {
              terrainStateTable[tileIndex].pad00[1] = 3;
            }
          } else {
            terrainStateTable[tileIndex].pad00[1] = 0;
          }
        }
      }
    }
    unsigned char variant = terrainStateTable[tileIndex].roadFlag;
    if (variant != 0) {
      if ((variant & 0x80) == 0) {
        int resolved = ResolveMapTileVariantSpriteFromAdjacencyState(param_1);
        terrainStateTable[tileIndex].roadFlag = (unsigned char)resolved;
      } else {
        terrainStateTable[tileIndex].roadFlag = variant & 0x7f;
      }
    }
    char finalVariant = terrainStateTable[tileIndex].roadFlag;
    result = reinterpret_cast<unsigned char*>((unsigned int)(unsigned char)finalVariant);
    if (0x1a < finalVariant && finalVariant < 0x2b) {
      terrainStateTable[tileIndex].roadFlag = finalVariant - 0x10;
      return reinterpret_cast<unsigned char*>((unsigned int)(unsigned char)(finalVariant - 0x10));
    }
  } else {
    ComputeHexNeighborTileIndices(param_1, neighbors, hexNeighborWrapHorizontally20);
    unsigned int lcg = g_mapGenLcgState_006a38e8;
    for (int d = 0; d < 6; ++d) {
      if (neighbors[d] != -1 && terrainStateTable[neighbors[d]].pad00[0] != 5) {
        terrainStateTable[tileIndex].adjacencyMaskB0b |=
            (unsigned char)g_hexDirectionBitMasks_00696e40[d];
        g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
        lcg = g_mapGenLcgState_006a38e8;
        if ((g_mapGenLcgState_006a38e8 >> 0xc & 1) != 0) {
          terrainStateTable[tileIndex].pad00[1] |=
              (unsigned char)g_hexDirectionBitMasks_00696e40[d];
          lcg = g_mapGenLcgState_006a38e8;
        }
      }
    }
    result = reinterpret_cast<unsigned char*>(terrainStateTable);
    if (terrainStateTable[tileIndex].adjacencyMaskB0b != 0) {
      unsigned char variant = terrainStateTable[tileIndex].roadFlag;
      result = &terrainStateTable[tileIndex].roadFlag;
      if (variant == 0) {
        return result;
      }
      if ((variant & 0x80) == 0) {
        int resolved = ResolveMapTileVariantSpriteFromAdjacencyState(param_1);
        terrainStateTable[tileIndex].roadFlag = (unsigned char)resolved;
        return reinterpret_cast<unsigned char*>(resolved);
      }
      *result = variant & 0x7f;
      return result;
    }
    if (neighbors[4] == -1) {
      return result;
    }
    if (terrainStateTable[neighbors[4]].pad00[1] != 0) {
      return result;
    }
    if (((neighbors[5] == -1) || (terrainStateTable[neighbors[5]].pad00[1] == 0)) &&
        ((neighbors[0] == -1) || (terrainStateTable[neighbors[0]].pad00[1] == 0))) {
      g_mapGenLcgState_006a38e8 = lcg * 0x15a4e35 + 1;
      unsigned int roll = g_mapGenLcgState_006a38e8 >> 0xc & 0x7fff;
      result = reinterpret_cast<unsigned char*>(roll / 100);
      if (3 < roll % 100) {
        return result;
      }
      g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
      terrainStateTable[tileIndex].pad00[1] =
          (unsigned char)((g_mapGenLcgState_006a38e8 >> 0xc) & 3) + 1;
      if (pendingRiverMouthTile22 != -1) {
        return result;
      }
      pendingRiverMouthTile22 = tileIndex;
      return reinterpret_cast<unsigned char*>(param_1 & 0xffff);
    }
    g_mapGenLcgState_006a38e8 = lcg * 0x15a4e35 + 1;
    unsigned int roll = g_mapGenLcgState_006a38e8 >> 0xc & 0x7fff;
    result = reinterpret_cast<unsigned char*>(roll / 100);
    if (7 < roll % 100) {
      return result;
    }
    char v;
    if (neighbors[5] != -1) {
      v = terrainStateTable[neighbors[5]].pad00[1];
      if (v != 0) {
        terrainStateTable[tileIndex].pad00[1] = v + 1;
        v = terrainStateTable[tileIndex].pad00[1];
        result = &terrainStateTable[tileIndex].pad00[1];
        if (v != 0) {
          if (v < 5) {
            return result;
          }
          *result = 1;
          return result;
        }
        goto assign_river_mouth_one;
      }
    }
    if (neighbors[0] != -1) {
      terrainStateTable[tileIndex].pad00[1] = terrainStateTable[neighbors[0]].pad00[1] + 1;
      v = terrainStateTable[tileIndex].pad00[1];
      result = &terrainStateTable[tileIndex].pad00[1];
      if ((v == 0) || (4 < v)) {
      assign_river_mouth_one:
        *result = 1;
        return result;
      }
    }
  }
  return result;
}

// FUNCTION: IMPERIALISM 0x005108d0
int TMapMgr::ResolveMapTileVariantSpriteFromAdjacencyState(int nTileIndex) {
  short sTileIndex = (short)nTileIndex;
  int iTileIndex = (int)sTileIndex;
  int result = 0;
  TTerrainStateRecordView* tiles = terrainStateTable;
  TTerrainStateRecordView* cur = &tiles[iTileIndex];
  if (cur->pad00[0] != 5) {
    char code = cur->roadFlag;
    switch (code) {
    case 1:
      return 0xb;
    case 2:
      return 0xc;
    case 3:
      code = tiles[(short)(sTileIndex - 1)].roadFlag;
      if (code == 0xf || code == 0x1f || code == 0x11 || code == 0x21 || code == 0x13 ||
          code == 0x23 || code == 0x15 || code == 0x25 || code == 0x2c || code == 0x34) {
        return 0xd;
      }
      code = tiles[(short)(sTileIndex - 1)].roadFlag;
      if (code != 0x10 && code != 0x20 && code != 0x12 && code != 0x22 && code != 0x14 &&
          code != 0x24 && code != 0x16 && code != 0x26 && code != 0x2d && code != 0x35) {
        g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
        return (g_mapGenLcgState_006a38e8 >> 0xc & 1) + 0xd;
      }
      return 0xe;
    case 4:
      if (iTileIndex % 0x6c != 0x6b) {
        g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
        return 0x10 - (unsigned int)((g_mapGenLcgState_006a38e8 >> 0xc & 1) != 0);
      }
      code = tiles[(short)(sTileIndex - 0x6b)].roadFlag;
      if (code == 0xd || code == 0x1d || code == 0x11 || code == 0x21 || code == 0x12 ||
          code == 0x22 || code == 0x17 || code == 0x27 || code == 0x30 || code == 0x38) {
        return 0xf;
      }
      code = tiles[(short)(sTileIndex - 0x6b)].roadFlag;
      if (code == 0xe || code == 0x1e || code == 0x13 || code == 0x23 || code == 0x14 ||
          code == 0x24 || code == 0x18 || code == 0x28 || code == 0x31 || code == 0x39) {
        return 0x10;
      }
      g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
      return (g_mapGenLcgState_006a38e8 >> 0xc & 1) + 0xf;
    case 5:
      code = tiles[(short)(sTileIndex - 1)].roadFlag;
      if (code == 0xf || code == 0x1f || code == 0x11 || code == 0x21 || code == 0x13 ||
          code == 0x23 || code == 0x15 || code == 0x25 || code == 0x2c || code == 0x34) {
        if (iTileIndex % 0x6c != 0x6b) {
          g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
          return 0x12 - (unsigned int)((g_mapGenLcgState_006a38e8 >> 0xc & 1) != 0);
        }
        code = tiles[(short)(sTileIndex - 0x6b)].roadFlag;
        if (code != 0xd && code != 0x1d && code != 0x11 && code != 0x21 && code != 0x12 &&
            code != 0x22 && code != 0x17 && code != 0x27 && code != 0x30 && code != 0x38) {
          return 0x12;
        }
        return 0x11;
      }
      code = tiles[(short)(sTileIndex - 1)].roadFlag;
      if (code == 0x10 || code == 0x20 || code == 0x12 || code == 0x22 || code == 0x14 ||
          code == 0x24 || code == 0x16 || code == 0x26 || code == 0x2d || code == 0x35) {
        if (iTileIndex % 0x6c != 0x6b) {
        lcg_variant_0x14:
          g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
          return 0x14 - (unsigned int)((g_mapGenLcgState_006a38e8 >> 0xc & 1) != 0);
        }
        code = tiles[(short)(sTileIndex - 0x6b)].roadFlag;
      } else {
        if (iTileIndex % 0x6c != 0x6b) {
          goto lcg_variant_0x14;
        }
        code = tiles[(short)(sTileIndex - 0x6b)].roadFlag;
      }
      if (code != 0xd && code != 0x1d && code != 0x11 && code != 0x21 && code != 0x12 &&
          code != 0x22 && code != 0x17 && code != 0x27 && code != 0x30 && code != 0x38) {
        return 0x14;
      }
      return 0x13;
    case 6:
      if (iTileIndex % 0x6c != 0x6b) {
        g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
        return 0x16 - (unsigned int)((g_mapGenLcgState_006a38e8 >> 0xc & 1) != 0);
      }
      code = tiles[(short)(sTileIndex - 0x6b)].roadFlag;
      if (code == 0xd || code == 0x1d || code == 0x11 || code == 0x21 || code == 0x12 ||
          code == 0x22 || code == 0x17 || code == 0x27 || code == 0x30 || code == 0x38) {
        return 0x15;
      }
      code = tiles[(short)(sTileIndex - 0x6b)].roadFlag;
      if (code == 0xe || code == 0x1e || code == 0x13 || code == 0x23 || code == 0x14 ||
          code == 0x24 || code == 0x18 || code == 0x28 || code == 0x31 || code == 0x39) {
        return 0x16;
      }
      g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
      return (g_mapGenLcgState_006a38e8 >> 0xc & 1) + 0x15;
    case 7:
      code = tiles[(short)(nTileIndex - 1)].roadFlag;
      if (code == 0xf || code == 0x1f || code == 0x11 || code == 0x21 || code == 0x13 ||
          code == 0x23 || code == 0x15 || code == 0x25 || code == 0x2c || code == 0x34) {
        return 0x17;
      }
      if (CheckTileVariantCodeMembershipSetB(nTileIndex - 1) == 0) {
        g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
        return (g_mapGenLcgState_006a38e8 >> 0xc & 1) + 0x17;
      }
      return 0x18;
    case 8:
      return 0x19;
    case 9:
      return 0x1a;
    case 10:
      return 0x2b;
    case 0xb:
      if (iTileIndex % 0x6c != 0x6b) {
        g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
        return 0x2d - (unsigned int)((g_mapGenLcgState_006a38e8 >> 0xc & 1) != 0);
      }
      if (CheckTileVariantCodeMembershipSetC(nTileIndex - 0x6b) == 0) {
        if (CheckTileVariantCodeMembershipSetD(nTileIndex - 0x6b) == 0) {
          g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
          return (g_mapGenLcgState_006a38e8 >> 0xc & 1) + 0x2c;
        }
        return 0x2d;
      }
      return 0x2c;
    case 0xc:
      return 0x2e;
    case 0xd:
      return 0x2f;
    case 0xe:
      if (CheckTileVariantCodeMembershipSetA(nTileIndex - 1) != 0) {
        return 0x30;
      }
      if (CheckTileVariantCodeMembershipSetB(nTileIndex - 1) == 0) {
        g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
        return (g_mapGenLcgState_006a38e8 >> 0xc & 1) + 0x30;
      }
      return 0x31;
    case 0xf:
      return 0x32;
    }
  } else {
    char subtype = cur->roadFlag;
    if (subtype != 0) {
      switch (subtype) {
      case 0x10:
        return 0x37;
      case 0x11:
        if (CheckTileVariantCodeMembershipSetA(nTileIndex - 1) != 0) {
          return 0x38;
        }
        if (CheckTileVariantCodeMembershipSetB(nTileIndex - 1) == 0) {
          g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
          return (g_mapGenLcgState_006a38e8 >> 0xc & 1) + 0x38;
        }
        return 0x39;
      case 0x12:
        result = 0x3a;
        break;
      case 0x13:
        return 0x33;
      case 0x14:
        if (iTileIndex % 0x6c != 0x6b) {
          g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
          return 0x35 - (unsigned int)((g_mapGenLcgState_006a38e8 >> 0xc & 1) != 0);
        }
        if (CheckTileVariantCodeMembershipSetC(nTileIndex - 0x6b) == 0) {
          if (CheckTileVariantCodeMembershipSetD(nTileIndex - 0x6b) == 0) {
            g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
            return (g_mapGenLcgState_006a38e8 >> 0xc & 1) + 0x34;
          }
          return 0x35;
        }
        return 0x34;
      case 0x15:
        return 0x36;
      }
    }
  }
  return result;
}

// FUNCTION: IMPERIALISM 0x005112f0
char TMapMgr::CheckTileVariantCodeMembershipSetA(short tileIndex) {
  char code = terrainStateTable[tileIndex].roadFlag;
  if (code == 0xf || code == 0x1f || code == 0x11 || code == 0x21 || code == 0x13 || code == 0x23 ||
      code == 0x15 || code == 0x25 || code == 0x2c || code == 0x34) {
    return 1;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x00511360
char TMapMgr::CheckTileVariantCodeMembershipSetB(short tileIndex) {
  char code = terrainStateTable[tileIndex].roadFlag;
  if (code == 0x10 || code == 0x20 || code == 0x12 || code == 0x22 || code == 0x14 ||
      code == 0x24 || code == 0x16 || code == 0x26 || code == 0x2d || code == 0x35) {
    return 1;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x005113d0
char TMapMgr::CheckTileVariantCodeMembershipSetC(short tileIndex) {
  char code = terrainStateTable[tileIndex].roadFlag;
  if (code == 0xd || code == 0x1d || code == 0x11 || code == 0x21 || code == 0x12 || code == 0x22 ||
      code == 0x17 || code == 0x27 || code == 0x30 || code == 0x38) {
    return 1;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x00511440
char TMapMgr::CheckTileVariantCodeMembershipSetD(short tileIndex) {
  char code = terrainStateTable[tileIndex].roadFlag;
  if (code == 0xe || code == 0x1e || code == 0x13 || code == 0x23 || code == 0x14 || code == 0x24 ||
      code == 0x18 || code == 0x28 || code == 0x31 || code == 0x39) {
    return 1;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x00512b50
void TMapMgr::ComputeHexNeighborTileIndices(short tileIndex, short* neighborTiles,
                                            char wrapHorizontally) {
  unsigned int row = static_cast<unsigned int>(static_cast<int>(tileIndex) / 0x6c);
  int col = static_cast<int>(tileIndex) % 0x6c;
  unsigned int rowParity = row & 1U;
  short sVar4;
  if (rowParity == 0) {
    sVar4 = static_cast<short>(tileIndex + -0x6d);
    neighborTiles[2] = static_cast<short>(tileIndex + 0x6c);
    neighborTiles[0] = static_cast<short>(tileIndex + -0x6c);
    neighborTiles[3] = static_cast<short>(tileIndex + 0x6b);
    neighborTiles[1] = static_cast<short>(tileIndex + 1);
    neighborTiles[4] = static_cast<short>(tileIndex + -1);
  } else {
    sVar4 = static_cast<short>(tileIndex + -0x6c);
    neighborTiles[2] = static_cast<short>(tileIndex + 0x6d);
    neighborTiles[0] = static_cast<short>(tileIndex + -0x6b);
    neighborTiles[3] = static_cast<short>(tileIndex + 0x6c);
    neighborTiles[1] = static_cast<short>(tileIndex + 1);
    neighborTiles[4] = static_cast<short>(tileIndex + -1);
  }
  neighborTiles[5] = sVar4;
  if (col < 0x6b) {
    if (col == 0) {
      if (wrapHorizontally == '\0') {
        neighborTiles[4] = static_cast<short>(tileIndex + 0x6b);
        if (rowParity == 0) {
          neighborTiles[5] = static_cast<short>(tileIndex + -1);
          neighborTiles[3] = static_cast<short>(tileIndex + 0xd7);
        }
      } else {
        neighborTiles[4] = -1;
        neighborTiles[3] = -1;
        neighborTiles[5] = -1;
      }
    }
  } else if (wrapHorizontally == '\0') {
    neighborTiles[1] = static_cast<short>(tileIndex + -0x6b);
    if (rowParity != 0) {
      neighborTiles[2] = static_cast<short>(tileIndex + 1);
      neighborTiles[0] = static_cast<short>(tileIndex + -0xd7);
    }
  } else {
    neighborTiles[1] = -1;
    neighborTiles[0] = -1;
    neighborTiles[2] = -1;
  }
  if (0x3a < static_cast<int>(row)) {
    neighborTiles[2] = -1;
    neighborTiles[3] = -1;
    return;
  }
  if (row == 0) {
    neighborTiles[0] = -1;
    neighborTiles[5] = -1;
  }
}

// FUNCTION: IMPERIALISM 0x00512cc0
short TMapMgr::GetWrappedHexNeighborTileIndexByDirection(short tileIndex, short direction) {
  int tile = static_cast<int>(tileIndex);
  int row = tile / 0x6c;
  int col = tile % 0x6c;
  int rowParity = row & 1;
  int scaledCol = rowParity + col * 2;

  int dir = static_cast<int>(direction);
  if (dir < 0) {
    dir += 6;
  } else if (dir > 5) {
    dir -= 6;
  }

  scaledCol += static_cast<int>(g_Build_Hex_Area_LookupTable_00696E70[dir]);

  if (static_cast<short>(direction) < 0) {
    dir = static_cast<int>(static_cast<short>(direction)) + 6;
  } else if (static_cast<short>(direction) > 5) {
    dir = static_cast<int>(static_cast<short>(direction)) - 6;
  }

  short wrappedRow = static_cast<short>(row);
  wrappedRow = static_cast<short>(wrappedRow + g_Build_Hex_Area_LookupTable_00696E80[dir]);

  if (scaledCol > 0xd7) {
    scaledCol -= 0xd9;
  } else if (scaledCol < 0) {
    scaledCol += 0xd8;
  }

  if (wrappedRow < 0) {
    wrappedRow = 0;
  } else if (wrappedRow > 0x3b) {
    wrappedRow = 0x3b;
  }

  int halfCol = scaledCol;
  int halfColSign = halfCol >> 0x1f;
  halfCol = (halfCol - halfColSign) >> 1;
  int result = halfCol + static_cast<int>(wrappedRow) * 0x6c;
  if (result < 0 || result >= 0x1950) {
    return -1;
  }
  return static_cast<short>(result);
}
// FUNCTION: IMPERIALISM 0x00512dd0
extern "C" short __cdecl GetHexDirectionBetweenTiles(short sourceTile, short destTile) {
  short rowFrom = sourceTile / 0x6c;
  short colFrom = sourceTile % 0x6c;
  short diagFrom = (rowFrom & 1) + colFrom * 2;
  short rowTo = destTile / 0x6c;
  short colTo = destTile % 0x6c;
  short diagTo = (rowTo & 1) + colTo * 2;

  if ((diagFrom < diagTo) && (diagTo < diagFrom + 0xd7)) {
    if (rowTo <= rowFrom) {
      return (rowFrom <= rowTo) ? 1 : 0;
    }
    return 2;
  }
  if (((diagFrom <= diagTo) || (diagTo + 0xd7 <= diagFrom)) && (diagTo < diagFrom + 0xd7)) {
    return (rowTo <= rowFrom) ? 5 : 3;
  }
  if (rowTo <= rowFrom) {
    return (rowTo < rowFrom) ? 5 : 4;
  }
  return 3;
}

// FUNCTION: IMPERIALISM 0x00513120
void NormalizeWrappedMapCoord217x60(short* xCoord, short* yCoord) {
  short x = *xCoord;
  if (x < 216) {
    if (x >= 0)
      goto clampY;
    x = x + 216;
  } else {
    x = x - 217;
  }
  *xCoord = x;
clampY:
  if (*yCoord < 0) {
    *yCoord = 0;
    return;
  }
  if (*yCoord > 59)
    *yCoord = 59;
}

// FUNCTION: IMPERIALISM 0x00513200
int TMapMgr::SetTileTransportFlags(short nTileIndex, unsigned short wTileTransportFlags) {
  char* terrainTileBytes = *reinterpret_cast<char**>(reinterpret_cast<unsigned char*>(this) + 0xc);
  int tileByteOffset = static_cast<int>(nTileIndex) * 0x24;
  unsigned char* flagByte =
      reinterpret_cast<unsigned char*>(terrainTileBytes + 0x1c + tileByteOffset);
  if (((*flagByte & 4) != 0) && ((wTileTransportFlags & 4) == 0)) {
    RemovePortZoneByTile(nTileIndex);
  }
  *reinterpret_cast<unsigned short*>(flagByte) = wTileTransportFlags;
  if ((wTileTransportFlags & 4) != 0) {
    EnsurePortZoneForTile(nTileIndex);
  }
  if ((wTileTransportFlags & 3) != 0) {
    *flagByte = static_cast<unsigned char>(*flagByte | 0x20);
  }
  return reinterpret_cast<int>(flagByte);
}

namespace {

const int kGlobalMapTileCount = 0x1950;

short FindReachableRecruitSpawnTileRecursiveImpl(TMapMgr* mapState, short tileIndex,
                                                 short ownerNationTag, char allowActiveFlag2) {
  TTerrainStateRecordView* tile = &mapState->terrainStateTable[tileIndex];
  if (tile->recruitSearchVisited0e != 0) {
    return -1;
  }
  tile->recruitSearchVisited0e = 1;
  if (tile->ownerNationTag04 != ownerNationTag) {
    return -1;
  }

  TUnit* civilianOrder = tile->firstCivilianOrder20;
  bool noMatchingCivilian = civilianOrder == 0;
  if (!noMatchingCivilian) {
    while (civilianOrder->field_18 != ownerNationTag) {
      civilianOrder = civilianOrder->nextOnTile;
      if (civilianOrder == 0) {
        noMatchingCivilian = true;
        break;
      }
    }
  }
  if (noMatchingCivilian) {
    if ((tile->activeFlags1c & 2) == 0) {
      return tileIndex;
    }
    if (allowActiveFlag2 != 0) {
      return tileIndex;
    }
  }

  short neighborTiles[6];
  TMapMgr::ComputeHexNeighborTileIndices(tileIndex, neighborTiles,
                                         mapState->hexNeighborWrapHorizontally20);
  for (short neighborIndex = 0; neighborIndex < 6; ++neighborIndex) {
    if (neighborTiles[neighborIndex] == -1) {
      continue;
    }
    short foundTile = FindReachableRecruitSpawnTileRecursiveImpl(
        mapState, neighborTiles[neighborIndex], ownerNationTag, allowActiveFlag2);
    if (foundTile != -1) {
      return foundTile;
    }
  }
  return -1;
}

} // namespace

// FUNCTION: IMPERIALISM 0x00513ed0
byte TMapMgr::CheckTileProspectingDiscoveryCandidate(short nTileIndex) {
  byte fHasDiscoveryCandidate;
  int nResourceSlotIndex;
  char cTileResourceCode;

  fHasDiscoveryCandidate = 0;
  if (terrainStateTable[nTileIndex].resourceTypeByEdge[0] != '\0') {
    nResourceSlotIndex = 0;
    do {
      if (fHasDiscoveryCandidate != 0) {
        return fHasDiscoveryCandidate;
      }
      cTileResourceCode =
          terrainStateTable[nTileIndex].resourceTypeByEdge[(short)nResourceSlotIndex];
      if ((((cTileResourceCode == '\x03') || (cTileResourceCode == '\x04')) ||
           (cTileResourceCode == '\x15')) ||
          ((cTileResourceCode == '\x16') ||
           ((cTileResourceCode == '\x06') &&
            (g_pCityOrderCapabilityState->hasProductionOrder193 != '\0')))) {
        fHasDiscoveryCandidate = 1;
      }
      nResourceSlotIndex = nResourceSlotIndex + 1;
    } while (nResourceSlotIndex < 2);
  }
  return fHasDiscoveryCandidate;
}

// Hex-direction bit flags (1 << dir). Ground truth reads this via
// `(char*)g_Build_Hex_Area_LookupTable_00696E80 + N`, but that offset lands well past that
// global's own declared 6-short extent (0x696e80..0x696e8b) -- it's really a distinct,
// separately-emitted 6-entry const table that happens to sit shortly after it in the
// original .rdata layout, not guaranteed to hold in a freshly linked recompile. Modeled here
// as its own bounds-safe table instead of pointer-walking off an unrelated global.
static const unsigned char kHexDirectionBitMask[6] = {1, 2, 4, 8, 16, 32};

// FUNCTION: IMPERIALISM 0x00513ff0
void TMapMgr::ApplyRailSectionEndpointDirectionFlags(short sourceTile, short destTile,
                                                     short ownerNation) {
  (void)ownerNation;
  short dir = GetHexDirectionBetweenTiles(sourceTile, destTile);
  terrainStateTable[sourceTile].railFlags17 += kHexDirectionBitMask[dir];
  terrainStateTable[destTile].railFlags17 += kHexDirectionBitMask[(dir + 3) % 6];
}

// Rescind counterpart to ApplyRailSectionEndpointDirectionFlags above: same bit-flag table,
// subtracts instead of adding -- matches HandleCivilianReportDecision's "rescind a rail
// section" refund path.
// FUNCTION: IMPERIALISM 0x00514080
void TMapMgr::ApplyEngineerRailCostDeltaForConnectedTiles(short tileA, short tileB,
                                                          short ownerNation) {
  (void)ownerNation;
  short dir = GetHexDirectionBetweenTiles(tileA, tileB);
  terrainStateTable[tileA].railFlags17 -= kHexDirectionBitMask[dir];
  terrainStateTable[tileB].railFlags17 -= kHexDirectionBitMask[(dir + 3) % 6];
}

// FUNCTION: IMPERIALISM 0x00514250
TCivUnit* TMapMgr::GetTileUnitEntryByOwner(short tileIndex, short nationId) {
  TCivUnit* entry = GetFirstCivilianOrderOnTile(tileIndex);
  while ((entry != nullptr) && (entry->field_18 != nationId)) {
    entry = static_cast<TCivUnit*>(entry->nextOnTile);
  }
  return entry;
}

// FUNCTION: IMPERIALISM 0x00514290
short TMapMgr::ResolveTileOwnerNationCodeNormalized(int tileIndex) {
  short ownerCode = cityScoreTable[tileIndex].ownerNationCode00;
  if (ownerCode == -1) {
    return ownerCode;
  }
  TCountry* nation = g_apTerrainTypeDescriptorTable[ownerCode];
  if (nation->needLevelByNation[1] < 200) {
    return ownerCode;
  }
  short code = nation->needLevelByNation[1];
  if (code < 200) {
    if (code < 100) {
      return nation->needLevelByNation[0];
    }
    return code - 100;
  }
  return code - 200;
}

// FUNCTION: IMPERIALISM 0x00514c80
short TMapMgr::FindReachableRecruitSpawnTileWithVisitedReset(short startTileIndex,
                                                             char allowActiveFlag2) {
  signed char ownerNationTag = terrainStateTable[startTileIndex].ownerNationTag04;
  for (int tileIndex = 0; tileIndex < kGlobalMapTileCount; ++tileIndex) {
    terrainStateTable[tileIndex].recruitSearchVisited0e = 0;
  }
  return FindReachableRecruitSpawnTileRecursiveImpl(this, startTileIndex, ownerNationTag,
                                                    allowActiveFlag2);
}

// FUNCTION: IMPERIALISM 0x00515db0
void TMapMgr::ClearPerTileByte0FForAllMapTiles() {
  for (int tileIndex = 0; tileIndex < kGlobalMapTileCount; ++tileIndex) {
    terrainStateTable[tileIndex].perTileVisitedFlag0f = 0;
  }
}

// Verified against 0x0053e7bf's callsite (TDefendProvinceMission::
// ComputeCrossNationSupportVectorScore): despite the Ghidra-provisional name, this
// checks whether regionIndex appears in nodeContext's adjacent-region list, not
// anything about movement classes -- kept the name per Hard Rule 6 (no clean
// replacement name yet), documented here instead.
// FUNCTION: IMPERIALISM 0x00515e50
char TMapMgr::TileHasMovementClassId(int nodeContext, int regionIndex) {
  const TGlobalMapCityScoreRecord& record = cityScoreTable[nodeContext];
  for (int i = 0; i < record.adjacentRegionCount08; ++i) {
    if (record.adjacentRegionIds0A[i] == regionIndex) {
      return 1;
    }
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x00515ec0
void TMapMgr::AssignSharedStringFromIndexedA8EntryNameField(int cityRecordIndex, CString* dest) {
  *dest = *reinterpret_cast<CString*>(reinterpret_cast<char*>(cityScoreTable) +
                                      cityRecordIndex * 0xa8 + 0xa4);
}

// FUNCTION: IMPERIALISM 0x005178f0
short TMapMgr::ComputeRepresentativeTileIndexForTerrainTypeWithWrapBias(short terrainType,
                                                                        char wrapBias) {
  char* tileTable = reinterpret_cast<char*>(terrainStateTable);
  char* cityTable = reinterpret_cast<char*>(cityScoreTable);
  unsigned int colSum = 0;
  int rowSum = 0;
  unsigned int tileCount = 0;
  int westCount = 0;
  unsigned int eastCount = 0;

  for (int tileIndex = 0; tileIndex < 0x1950; ++tileIndex) {
    int tileByteOffset = tileIndex * 0x24;
    char terrainTag = tileTable[tileByteOffset + 4];
    if (terrainTag != terrainType) {
      continue;
    }
    char includeTile = 1;
    if (terrainType < 0x17 && g_apTerrainTypeDescriptorTable[terrainType] != 0 &&
        g_apTerrainTypeDescriptorTable[terrainType]->ownerNationSlot != static_cast<short>(-1)) {
      short nationSlot = g_apTerrainTypeDescriptorTable[terrainType]->ownerNationSlot;
      short tileCityLink = *reinterpret_cast<short*>(tileTable + tileByteOffset + 0x14);
      char tileCityByte = cityTable[0xa3 + static_cast<int>(tileCityLink) * 0xa8];
      short nationTileCityLink = *reinterpret_cast<short*>(tileTable + nationSlot * 0x24 + 0x14);
      char nationCityByte = cityTable[0xa3 + static_cast<int>(nationTileCityLink) * 0xa8];
      if (tileCityByte != nationCityByte) {
        includeTile = 0;
      }
    }
    if (includeTile == 0) {
      continue;
    }
    int tileCol = tileIndex % 0x6c;
    if (tileCol < 0x19) {
      westCount = westCount + 1;
    }
    if (tileCol > 0x53) {
      eastCount = eastCount + 1;
    }
    colSum = colSum + static_cast<unsigned int>(tileCol);
    rowSum = rowSum + tileIndex / 0x6c;
    tileCount = tileCount + 1;
  }

  char applyWrapBias = 0;
  if (westCount >= 1 && static_cast<int>(eastCount) >= 1) {
    applyWrapBias = 1;
    if (wrapBias == 0) {
      tileCount = 0;
      rowSum = 0;
      colSum = 0;
      for (int tileIndex = 0; tileIndex < 0x1950; ++tileIndex) {
        if (tileTable[tileIndex * 0x24 + 4] != terrainType) {
          continue;
        }
        int tileCol = tileIndex % 0x6c;
        if (tileCol < 0x36 && westCount < static_cast<int>(eastCount)) {
          tileCol = 0x6b;
        }
        if (tileCol > 0x36 && static_cast<int>(eastCount) < westCount) {
          tileCol = 0;
        }
        colSum = colSum + static_cast<unsigned int>(tileCol);
        rowSum = rowSum + tileIndex / 0x6c;
        tileCount = tileCount + 1;
      }
    } else if (wrapBias != 0) {
      colSum = colSum + static_cast<unsigned int>(westCount * 0x6c);
    }
  }

  if (tileCount != 0) {
    return static_cast<short>(((static_cast<int>(colSum) / static_cast<int>(tileCount)) % 0x6c) +
                              (rowSum / static_cast<int>(tileCount)) * 0x6c);
  }

  short fallbackTile = -1;
  if (terrainType < 0x17 && g_apTerrainTypeDescriptorTable[terrainType] != 0) {
    TSortedList* ownedRegions = g_apTerrainTypeDescriptorTable[terrainType]->ownedRegionList;
    if (ownedRegions != 0 && ownedRegions->GetCountSlot48() > 0) {
      int lastMatch = -1;
      for (int tileIndex = 0; tileIndex < 0x1950; ++tileIndex) {
        if (static_cast<signed char>(tileTable[tileIndex * 0x24 + 4]) == terrainType) {
          lastMatch = tileIndex;
        }
      }
      fallbackTile = static_cast<short>(lastMatch);
    }
  }
  return fallbackTile;
}

static const unsigned int kAddrTerrainFlowTypeRemapTable = 0x0065c632;
static const unsigned int kAddrTerrainFlowDirectionTable = 0x0065c668;

namespace {

short FindSeaTileForPortZoneCreation(short portTileIndex, signed char nationSeed) {
  short seaTileIndex = -1;
  short tileWalkIndex = portTileIndex;
  for (int attempt = 0; attempt < 6; ++attempt) {
    short candidateTile = TMapMgr::StepHexTileIndexByDirectionWithWrapRules(
        portTileIndex, static_cast<short>(tileWalkIndex % 6));
    ++tileWalkIndex;
    if (candidateTile == -1) {
      continue;
    }
    TTerrainStateRecordView& candidateRecord = g_pGlobalMapState->terrainStateTable[candidateTile];
    if (candidateRecord.pad00[0] != 5) {
      continue;
    }
    char allNeighborsMatchNation = 1;
    for (int neighborDirection = 0; neighborDirection < 6; ++neighborDirection) {
      short neighborTile = g_pGlobalMapState->GetWrappedHexNeighborTileIndexByDirection(
          candidateTile, static_cast<short>(neighborDirection));
      if (neighborTile == -1) {
        continue;
      }
      signed char neighborNation =
          g_pGlobalMapState->terrainStateTable[neighborTile].ownerNationTag04;
      if (neighborNation < 0x17 && neighborNation != nationSeed) {
        allNeighborsMatchNation = 0;
        break;
      }
    }
    if (allNeighborsMatchNation != 0) {
      seaTileIndex = candidateTile;
      break;
    }
  }
  if (seaTileIndex == -1) {
    seaTileIndex = TraceTerrainFlowToNearestSeaTile(portTileIndex);
  }
  return seaTileIndex;
}

void LinkPortZoneToContextIfMissing(TZone* portZone, TZone* contextZone) {
  if (contextZone == 0 || portZone == 0) {
    return;
  }
  int entryIndex = 0;
  int primarySize = portZone->primaryNeighbors.GetSize();
  if (primarySize != 0) {
    for (; entryIndex < primarySize; ++entryIndex) {
      if (portZone->primaryNeighbors.GetAt(entryIndex) == contextZone) {
        return;
      }
    }
  }
  portZone->AppendZonePointerToPrimaryArray(contextZone);
  contextZone->AppendZonePointerToSecondaryArray(portZone);
}

} // namespace

// FUNCTION: IMPERIALISM 0x00517c30
char TMapMgr::AreNationsBorderLinked(int nationA, int nationB) {
  TSortedList* regionList = g_apTerrainTypeDescriptorTable[nationA]->ownedRegionList;
  if (regionList->GetCountSlot48() < 1) {
    return 0;
  }
  int ordinal = 1;
  do {
    int regionId = regionList->GetIntByOrdinalSlot24(ordinal);
    TGlobalMapCityScoreRecord* record = &cityScoreTable[regionId];
    char found = 0;
    int neighborCount = record->adjacentRegionCount08;
    if (neighborCount > 0) {
      for (int neighborIndex = 0; neighborIndex < neighborCount; ++neighborIndex) {
        short neighborRegionId = record->adjacentRegionIds0A[neighborIndex];
        if (cityScoreTable[neighborRegionId].ownerNationCode00 == nationB) {
          found = 1;
          break;
        }
      }
    }
    if (found != 0) {
      return 1;
    }
    ++ordinal;
  } while (ordinal <= regionList->GetCountSlot48());
  return 0;
}

// FUNCTION: IMPERIALISM 0x00518470
void TMapMgr::ApplyJoinEmpireMode0GlobalDiplomacyReset(int nationSlot) {
  signed char* tileBase = tileOwnershipTable;
  signed char* tagCursor = tileBase + 4;
  int tileIndex = 0;
  do {
    if (*tagCursor >= 7 && *tagCursor <= 0x16) {
      signed char* ownerByte = tileOwnershipTable + static_cast<short>(tileIndex) * 0x24 + 0x18;
      if (*ownerByte == nationSlot) {
        *ownerByte = -1;
      }
    }
    tagCursor += 0x24;
    ++tileIndex;
  } while (tileIndex < 0x1950);
}

// FUNCTION: IMPERIALISM 0x005184e0
short __stdcall GetProvinceUnitOrderWeight(short provinceId) {
  // Retail body ignores the province and returns the constant weight 0x21 (33);
  // mission scoring converts it to float for the accumulate dampening factor.
  (void)provinceId;
  return 0x21;
}

// FUNCTION: IMPERIALISM 0x00518960
void TMapMgr::SetRegionDevelopmentStageByte(short regionId, unsigned char stage) {
  cityScoreTable[regionId].developmentStage = stage;
}

// Verified against the disassembly: returns TRUE as soon as it finds a linked
// region whose terrainStateTable activeFlags1c bit 2 is SET, and FALSE if
// linkedRegionCount<=0 -- the OPPOSITE of what the Ghidra-provisional name
// implies ("all clear" would return true only when none are set). Kept the name
// per Hard Rule 6 pending a confident replacement; documented the real behavior
// here instead of renaming on a single read.
// FUNCTION: IMPERIALISM 0x00518a20
char TMapMgr::AreAllLinkedEntriesTerrainFlagBit2Clear(int regionIndex) {
  const TGlobalMapCityScoreRecord& record = cityScoreTable[regionIndex];
  for (int i = 0; i < record.linkedRegionCount; ++i) {
    unsigned char flags = terrainStateTable[record.linkedRegionIds[i]].activeFlags1c;
    if ((flags >> 2) & 1) {
      return 1;
    }
  }
  return 0;
}

// Sum the developer purchase cost of the two edge resources on a tile: for each real
// resource type (< 0x11) weight it via the trade manager's proposal-weight metric (slot
// 0x13) scaled x20; fixed surcharges for the special types 0x15 (10000) and 0x16 (4000).
// (Ghidra mis-attributed this to TCivToolbar; `this->field0c` is TMapMgr::terrainStateTable.)
// FUNCTION: IMPERIALISM 0x00518b40
int TMapMgr::CalculateDeveloperTilePurchaseCost(short nTileIndex) {
  int total = 0;
  int edge = 0;
  do {
    short resourceType = terrainStateTable[nTileIndex].resourceTypeByEdge[edge];
    if (resourceType != -1) {
      if (resourceType < 0x11) {
        total = total +
                g_pNationInteractionStateManager->QueryProposalWeightSlot4C(resourceType) * 0x14;
      } else if (resourceType == 0x15) {
        total = total + 10000;
      } else if (resourceType == 0x16) {
        total = total + 4000;
      }
    }
    edge = edge + 1;
  } while (edge < 2);
  return total;
}

// FUNCTION: IMPERIALISM 0x00518bd0
void TMapMgr::MarkAdjacentHexOrderDirectionAndSelectTile(int tileIndex, int contextArg, char flag) {
  (void)tileIndex;
  (void)contextArg;
  (void)flag;
}

namespace {
// Indexed by (gateFlag - 1) for terrainStateTable gateFlag values in [1,15]; groups a
// linked region's gate type into one of the buckets tallied by
// ClassifyCityGateTerrainComposition below (bucket 7, gateFlag 14, scores nothing).
const unsigned char kGateFlagScoreBucket[15] = {0, 0, 0, 0, 1, 1, 2, 2, 2, 3, 4, 2, 2, 7, 2};
} // namespace

// FUNCTION: IMPERIALISM 0x00519010
int TMapMgr::ClassifyCityGateTerrainComposition(int cityIndex) {
  const TGlobalMapCityScoreRecord& city = cityScoreTable[cityIndex];
  if ((terrainStateTable[city.ownerNationSlot].activeFlags1c & 1) != 0) {
    return 3;
  }

  int tallyA = 0;
  int tallyB = 0;
  int tallyC = 0;
  for (int i = 0; i < city.linkedRegionCount; ++i) {
    short gateFlag = terrainStateTable[city.linkedRegionIds[i]].gateFlag;
    if (gateFlag < 1 || gateFlag > 15) {
      continue;
    }
    switch (kGateFlagScoreBucket[gateFlag - 1]) {
    case 0:
      ++tallyB;
      break;
    case 1:
      tallyB += 2;
      break;
    case 2:
      tallyA += 2;
      break;
    case 3:
      tallyA += 4;
      break;
    case 4:
      tallyC += 6;
      break;
    default:
      break;
    }
  }

  if (tallyC > tallyA && tallyC > tallyB) {
    return 2;
  }
  return tallyA > tallyB ? 1 : 0;
}

// FUNCTION: IMPERIALISM 0x0055e360
short TMapMgr::StepHexTileIndexByDirectionWithWrapRules(short tileIndex, short direction) {
  int col = static_cast<int>(tileIndex) % 0x6c;
  unsigned int row = static_cast<unsigned int>(static_cast<int>(tileIndex) / 0x6c);
  if ((direction == 4) || ((direction > 2) && ((row & 1U) == 0U))) {
    col = col - 1;
    if (static_cast<short>(col) < 0) {
      if (g_pGlobalMapState->hexNeighborWrapHorizontally20 != 0) {
        return -1;
      }
      col = 0x6b;
    }
  } else if (((direction == 1) || ((direction < 3) && ((row & 1U) != 0U)))) {
    col = col + 1;
    if (col > 0x6b) {
      if (g_pGlobalMapState->hexNeighborWrapHorizontally20 != 0) {
        return -1;
      }
      col = 0;
    }
  }
  if ((direction == 5) || (direction == 0)) {
    if (static_cast<short>(row) - 1 < 0) {
      return -1;
    }
    row = row - 1U;
  } else if (((direction == 3) || (direction == 2)) &&
             (row = row + 1U, static_cast<short>(row) > 0x3b)) {
    return -1;
  }
  return static_cast<short>(col + static_cast<int>(row) * 0x6c);
}

// FUNCTION: IMPERIALISM 0x0055e550
bool TMapMgr::StepHexRowColByDirectionWithWrapRules(int* row, int* col, int direction) {
  if ((direction == 4) || ((direction > 2) && (((*row) & 1) == 0))) {
    int nextCol = *col - 1;
    *col = nextCol;
    if (nextCol < 0) {
      if (g_pGlobalMapState->hexNeighborWrapHorizontally20 != 0) {
        return false;
      }
      *col = 0x6b;
    }
  } else if ((direction == 1) || ((direction < 3) && (((*row) & 1) != 0))) {
    int nextCol = *col + 1;
    *col = nextCol;
    if (nextCol > 0x6b) {
      if (g_pGlobalMapState->hexNeighborWrapHorizontally20 != 0) {
        return false;
      }
      *col = 0;
    }
  }
  if ((direction == 5) || (direction == 0)) {
    int nextRow = *row - 1;
    *row = nextRow;
    if (nextRow < 0) {
      return false;
    }
  } else if ((direction == 3) || (direction == 2)) {
    int nextRow = *row + 1;
    *row = nextRow;
    if (nextRow > 0x3b) {
      return false;
    }
  }
  return true;
}

// FUNCTION: IMPERIALISM 0x00560470
void TMapMgr::AdvanceSpiralSearchStateAndStepHexCoordinates(HexSpiralSearchState* state) {
  int stepInRing = state->stepInRing + 1;
  state->stepInRing = stepInRing;
  if (state->ring <= stepInRing) {
    int direction = state->direction + 1;
    state->stepInRing = 0;
    state->direction = direction;
    if (direction > 5) {
      state->ring = state->ring + 1;
      state->direction = 0;
      TMapMgr::StepHexRowColByDirectionWithWrapRules(&state->row, &state->col, 4);
    }
  }
  TMapMgr::StepHexRowColByDirectionWithWrapRules(&state->row, &state->col, state->direction);
}

short TMapMgr::TileIndexFromRowCol(int row, int col) {
  if ((row < 0) || (row > 0x3b) || (col < 0) || (col > 0x6b)) {
    return -1;
  }
  return static_cast<short>(col + row * 0x6c);
}

// FUNCTION: IMPERIALISM 0x005635e0
void EnsurePortZoneForTile(short nTileIndex) {
  if (g_pGlobalMapState == 0) {
    return;
  }
  TTerrainStateRecordView* terrainTable = g_pGlobalMapState->terrainStateTable;
  int tileIndex = static_cast<int>(nTileIndex);
  if ((terrainTable[tileIndex].activeFlags1c & 1) == 0) {
    return;
  }
  signed char nationSeed = terrainTable[tileIndex].ownerNationTag04;
  if (TZone::FindPortZoneByTile(nTileIndex) != 0) {
    return;
  }

  TPortZone* portZone = TPortZone::CreateTPortZone();
  if (portZone == 0) {
    return;
  }
  portZone->field48 = static_cast<int>(nTileIndex);
  portZone->SetMapActionContextTargetTileAndRefreshMarkers(static_cast<int>(nationSeed), -1);
  portZone->field0c = tileIndex;
  portZone->GenerateZoneStatusCodeIfUnset();
  portZone->GenerateMapActionContextDisplayNameAndHeadline(0, 0);

  short seaTileIndex = FindSeaTileForPortZoneCreation(nTileIndex, nationSeed);
  TZone* linkedContext = g_pActiveMapOrderContext->GetLinkedZoneForSeaTile(seaTileIndex);
  LinkPortZoneToContextIfMissing(portZone, linkedContext);

  SetMapTileStateByteAndNotifyObserver(static_cast<int>(seaTileIndex), 3);
  portZone->field0c = static_cast<int>(seaTileIndex);
  portZone->field20 = portZone->GetActiveNationSlotTile();
}

// FUNCTION: IMPERIALISM 0x00563990
short TraceTerrainFlowToNearestSeaTile(short tileIndex) {
  if (g_pGlobalMapState == 0) {
    return -1;
  }
  TTerrainStateRecordView* terrainTable = g_pGlobalMapState->terrainStateTable;
  for (int flowVariant = 0; flowVariant < 2; ++flowVariant) {
    short flowType = static_cast<short>(terrainTable[tileIndex].roadFlag);
    if (flowType == 0) {
      return -1;
    }
    if (flowType > 0x1a && flowType < 0x2b) {
      flowType = static_cast<short>(flowType - 0x10);
    }
    if (flowType >= 0xb && flowType <= 0x1a) {
      flowType = *reinterpret_cast<const short*>(kAddrTerrainFlowTypeRemapTable + flowType * 2);
    } else if (flowType >= 0x2b && flowType <= 0x3a) {
      return -1;
    }

    short stepDirection = *reinterpret_cast<const short*>(kAddrTerrainFlowDirectionTable +
                                                          (flowVariant + flowType * 2) * 2);
    short walkTile = tileIndex;
    for (int stepCount = 0; stepCount < 100; ++stepCount) {
      walkTile = TMapMgr::StepHexTileIndexByDirectionWithWrapRules(walkTile, stepDirection);
      TTerrainStateRecordView& walkRecord = terrainTable[walkTile];
      if (walkRecord.pad00[0] == 5) {
        return walkTile;
      }

      short nextFlowType = static_cast<short>(walkRecord.roadFlag);
      if (nextFlowType == 0) {
        break;
      }
      if (nextFlowType > 0x1a && nextFlowType < 0x2b) {
        nextFlowType = static_cast<short>(nextFlowType - 0x10);
      }
      if (nextFlowType >= 0xb && nextFlowType <= 0x1a) {
        nextFlowType =
            *reinterpret_cast<const short*>(kAddrTerrainFlowTypeRemapTable + nextFlowType * 2);
      } else if (nextFlowType >= 0x2b && nextFlowType <= 0x3a) {
        break;
      }

      short preferredDirection = static_cast<short>((static_cast<int>(stepDirection) + 3) % 6);
      const short* directionPair =
          reinterpret_cast<const short*>(kAddrTerrainFlowDirectionTable + nextFlowType * 4);
      if (directionPair[0] == preferredDirection) {
        stepDirection = directionPair[1];
      } else if (directionPair[1] != preferredDirection) {
        break;
      } else {
        stepDirection = directionPair[0];
      }
    }
  }
  return -1;
}

// FUNCTION: IMPERIALISM 0x00564240
void RemovePortZoneByTile(short nTileIndex) {
  for (TZone* zone = TZone::GetFirstPortZone(); zone != 0; zone = zone->GetNextPortZone()) {
    if (static_cast<short>(zone->field0c) == nTileIndex || zone->field20 == nTileIndex ||
        static_cast<short>(static_cast<TPortZone*>(zone)->field48) == nTileIndex) {
      zone->Free();
      return;
    }
  }
}

char TMapMgr::CallMetricSlotC4(int regionIndex, int edgeIndex) {
  (void)regionIndex;
  (void)edgeIndex;
  return 0;
}

short TMapMgr::QueryIconStripXSlot110(int iconCode) {
  (void)iconCode;
  return 0;
}

void TMapMgr::NotifyCityRecordSlot12C(int cityRecordIndex) {
  (void)cityRecordIndex;
}

void TMapMgr::LinkRegionToNationSlot134(int regionId, int nationSlot) {
  (void)regionId;
  (void)nationSlot;
}
