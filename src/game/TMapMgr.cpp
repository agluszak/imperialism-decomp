#include "game/TMapMgr.h"

#include "game/CString.h"
#include "game/TArmyMgr.h"
#include "game/TCivMgr.h"
#include "game/TSimMgr.h"
#include "game/TViewMgr.h"
#include "game/TCountry.h"
#include "game/TSortedList.h"
#include "game/TMinor.h"
#include "game/TCivUnit.h"
#include "game/TMilitaryUnit.h"
#include "game/TPortZone.h"
#include "game/TOcean.h"
#include "game/TZone.h"
#include "game/global_data_tables.h"
#include "game/TTradeMgr.h"
#include "game/TTechMgr.h"
#include "game/TGreatPower.h"
#include "game/TTown.h"
#include "game/TDiplomacyMgr.h"
#include "game/ui_invalidation_guard.h"

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

// SYNTHETIC: IMPERIALISM 0x0050e460
// TMapMgr::`scalar deleting destructor'

// FUNCTION: IMPERIALISM 0x0050e490
TMapMgr::~TMapMgr() {}

// FUNCTION: IMPERIALISM 0x0050e510
void TMapMgr::Free() {
  delete[] terrainStateTable;
  delete[] cityScoreTable;
  delete this;
}

// FUNCTION: IMPERIALISM 0x0050e620
void TMapMgr::ReadFrom(TStream* stream) {
  TObject::ReadFrom(stream);
  stream->ReadBytes(&field6, 2);
  stream->ReadBytes(&field8, 1);
  stream->ReadBytes(&field9, 1);
  stream->ReadBytes(&cityScoreTotal, 4);
  stream->streamSlot70(&scenarioTagText1c, 0x20);
  hexNeighborWrapHorizontally20 = stream->streamSlot44();
  stream->ReadBytes(terrainStateTable, 0x38f40);
  int i;
  TGlobalMapCityScoreRecord* record = cityScoreTable;
  for (i = 0; i < 0x180; ++i, ++record) {
    stream->ReadBytes(record, 0xa4);
    stream->streamSlot70(&record->cityNameA4, 0x20);
  }
  for (i = 0; i < 0x1950; ++i) {
    terrainStateTable[i].firstCivilianOrder20 = nullptr;
  }
  for (i = 0; i < 0x180; ++i) {
    cityScoreTable[i].stationedUnitChain98 = nullptr;
  }
  field4 = 0;
  if (g_nSaveFormatVersion < 0x32) {
    for (i = 0; i < 0x1950; ++i) {
      terrainStateTable[i].perTileVisitedFlag0f = 0;
    }
  }
  if (g_nSaveFormatVersion > 0x32) {
    stream->ReadBytes(&pendingRiverMouthTile22, 2);
  } else {
    pendingRiverMouthTile22 = -1;
  }
}

// FUNCTION: IMPERIALISM 0x0050e7a0
void TMapMgr::WriteTo(TStream* stream) {
  TObject::WriteTo(stream);
  stream->WriteBytesSlot78(&field6, 2);
  stream->WriteBytesSlot78(&field8, 1);
  stream->WriteBytesSlot78(&field9, 1);
  stream->WriteBytesSlot78(&cityScoreTotal, 4);
  stream->streamSlotAc(&scenarioTagText1c);
  stream->streamSlot80(hexNeighborWrapHorizontally20);
  stream->WriteBytesSlot78(terrainStateTable, 0x38f40);
  TGlobalMapCityScoreRecord* record = cityScoreTable;
  for (int i = 0; i < 0x180; ++i, ++record) {
    stream->WriteBytesSlot78(record, 0xa4);
    stream->streamSlotAc(&record->cityNameA4);
  }
  stream->WriteBytesSlot78(&pendingRiverMouthTile22, 2);
}

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

// Recompute a tile's per-direction adjacency masks (bytes 0x0a/0x0b) and its sprite-variant
// code (byte 2) from its six hex neighbors, using the map-gen LCG for random tie-breaks.
// Branches on terrain type (byte 0): type 5 = water/coast, else land. Returns the last EAX
// value (a tile-byte pointer or an incidental scalar); callers ignore it.
// FUNCTION: IMPERIALISM 0x00510210
unsigned char* TMapMgr::UpdateMapTileAdjacencyMasksAndVariantForTile(uint param_1) {
  short tileIndex = (short)param_1;
  short neighbors[6];
  unsigned char* result;

  if (terrainStateTable[tileIndex].terrainType00 != 5) {
    ComputeHexNeighborTileIndices(param_1, neighbors, hexNeighborWrapHorizontally20);
    result = reinterpret_cast<unsigned char*>(terrainStateTable);
    for (int d = 0; d < 6; ++d) {
      if (neighbors[d] != -1 &&
          terrainStateTable[neighbors[d]].gateFlag == terrainStateTable[tileIndex].gateFlag) {
        terrainStateTable[tileIndex].adjacencyMaskA0a |=
            (unsigned char)g_hexDirectionBitMasks_00696e40[d];
      }
    }
    if (terrainStateTable[tileIndex].terrainType00 == 2) {
      for (int d = 0; d < 6; ++d) {
        if (neighbors[d] != -1) {
          if (terrainStateTable[neighbors[d]].terrainType00 == 3) {
            terrainStateTable[tileIndex].adjacencyMaskB0b |=
                (unsigned char)g_hexDirectionBitMasks_00696e40[d];
          }
          if (terrainStateTable[neighbors[d]].terrainType00 == 2) {
            terrainStateTable[tileIndex].adjacencyMaskA0a |=
                (unsigned char)g_hexDirectionBitMasks_00696e40[d];
          }
        }
      }
    }
    if (terrainStateTable[tileIndex].terrainType00 == 3) {
      for (int d = 0; d < 6; ++d) {
        if (neighbors[d] != -1 && terrainStateTable[neighbors[d]].terrainType00 == 2) {
          terrainStateTable[tileIndex].adjacencyMaskB0b |=
              (unsigned char)g_hexDirectionBitMasks_00696e40[d];
        }
      }
    }
    if (terrainStateTable[tileIndex].terrainType00 == 3) {
      g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
      result = 0;
      if ((g_mapGenLcgState_006a38e8 >> 0xc & 1) != 0) {
        result = reinterpret_cast<unsigned char*>(terrainStateTable);
        terrainStateTable[tileIndex].spriteVariantIndex01 = 1;
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
              terrainStateTable[tileIndex].spriteVariantIndex01 = 1;
            } else {
              if (prevTag != 0xb) {
                goto check_next_only;
              }
              if (terrainStateTable[neighbors[next]].gateFlag != 0xb) {
                terrainStateTable[tileIndex].spriteVariantIndex01 = 2;
              }
            }
          } else if (terrainStateTable[neighbors[next]].gateFlag == 0xb) {
            if (prevTag == 0xb) {
              goto check_next_run;
            }
          check_next_only:
            if (terrainStateTable[neighbors[next]].gateFlag == 0xb) {
              terrainStateTable[tileIndex].spriteVariantIndex01 = 3;
            }
          } else {
            terrainStateTable[tileIndex].spriteVariantIndex01 = 0;
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
      if (neighbors[d] != -1 && terrainStateTable[neighbors[d]].terrainType00 != 5) {
        terrainStateTable[tileIndex].adjacencyMaskB0b |=
            (unsigned char)g_hexDirectionBitMasks_00696e40[d];
        g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
        lcg = g_mapGenLcgState_006a38e8;
        if ((g_mapGenLcgState_006a38e8 >> 0xc & 1) != 0) {
          terrainStateTable[tileIndex].spriteVariantIndex01 |=
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
    if (terrainStateTable[neighbors[4]].spriteVariantIndex01 != 0) {
      return result;
    }
    if (((neighbors[5] == -1) || (terrainStateTable[neighbors[5]].spriteVariantIndex01 == 0)) &&
        ((neighbors[0] == -1) || (terrainStateTable[neighbors[0]].spriteVariantIndex01 == 0))) {
      g_mapGenLcgState_006a38e8 = lcg * 0x15a4e35 + 1;
      unsigned int roll = g_mapGenLcgState_006a38e8 >> 0xc & 0x7fff;
      result = reinterpret_cast<unsigned char*>(roll / 100);
      if (3 < roll % 100) {
        return result;
      }
      g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
      terrainStateTable[tileIndex].spriteVariantIndex01 =
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
      v = terrainStateTable[neighbors[5]].spriteVariantIndex01;
      if (v != 0) {
        terrainStateTable[tileIndex].spriteVariantIndex01 = v + 1;
        v = terrainStateTable[tileIndex].spriteVariantIndex01;
        result =
            reinterpret_cast<unsigned char*>(&terrainStateTable[tileIndex].spriteVariantIndex01);
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
      terrainStateTable[tileIndex].spriteVariantIndex01 =
          terrainStateTable[neighbors[0]].spriteVariantIndex01 + 1;
      v = terrainStateTable[tileIndex].spriteVariantIndex01;
      result = reinterpret_cast<unsigned char*>(&terrainStateTable[tileIndex].spriteVariantIndex01);
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
  if (cur->terrainType00 != 5) {
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

// FUNCTION: IMPERIALISM 0x00511610
short TMapMgr::UpdateStrategicMapTileIconVariantState(short tileIndex) {
  TTerrainStateRecordView* tile = &terrainStateTable[tileIndex];
  switch (static_cast<unsigned char>(tile->terrainType00)) {
  case 5: {
    short neighbors[6];
    ComputeHexNeighborTileIndices(tileIndex, neighbors, hexNeighborWrapHorizontally20);
    bool foundLandNeighbor = false;
    for (int i = 0; i < 6; ++i) {
      if (neighbors[i] != -1 && terrainStateTable[neighbors[i]].terrainType00 != 5) {
        foundLandNeighbor = true;
      }
    }
    if (foundLandNeighbor) {
      tile->resourceTypeByEdge[0] = 0x13;
    }
    break;
  }
  case 0: {
    g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
    unsigned int roll = g_mapGenLcgState_006a38e8 >> 0xc & 0x7fff;
    if (roll % 100 < 10) {
      tile->resourceTypeByEdge[0] = 0;
      break;
    }
    g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
    roll = g_mapGenLcgState_006a38e8 >> 0xc & 0x7fff;
    if (roll % 100 < 5 && tile->ownerNationTag04 < 7) {
      tile->resourceTypeByEdge[0] = 5;
      break;
    }
    g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
    roll = g_mapGenLcgState_006a38e8 >> 0xc & 0x7fff;
    if (roll % 100 < 0x24) {
      tile->resourceTypeByEdge[0] = 0x14;
    } else {
      tile->resourceTypeByEdge[0] = 0x11;
    }
    break;
  }
  case 7: {
    g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
    unsigned int roll = g_mapGenLcgState_006a38e8 >> 0xc & 0x7fff;
    if (roll % 100 < 0x37) {
      tile->resourceTypeByEdge[0] = 0x11;
    } else {
      tile->resourceTypeByEdge[0] = 0x12;
    }
    break;
  }
  case 1:
    tile->resourceTypeByEdge[0] = 2;
    break;
  case 4:
  case 6: {
    g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
    unsigned int roll = g_mapGenLcgState_006a38e8 >> 0xc & 0x7fff;
    if (roll % 100 < 0xf) {
      tile->resourceTypeByEdge[0] = 6;
    }
    break;
  }
  case 2: {
    g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
    unsigned int roll = g_mapGenLcgState_006a38e8 >> 0xc & 0x7fff;
    if (roll % 100 < 0xc) {
      tile->resourceTypeByEdge[0] = 1;
      break;
    }
    g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
    roll = g_mapGenLcgState_006a38e8 >> 0xc & 0x7fff;
    if (roll % 100 < 0x14) {
      g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
      roll = g_mapGenLcgState_006a38e8 >> 0xc & 0x7fff;
      if (roll % 100 < 0x32) {
        tile->resourceTypeByEdge[0] = 3;
      } else {
        tile->resourceTypeByEdge[0] = 4;
      }
    }
    break;
  }
  case 3: {
    int edgeIndex = 0;
    g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
    unsigned int roll = g_mapGenLcgState_006a38e8 >> 0xc & 0x7fff;
    if (roll % 100 < 0x14) {
      g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
      roll = g_mapGenLcgState_006a38e8 >> 0xc & 0x7fff;
      if (roll % 100 < 0x32) {
        tile->resourceTypeByEdge[0] = 3;
      } else {
        tile->resourceTypeByEdge[0] = 4;
      }
      edgeIndex = 1;
    }
    if (tile->ownerNationTag04 < 7) {
      g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
      roll = g_mapGenLcgState_006a38e8 >> 0xc & 0x7fff;
      if (roll % 100 < 0xf) {
        tile->resourceTypeByEdge[edgeIndex] = 0x16;
      }
    } else {
      g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
      roll = g_mapGenLcgState_006a38e8 >> 0xc & 0x7fff;
      if (roll % 100 < 0xa) {
        tile->resourceTypeByEdge[edgeIndex] = 0x15;
      } else {
        g_mapGenLcgState_006a38e8 = g_mapGenLcgState_006a38e8 * 0x15a4e35 + 1;
        roll = g_mapGenLcgState_006a38e8 >> 0xc & 0x7fff;
        if (roll % 100 < 0xf) {
          tile->resourceTypeByEdge[edgeIndex] = 0x16;
        }
      }
    }
    break;
  }
  }
  short code = ResolveRegionTileSubtypeCodeForTileIndex(tileIndex);
  tile->gateFlag = static_cast<signed char>(code);
  return code;
}

// FUNCTION: IMPERIALISM 0x00511e80
void TMapMgr::TMapMaker_EnsureMapDataStreamOpenedAndMaybeTickUiProgress() {
  if (field8 == 0) {
    hexNeighborWrapHorizontally20 = 1;
    BuildOrLoadGlobalMapStateForSession("mapdata", nullptr);
  }
  if (field4 == 0) {
    g_pUiRuntimeContext->InvokeStrategicMapViewMethod70();
  }
}

// FUNCTION: IMPERIALISM 0x00511ed0
void TMapMgr::DispatchTurnEvent7DDForActiveNation() {
  TMapMaker_EnsureMapDataStreamOpenedAndMaybeTickUiProgress();
  short nationId = g_pSimMgr->GetActiveNationId();
  g_pUiRuntimeContext->DispatchTurnEventSlot4C(0x7dd, nationId);
}

// FUNCTION: IMPERIALISM 0x00511f10
void TMapMgr::ForwardComputeRepresentativeTileIndexForTerrainTypeWithWrapBias(undefined4 param_1) {
  ComputeRepresentativeTileIndexForTerrainTypeWithWrapBias(static_cast<short>(param_1), 1);
}

undefined TMapMgr::TMapMaker_CheckTerrainTypePairReachabilityByRegionClassMask(short param_1,
                                                                               short param_2) {
  return 0;
}

undefined TMapMgr::IsNodeTypeLinkUnavailableAndNoActiveMapActionContext(int param_1,
                                                                        short param_2) {
  return 0;
}

// FUNCTION: IMPERIALISM 0x005122b0
int TMapMgr::IsShiftKeyDown() {
  return GetAsyncKeyState(VK_SHIFT) & 0x8000;
}

// FUNCTION: IMPERIALISM 0x005122d0
int TMapMgr::IsAltKeyDown() {
  return GetAsyncKeyState(VK_MENU) & 0x8000;
}

// FUNCTION: IMPERIALISM 0x00512930
extern "C" short* __cdecl BuildHexAreaTileIndexList(short centerTileIndex, short radius) {
  short* buffer = static_cast<short*>(::operator new(static_cast<short>(radius * 6) << 1));
  if (buffer == nullptr) {
    MessageBoxA(nullptr, g_szUiNilPointerMessage, g_szUiFailureMessage, 0x30);
    TemporarilyClearAndRestoreUiInvalidationFlag("D:\\Ambit\\Cross\\UMap.cpp", 0xb85);
  }

  int row = static_cast<int>(centerTileIndex) / 0x6c;
  int rowParity = row & 1;
  int colBase = (static_cast<int>(centerTileIndex) % 0x6c) * 2;

  short* out = buffer;
  for (short direction = 0; direction < 6; ++direction) {
    int dir = static_cast<int>(direction);
    if (dir < 0) {
      dir += 6;
    } else if (dir > 5) {
      dir -= 6;
    }
    int colAccum = g_Build_Hex_Area_LookupTable_00696E70[dir] * radius + rowParity + colBase;

    dir = static_cast<int>(direction);
    if (dir < 0) {
      dir += 6;
    } else if (dir > 5) {
      dir -= 6;
    }
    int rowAccum = g_Build_Hex_Area_LookupTable_00696E80[dir] * radius + row;

    int colHalfSign = colAccum >> 0x1f;
    *out = static_cast<short>(((colAccum - colHalfSign) >> 1) + rowAccum * 0x6c);
    ++out;

    int innerDir = static_cast<int>(direction) + 2;
    if (innerDir > 5) {
      innerDir -= 6;
    }
    for (short step = 0; step < radius - 1; ++step) {
      colAccum += g_Build_Hex_Area_LookupTable_00696E70[innerDir];
      rowAccum += g_Build_Hex_Area_LookupTable_00696E80[innerDir];
      colHalfSign = colAccum >> 0x1f;
      *out = static_cast<short>(((colAccum - colHalfSign) >> 1) + rowAccum * 0x6c);
      ++out;
    }
  }
  return buffer;
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

// FUNCTION: IMPERIALISM 0x00513170
TTown* TMapMgr::FindTownMarkerForTileByOwnerNation(short tileIndex) {
  TGreatPower* owner = g_apNationStates[terrainStateTable[tileIndex].ownerNationTag04];
  if (owner == nullptr) {
    return nullptr;
  }
  TSortedList* townMarkerList = owner->townMarkerList;
  for (int ordinal = 1; ordinal <= townMarkerList->GetCount(); ++ordinal) {
    TTown* town = static_cast<TTown*>(townMarkerList->GetEntryByOrdinal(ordinal));
    if (town->regionId14 == tileIndex) {
      return town;
    }
  }
  return nullptr;
}

undefined TMapMgr::DispatchFormationEntryActionsAndMaybeCreateTurnEvent12(short param_1,
                                                                          undefined4 param_2) {
  return 0;
}

undefined TMapMgr::SetTileOwnerAndInvalidateNeighborState(short param_1, short param_2) {
  return 0;
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

// FUNCTION: IMPERIALISM 0x005135a0
byte TMapMgr::FindResourceCapabilityRequirementLevelByType(short tileIndex, char resourceType) {
  for (int edgeIndex = 0; edgeIndex < 2; ++edgeIndex) {
    if (terrainStateTable[tileIndex].resourceTypeByEdge[edgeIndex] == resourceType) {
      return FindResourceCapabilityRequirementLevel(tileIndex, static_cast<short>(edgeIndex));
    }
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x00513610
byte TMapMgr::FindResourceCapabilityRequirementLevel(short tileIndex, short edgeIndex) {
  signed char resourceType = terrainStateTable[tileIndex].resourceTypeByEdge[edgeIndex];
  signed char raw = terrainStateTable[tileIndex].developmentClassNibbles0c;
  signed char index = g_abResourceTypeUsesHighNibbleFlag[resourceType] != 0 ? (raw >> 4) : raw;
  return g_abUniversityRequirementLevelById[resourceType][index];
}

// FUNCTION: IMPERIALISM 0x00513660
byte TMapMgr::GetTileCivilianWorkOrderCostClassNibble(short nTileIndex, char fUseHighNibble) {
  if (fUseHighNibble) {
    return terrainStateTable[nTileIndex].developmentClassNibbles0c >> 4;
  }
  return terrainStateTable[nTileIndex].developmentClassNibbles0c & 0xf;
}

// FUNCTION: IMPERIALISM 0x005136a0
void TMapMgr::SetCivilianDevelopmentClassNibble(short tileIndex, char selectHighNibble, byte value,
                                                char param4) {
  unsigned char packed = terrainStateTable[tileIndex].developmentClassNibbles0c;
  if (selectHighNibble) {
    packed = (packed & 0xf) | (value << 4);
  } else {
    packed = (packed & 0xf0) | value;
  }
  terrainStateTable[tileIndex].developmentClassNibbles0c = packed;
  if (selectHighNibble) {
    if (static_cast<signed char>(value) > 0 && param4 != 0) {
      terrainStateTable[tileIndex].pendingDevelopmentFlag0d = 0x7f;
    }
  }
}

// FUNCTION: IMPERIALISM 0x00513720
short TMapMgr::FindMaxResourceCapabilityValueForTile(short tileIndex, char categoryCode,
                                                     int nationSlot) {
  short maxValue = 0;
  for (int edgeIndex = 0; edgeIndex < 2; ++edgeIndex) {
    signed char resourceType = terrainStateTable[tileIndex].resourceTypeByEdge[edgeIndex];
    if (resourceType == -1) {
      continue;
    }
    if (g_abResourceTypeCapabilityCategory[resourceType] != categoryCode) {
      continue;
    }
    short value =
        g_pCityOrderCapabilityState->capabilityValueByNationAndResource[nationSlot][resourceType];
    if (value > maxValue) {
      maxValue = value;
    }
  }
  return maxValue;
}

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

// FUNCTION: IMPERIALISM 0x00513f60
void TMapMgr::SetHexAdjacencyDirectionFlagsForTilePair(short sourceTile, short destTile,
                                                       int unusedParam3) {
  (void)unusedParam3;
  short direction = GetHexDirectionBetweenTiles(sourceTile, destTile);
  terrainStateTable[sourceTile].adjacencyBits06 |=
      static_cast<unsigned char>(g_hexDirectionBitMasksAlt_00696ea8[direction]);
  short oppositeDirection = (direction + 3) % 6;
  terrainStateTable[destTile].adjacencyBits06 |=
      static_cast<unsigned char>(g_hexDirectionBitMasksAlt_00696ea8[oppositeDirection]);
}

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

// FUNCTION: IMPERIALISM 0x00514110
short TMapMgr::ResolveRegionTileSubtypeCodeForTileIndex(short tileIndex) {
  TTerrainStateRecordView* tile = &terrainStateTable[tileIndex];
  switch (static_cast<unsigned char>(tile->terrainType00)) {
  case 0:
    if (tile->resourceTypeByEdge[0] == 0) {
      return 2;
    }
    if (tile->resourceTypeByEdge[0] == 5) {
      return 4;
    }
    if (tile->resourceTypeByEdge[0] == 0x14) {
      return 3;
    }
    return (tile->activeFlags1c & 2) ? 0xe : 1;
  case 1:
    if (tile->gateFlag == -1) {
      return 0xd;
    }
    return tile->gateFlag;
  case 2:
    return (tile->resourceTypeByEdge[0] != 1) + 7;
  case 3:
    return 9;
  case 4:
    return 0xa;
  case 6:
    if (tile->gateFlag != -1) {
      return tile->gateFlag;
    } else {
      short quotient = tileIndex / 0x6c;
      if (quotient < 0xf) {
        return 0xc;
      }
      if (quotient > 0x2d) {
        return 0xc;
      }
      return 0xb;
    }
  case 7:
    return (tile->resourceTypeByEdge[0] != 0x11) + 5;
  default:
    return 0;
  }
}

undefined TMapMgr::TMapMaker_EnsureRegionClassHasSubtype3And4AssignmentsWithRng() {
  return 0;
}

// FUNCTION: IMPERIALISM 0x00514250
TCivUnit* TMapMgr::GetTileUnitEntryByOwner(short tileIndex, short nationId) {
  TCivUnit* entry = GetFirstCivilianOrderOnTile(tileIndex);
  while ((entry != nullptr) && (entry->field_18 != nationId)) {
    entry = static_cast<TCivUnit*>(entry->nextOnTile);
  }
  return entry;
}

bool TMapMgr::IsValidSecondaryNationHomeTileCandidate(short tileIndex) {
  // TODO: port body @ 0x513980 (632 bytes; not yet ported).
  (void)tileIndex;
  return false;
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

// FUNCTION: IMPERIALISM 0x00514310
bool TMapMgr::TileHasCivilianOrderOfType(short tileIndex, short orderType) {
  for (TCivUnit* order = terrainStateTable[tileIndex].firstCivilianOrder20; order != nullptr;
       order = static_cast<TCivUnit*>(order->nextOnTile)) {
    if (order->orderType == orderType) {
      return true;
    }
  }
  return false;
}

// FUNCTION: IMPERIALISM 0x00514360
bool TMapMgr::TileHasCivilianOrderOfTypeAndField8(short tileIndex, short orderType,
                                                  short field8Value) {
  for (TCivUnit* order = terrainStateTable[tileIndex].firstCivilianOrder20; order != nullptr;
       order = static_cast<TCivUnit*>(order->nextOnTile)) {
    if (order->orderType == orderType && order->field_8 == field8Value) {
      return true;
    }
  }
  return false;
}

void TMapMgr::FloodFillTileRegionMarker(short nTileIndex, short nOwnerNationId) {}

int TMapMgr::QueueDepotConstructionOrder(int* pMapContext, short nTileIndex, short nNationId,
                                         undefined2 param_4) {
  return 0;
}

void TMapMgr::QueuePortConstructionOrder(int* pMapContext, short nTileIndex, short nNationId,
                                         undefined2 param_4) {}

// FUNCTION: IMPERIALISM 0x005149d0
void TMapMgr::SetProvinceCapitalTileFlagBit08(short nProvinceId) {
  short capitalTileIndex = cityScoreTable[nProvinceId].ownerNationSlot;
  terrainStateTable[capitalTileIndex].activeFlags1c |= 8;
  ++cityScoreTable[nProvinceId].fortLevel03;
}

void TMapMgr::SetTileTransportFlagsTo0x37AndRefreshNeighbors(short nTileIndex) {}

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

// FUNCTION: IMPERIALISM 0x00514dc0
void TMapMgr::WrapperFor_IsValidSecondaryNationHomeTileCandidate_At00514dc0(short nationTag) {
  field9 = 1;
  for (int tileIndex = 0; tileIndex < 0x1950; ++tileIndex) {
    TTerrainStateRecordView* tile = &terrainStateTable[tileIndex];
    if (tile->ownerNationTag04 == nationTag && tile->terrainType00 != 2 &&
        tile->terrainType00 != 3 && tile->terrainType00 != 4) {
      tile->recruitSearchVisited0e = IsValidSecondaryNationHomeTileCandidate(tileIndex) ? 0 : 1;
    } else {
      tile->recruitSearchVisited0e = 1;
    }
  }
}

// FUNCTION: IMPERIALISM 0x00514e40
void TMapMgr::SeedRecruitSearchVisitedStateExcludingNation(short ownerNationTag) {
  this->field9 = 1;
  for (int tileIndex = 0; tileIndex < 0x1950; ++tileIndex) {
    terrainStateTable[tileIndex].recruitSearchVisited0e =
        (terrainStateTable[tileIndex].ownerNationTag04 != ownerNationTag) ? 1 : 0;
  }
}

// FUNCTION: IMPERIALISM 0x00514e80
void TMapMgr::SeedRecruitSearchVisitedStateFromSelectedCivilianOrder() {
  TTerrainStateRecordView* tile = terrainStateTable;
  this->field9 = 1;
  for (int tileIndex = 0; tileIndex < 0x1950; ++tileIndex, ++tile) {
    TCivUnit* selectedEntry = g_pSelectedCivilianOrderState->selectedEntry;
    if (selectedEntry == nullptr) {
      continue;
    }
    if (selectedEntry->field_6 != 0) {
      tile->recruitSearchVisited0e = 1;
    } else {
      tile->recruitSearchVisited0e = (tile->activeFlags1c >> 4) & 1;
    }
  }
}

// FUNCTION: IMPERIALISM 0x00514ef0
void TMapMgr::ResetRecruitSearchVisitedState() {
  for (int tileIndex = 0; tileIndex < 0x1950; ++tileIndex) {
    terrainStateTable[tileIndex].recruitSearchVisited0e = 0;
  }
  this->field9 = 0;
}

// FUNCTION: IMPERIALISM 0x00514f20
void TMapMgr::SeedRecruitSearchVisitedStateAndClearAlliedTerritory(TCivUnit* pCivilianOrderEntry) {
  short refTileIndex = pCivilianOrderEntry->field_6;
  signed char refOwner = terrainStateTable[refTileIndex].ownerNationTag04;
  this->field9 = 1;
  for (int tileIndex = 0; tileIndex < 0x1950; ++tileIndex) {
    terrainStateTable[tileIndex].recruitSearchVisited0e =
        (terrainStateTable[tileIndex].ownerNationTag04 != refOwner) ? 1 : 0;
  }

  if (pCivilianOrderEntry->orderType != 1 && pCivilianOrderEntry->orderType != 7) {
    return;
  }
  if (pCivilianOrderEntry->field_1C != 0) {
    return;
  }

  TTerrainStateRecordView* refTile = &terrainStateTable[refTileIndex];
  unsigned char flags = refTile->activeFlags1c;
  bool gateFlagPasses = (flags & 3) != 0 && refTile->gateFlag != 0;
  if (!gateFlagPasses && (flags & 4) == 0) {
    return;
  }

  if (refOwner == pCivilianOrderEntry->field_18) {
    TTown* town = FindTownMarkerForTileByOwnerNation(refTileIndex);
    if (town->enabledFlag4d == 0) {
      return;
    }
  }

  for (int minorSlot = 7; minorSlot < 23; ++minorSlot) {
    TMinor* minorObj = g_apMinorNationCapabilityObjects[minorSlot - 7];
    if (minorObj == nullptr) {
      continue;
    }
    if (g_pDiplomacyTurnStateManager->IsNationPairAtWar(minorSlot, pCivilianOrderEntry->field_18)) {
      continue;
    }
    terrainStateTable[minorObj->ownerNationSlot].recruitSearchVisited0e = 0;
  }

  TGreatPower* owner = g_apNationStates[pCivilianOrderEntry->field_18];
  TSortedList* townMarkerList = owner->townMarkerList;
  for (int ordinal = 1; ordinal <= townMarkerList->GetCount(); ++ordinal) {
    TTown* town = static_cast<TTown*>(townMarkerList->GetEntryByOrdinal(ordinal));
    if (town->enabledFlag4d != 0) {
      terrainStateTable[town->regionId14].recruitSearchVisited0e = 0;
    }
  }
}

// FUNCTION: IMPERIALISM 0x005150e0
void TMapMgr::SeedRecruitSearchVisitedStateFromMilitaryUnitCandidates(
    TMilitaryUnit* const candidates[6], short orderTargetSlot) {
  int i;
  TMilitaryUnit* unit = nullptr;
  for (i = 0; i < 6; ++i) {
    if (candidates[i] != nullptr) {
      unit = candidates[i];
    }
  }
  if (unit == nullptr) {
    return;
  }

  short nationSlot = unit->field_18;
  field9 = 1;
  int tileScanIndex;
  for (tileScanIndex = 0; tileScanIndex < 0x1950; ++tileScanIndex) {
    terrainStateTable[tileScanIndex].recruitSearchVisited0e = 1;
  }
  terrainStateTable[unit->field_6].recruitSearchVisited0e = 0;

  // Minimum per-candidate combat class across all 6 slots (capped at 3) -- computed but
  // never read by the original; kept for byte-fidelity rather than dropped as dead code.
  short minCombatClass = 3;
  for (i = 0; i < 6; ++i) {
    if (candidates[i] != nullptr) {
      short combatClass = g_awUnitCombatClassBySlot[candidates[i]->orderType];
      if (combatClass < minCombatClass) {
        minCombatClass = combatClass;
      }
    }
  }
  (void)minCombatClass;

  short targetTileIndex;
  if (orderTargetSlot != 0) {
    targetTileIndex = unit->orderTargetTiles28[orderTargetSlot - 1];
  } else {
    targetTileIndex = unit->field_6;
  }

  for (short direction = 0; direction < 6; ++direction) {
    short neighborTile = GetWrappedHexNeighborTileIndexByDirection(targetTileIndex, direction);
    if (neighborTile == -1) {
      continue;
    }
    TTerrainStateRecordView* neighbor = &terrainStateTable[neighborTile];
    if (neighbor->ownerNationTag04 == nationSlot) {
      neighbor->recruitSearchVisited0e = 0;
    } else if (g_pDiplomacyTurnStateManager->IsNationPairAtWar(neighbor->ownerNationTag04,
                                                               nationSlot)) {
      neighbor->recruitSearchVisited0e = 0;
    }
  }
}

// FUNCTION: IMPERIALISM 0x00515330
void TMapMgr::WrapperFor_LookupOrderCompatibilityMatrixValue_At00515330(
    TCivUnit* pCivilianOrderEntry) {
  field9 = 1;
  short nationTag = pCivilianOrderEntry->field_18;
  unsigned char eligibleGateFlags[24] = {0};
  eligibleGateFlags[8] = 1;
  eligibleGateFlags[9] = 1;
  if (g_pCityOrderCapabilityState->orderCapRows277[nationTag].recruitTierFlag27b == 2) {
    eligibleGateFlags[10] = 1;
    eligibleGateFlags[11] = 1;
    eligibleGateFlags[12] = 1;
  }
  unsigned char nationBit = 1 << nationTag;
  for (int tileIndex = 0; tileIndex < 0x1950; ++tileIndex) {
    TTerrainStateRecordView* tile = &terrainStateTable[tileIndex];
    if (tile->terrainType00 == 5) {
      tile->recruitSearchVisited0e = 0;
      continue;
    }
    if (tile->ownerNationTag04 != nationTag) {
      if (tile->ownerNationTag04 < 7) {
        tile->recruitSearchVisited0e = 1;
        continue;
      }
      if (g_pDiplomacyTurnStateManager->LookupOrderCompatibilityMatrixValue(
              nationTag, tile->ownerNationTag04) != 2) {
        tile->recruitSearchVisited0e = 1;
        continue;
      }
    }
    if (eligibleGateFlags[tile->gateFlag] == 0) {
      tile->recruitSearchVisited0e = 1;
      continue;
    }
    tile->recruitSearchVisited0e = (nationBit & tile->pendingDevelopmentFlag0d) ? 1 : 0;
  }
}

// FUNCTION: IMPERIALISM 0x00515460
void TMapMgr::WrapperFor_LookupOrderCompatibilityMatrixValue_At00515460(
    TCivUnit* pCivilianOrderEntry) {
  short nationTag = pCivilianOrderEntry->field_18;
  bool recruitTierFlagIsTwo =
      (g_pCityOrderCapabilityState->orderCapRows277[nationTag].recruitTierFlag27b == 2);
  field9 = 1;
  unsigned char nationBit = 1 << nationTag;
  for (int tileIndex = 0; tileIndex < 0x1950; ++tileIndex) {
    TTerrainStateRecordView* tile = &terrainStateTable[tileIndex];
    tile->recruitSearchVisited0e = 1;
    if (tile->terrainType00 == 5) {
      continue;
    }
    if (tile->ownerNationTag04 < 7) {
      continue;
    }
    if (g_pDiplomacyTurnStateManager->LookupOrderCompatibilityMatrixValue(
            nationTag, tile->ownerNationTag04) != 2) {
      continue;
    }
    if (tile->secondaryOwnerNationTag18 != -1) {
      continue;
    }
    if (g_abGateFlagQualifies[tile->gateFlag] == 0) {
      continue;
    }
    bool found = false;
    for (int edge = 0; edge < 2; ++edge) {
      signed char resourceType = tile->resourceTypeByEdge[edge];
      if (resourceType == 0 || resourceType == 1 || resourceType == 2) {
        found = true;
        continue;
      }
      if (tile->pendingDevelopmentFlag0d & nationBit) {
        if (resourceType == 3 || resourceType == 4 || resourceType == 0x15 ||
            resourceType == 0x16) {
          found = true;
        } else if (recruitTierFlagIsTwo && resourceType == 6) {
          found = true;
        }
      }
    }
    if (found) {
      tile->recruitSearchVisited0e = 0;
    }
  }
}

// FUNCTION: IMPERIALISM 0x005155c0
void TMapMgr::SeedRecruitSearchVisitedStateByCapabilityThreshold(TCivUnit* pCivilianOrderEntry) {
  unsigned char qualifiesByResourceType[23] = {0};
  if (pCivilianOrderEntry->orderType == 0) {
    qualifiesByResourceType[3] = 1;
    qualifiesByResourceType[4] = 1;
    qualifiesByResourceType[21] = 1;
    qualifiesByResourceType[22] = 1;
  } else {
    qualifiesByResourceType[6] = 1;
  }

  this->field9 = 1;
  short nationTag = pCivilianOrderEntry->field_18;
  for (int tileIndex = 0; tileIndex < 0x1950; ++tileIndex) {
    TTerrainStateRecordView* tile = &terrainStateTable[tileIndex];
    if (tile->terrainType00 == 5) {
      tile->recruitSearchVisited0e = 1;
      continue;
    }
    if (tile->ownerNationTag04 != nationTag && tile->secondaryOwnerNationTag18 != nationTag) {
      tile->recruitSearchVisited0e = 1;
      continue;
    }
    if (tile->pendingDevelopmentFlag0d == 0) {
      tile->recruitSearchVisited0e = 1;
      continue;
    }
    short maxValue = 0;
    for (int edgeIndex = 0; edgeIndex < 2; ++edgeIndex) {
      signed char resourceType = tile->resourceTypeByEdge[edgeIndex];
      if (resourceType == -1) {
        continue;
      }
      if (qualifiesByResourceType[resourceType] == 0) {
        continue;
      }
      short value =
          g_pCityOrderCapabilityState->capabilityValueByNationAndResource[nationTag][resourceType];
      if (value > maxValue) {
        maxValue = value;
      }
    }
    signed char highNibble = tile->developmentClassNibbles0c >> 4;
    tile->recruitSearchVisited0e = (highNibble >= maxValue) ? 1 : 0;
  }
}

// FUNCTION: IMPERIALISM 0x00515720
void TMapMgr::MarkType5NeighborTilesUnavailableByNationCapability(TCivUnit* pCivilianOrderEntry) {
  for (int tileIndex = 0; tileIndex < 0x1950; ++tileIndex) {
    terrainStateTable[tileIndex].recruitSearchVisited0e = 1;
  }

  short nationTag = pCivilianOrderEntry->field_18;
  TGreatPower* nation = g_apNationStates[nationTag];
  TSortedList* townMarkerList = nation->townMarkerList;
  int townCount = townMarkerList->GetCount();
  for (int ordinal = 1; ordinal <= townCount; ++ordinal) {
    TTown* town = static_cast<TTown*>(townMarkerList->GetEntryByOrdinal(ordinal));
    if (town->enabledFlag4d == 0) {
      continue;
    }
    short regionId = town->regionId14;
    signed char townTag5 = terrainStateTable[regionId].regionSubtypeTag05;
    short neighbors[6];
    ComputeHexNeighborTileIndices(regionId, neighbors, hexNeighborWrapHorizontally20);
    for (int d = 0; d < 6; ++d) {
      if (neighbors[d] == -1) {
        continue;
      }
      TTerrainStateRecordView* neighbor = &terrainStateTable[neighbors[d]];
      if (neighbor->terrainType00 != 5) {
        continue;
      }
      if (neighbor->regionSubtypeTag05 != townTag5) {
        continue;
      }
      if (neighbor->developmentClassNibbles0c <
          g_pCityOrderCapabilityState->capabilityValueByNationAndResource[nationTag][19]) {
        neighbor->recruitSearchVisited0e = 0;
      }
    }
  }
}

// FUNCTION: IMPERIALISM 0x00515890
void TMapMgr::SeedRecruitSearchVisitedStateByCapabilityThresholdAlt(TCivUnit* pCivilianOrderEntry) {
  this->field9 = 1;
  short nationTag = pCivilianOrderEntry->field_18;
  short orderType = pCivilianOrderEntry->orderType;
  for (int tileIndex = 0; tileIndex < 0x1950; ++tileIndex) {
    TTerrainStateRecordView* tile = &terrainStateTable[tileIndex];
    tile->recruitSearchVisited0e = 1;
    if (tile->ownerNationTag04 != nationTag && tile->secondaryOwnerNationTag18 != nationTag) {
      continue;
    }
    if (g_abGateFlagQualifies[tile->gateFlag] == 0) {
      continue;
    }
    short maxValue = 0;
    for (int edgeIndex = 0; edgeIndex < 2; ++edgeIndex) {
      signed char resourceType = tile->resourceTypeByEdge[edgeIndex];
      if (resourceType == -1) {
        continue;
      }
      if (g_anResourceTypeRequiredOrderType[resourceType] != orderType) {
        continue;
      }
      if (g_abResourceTypeAlwaysQualifies[resourceType] == 0 &&
          tile->ownerNationTag04 != nationTag) {
        continue;
      }
      short value =
          g_pCityOrderCapabilityState->capabilityValueByNationAndResource[nationTag][resourceType];
      if (value > maxValue) {
        maxValue = value;
      }
    }
    signed char lowNibble = tile->developmentClassNibbles0c & 0xf;
    if (lowNibble < maxValue) {
      tile->recruitSearchVisited0e = 0;
    }
  }
}

// FUNCTION: IMPERIALISM 0x005159b0
void TMapMgr::MarkSeedNeighborTilesUnavailableByCapabilityMaskProfileA(
    TCivUnit* pCivilianOrderEntry) {
  this->field9 = 1;
  for (int i = 0; i < 0x1950; ++i) {
    terrainStateTable[i].recruitSearchVisited0e = 1;
  }

  short nationTag = pCivilianOrderEntry->field_18;
  short tileIndex = pCivilianOrderEntry->field_6;

  // orderCapRows277[nationTag - 1] reads the *previous* nation's row padding -- for
  // nationTag == 0 this reads out of the array's declared bounds (into the tail of
  // nationCapRows1e8[6]/pad274), reproducing the original's own out-of-bounds read.
  if (g_pCityOrderCapabilityState->orderCapRows277[nationTag - 1].unknownFlag28b == 2) {
    g_bSeedGateNotifyFlag_00696f0c = 1;
  }
  if (g_pCityOrderCapabilityState->orderCapRows277[nationTag - 1].unknownFlag291 == 2) {
    g_bSeedGateNotifyFlag_00696f0a = 1;
  }
  if (g_pCityOrderCapabilityState->orderCapRows277[nationTag].unknownFlag27f == 2) {
    g_bSeedGateNotifyFlag_00696f0b = 1;
  }

  if (g_abTerrainTypeSeedGateProfileA[terrainStateTable[tileIndex].terrainType00] != 0) {
    short* neighbors = BuildHexAreaTileIndexList(tileIndex, 1);
    unsigned char directionBit = 0;
    for (int d = 0; d < 6; ++d) {
      TTerrainStateRecordView* neighbor = &terrainStateTable[neighbors[d]];
      if (g_abTerrainTypeSeedGateProfileA[neighbor->terrainType00] != 0 &&
          neighbor->ownerNationTag04 == nationTag &&
          ((1 << directionBit) & terrainStateTable[tileIndex].adjacencyBits06) == 0) {
        neighbor->recruitSearchVisited0e = 0;
      }
      ++directionBit;
    }
    ::operator delete(neighbors);
  }
}

// FUNCTION: IMPERIALISM 0x00515b10
void TMapMgr::MarkSeedNeighborTilesUnavailableByCapabilityMaskProfileB(
    TCivUnit* pCivilianOrderEntry) {
  short tileIndex = pCivilianOrderEntry->field_6;
  short nationTag = pCivilianOrderEntry->field_18;

  unsigned char terrainTypeGate[8] = {1, 1, 0, 0, 0, 0, 1, 1};
  if (g_pCityOrderCapabilityState->orderCapRows277[nationTag - 1].unknownFlag28b == 2) {
    terrainTypeGate[4] = 1;
    terrainTypeGate[5] = 0;
    terrainTypeGate[6] = 1;
    terrainTypeGate[7] = 1;
  }
  if (g_pCityOrderCapabilityState->orderCapRows277[nationTag - 1].unknownFlag291 == 2) {
    terrainTypeGate[0] = 1;
    terrainTypeGate[1] = 1;
    terrainTypeGate[2] = 1;
    terrainTypeGate[3] = 0;
  }
  if (g_pCityOrderCapabilityState->orderCapRows277[nationTag].unknownFlag27f == 2) {
    terrainTypeGate[3] = 1;
  }

  this->field9 = 1;
  for (int i = 0; i < 0x1950; ++i) {
    terrainStateTable[i].recruitSearchVisited0e = 1;
  }

  TTerrainStateRecordView* tile = &terrainStateTable[tileIndex];
  if (terrainTypeGate[tile->terrainType00] != 0) {
    if (tile->regionSubtypeTag05 == -1 || cityScoreTable[tile->cityRecordIndex].fortLevel03 < 3) {
      tile->recruitSearchVisited0e = 0;
    }

    short* neighbors = BuildHexAreaTileIndexList(tileIndex, 1);
    unsigned char directionBit = 0;
    for (int d = 0; d < 6; ++d) {
      TTerrainStateRecordView* neighbor = &terrainStateTable[neighbors[d]];
      if (terrainTypeGate[neighbor->terrainType00] != 0 &&
          neighbor->ownerNationTag04 == nationTag &&
          ((1 << directionBit) & tile->adjacencyBits06) == 0) {
        neighbor->recruitSearchVisited0e = 0;
      }
      ++directionBit;
    }
    ::operator delete(neighbors);
  }
}

// FUNCTION: IMPERIALISM 0x00515d60
void TMapMgr::ApplyUnitMovementClassForTileIfValid(int tileIndex) {
  if (tileIndex != -1) {
    g_pMapContextActionManager->HasEligibleStationedUnitInRegion(static_cast<short>(tileIndex));
  }
}

// FUNCTION: IMPERIALISM 0x00515db0
void TMapMgr::ClearPerTileByte0FForAllMapTiles() {
  for (int tileIndex = 0; tileIndex < kGlobalMapTileCount; ++tileIndex) {
    terrainStateTable[tileIndex].perTileVisitedFlag0f = 0;
  }
}

// FUNCTION: IMPERIALISM 0x00515de0
void TMapMgr::NoOpVirtualSlot2D(int param_1, int param_2, int param_3) {
  (void)param_1;
  (void)param_2;
  (void)param_3;
}

undefined TMapMgr::SetRegionTileSubtypeAndRefreshNeighborFlags(int param_1, int param_2) {
  return 0;
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
void TMapMgr::AssignCityRecordDisplayName(int cityRecordIndex, CString* dest) {
  *dest = cityScoreTable[cityRecordIndex].cityNameA4;
}

// FUNCTION: IMPERIALISM 0x00516090
short TMapMgr::FindLinkedRegionIdForAdjacentRegion(int cityRecordIndex, int regionId) {
  TGlobalMapCityScoreRecord* city = &cityScoreTable[cityRecordIndex];
  for (int i = 0; i < 12; ++i) {
    if (city->adjacentRegionIds0A[i] == regionId) {
      return city->adjacentRegionIds0A[i + 12];
    }
  }
  return -1;
}

// FUNCTION: IMPERIALISM 0x00516100
void TMapMgr::SetCapitalCityDevelopmentStageIfValidNationSlot(int nationSlotParam, int param_2) {
  (void)param_2;
  short capitalTileIndex = g_apTerrainTypeDescriptorTable[nationSlotParam]->ownerNationSlot;
  short cityRecordIndex = terrainStateTable[capitalTileIndex].cityRecordIndex;
  if (nationSlotParam < 7) {
    cityScoreTable[cityRecordIndex].developmentStage = 2;
  }
}

// terrainType00 == 3 (region class 3) selects a per-spriteVariantIndex01 column;
// every other terrainType00 always reads column 0 of the same gateFlag row.
// FUNCTION: IMPERIALISM 0x00516150
short TMapMgr::LookupTileSpriteVariantOffsetByTerrainAndGate(short nTileIndex) {
  TTerrainStateRecordView* tile = &terrainStateTable[nTileIndex];
  if (tile->terrainType00 == 3) {
    return g_awTileSpriteVariantOffsetTable38[tile->gateFlag][tile->spriteVariantIndex01];
  }
  return g_awTileSpriteVariantOffsetTable38[tile->gateFlag][0];
}

// adjacencyMaskB0b != 0 forces column 0 (no per-tile variant); otherwise the table is
// indexed directly by spriteVariantIndex01 (single row, no gateFlag dimension).
// FUNCTION: IMPERIALISM 0x005161a0
short TMapMgr::LookupTileSpriteVariantOffsetByAdjacencyMaskB(short nTileIndex) {
  TTerrainStateRecordView* tile = &terrainStateTable[nTileIndex];
  if (tile->adjacencyMaskB0b != 0) {
    return g_awTileSpriteVariantOffsetTable39[0];
  }
  return g_awTileSpriteVariantOffsetTable39[tile->spriteVariantIndex01];
}

// FUNCTION: IMPERIALISM 0x005161e0
short TMapMgr::LookupTileSpriteVariantOffsetByGateAndVariant(short nTileIndex) {
  TTerrainStateRecordView* tile = &terrainStateTable[nTileIndex];
  return g_awTileSpriteVariantOffsetTable3a[tile->gateFlag][tile->spriteVariantIndex01];
}

// FUNCTION: IMPERIALISM 0x00516220
short TMapMgr::LookupTileSpriteVariantOffsetByGateAndVariantAlt(short nTileIndex) {
  TTerrainStateRecordView* tile = &terrainStateTable[nTileIndex];
  return g_awTileSpriteVariantOffsetTable3b[tile->gateFlag][tile->spriteVariantIndex01];
}

// FUNCTION: IMPERIALISM 0x00516260
short TMapMgr::LookupAdjacencyBitmaskVariantByDirection(char bitmaskIndex, char direction) {
  short table[64][7] = {
      {0, 0, 0, 0, 0, 0, 0},  {1, 2, 2, 0, 0, 0, 0},  {2, 0, 3, 3, 0, 0, 0},
      {3, 2, 1, 3, 0, 0, 0},  {4, 0, 0, 2, 2, 0, 0},  {5, 2, 0, 2, 2, 0, 0},
      {6, 0, 3, 1, 2, 0, 0},  {7, 2, 1, 1, 2, 0, 0},  {8, 0, 0, 0, 3, 3, 0},
      {9, 2, 2, 0, 3, 3, 0},  {10, 0, 3, 3, 3, 3, 0}, {11, 2, 1, 3, 3, 3, 0},
      {12, 0, 0, 2, 1, 3, 0}, {13, 2, 2, 2, 1, 3, 0}, {14, 0, 3, 1, 1, 3, 0},
      {15, 2, 1, 1, 1, 3, 0}, {16, 0, 0, 0, 0, 2, 2}, {17, 2, 2, 0, 0, 2, 2},
      {18, 0, 3, 3, 0, 2, 2}, {19, 2, 1, 3, 0, 2, 2}, {20, 0, 0, 2, 2, 2, 2},
      {21, 2, 2, 2, 2, 2, 2}, {22, 0, 3, 1, 2, 2, 2}, {23, 2, 1, 1, 2, 2, 2},
      {24, 0, 0, 0, 3, 1, 2}, {25, 2, 2, 0, 3, 1, 2}, {26, 0, 3, 3, 3, 1, 2},
      {27, 2, 1, 3, 3, 1, 2}, {28, 0, 0, 2, 1, 1, 2}, {29, 2, 2, 2, 1, 1, 2},
      {30, 0, 3, 1, 1, 1, 2}, {31, 2, 1, 1, 1, 1, 2}, {32, 3, 0, 0, 0, 0, 3},
      {33, 1, 2, 0, 0, 0, 3}, {34, 3, 3, 3, 0, 0, 3}, {35, 1, 1, 3, 0, 0, 3},
      {36, 3, 0, 2, 2, 0, 3}, {37, 1, 2, 2, 2, 0, 3}, {38, 3, 3, 1, 2, 0, 3},
      {39, 1, 1, 1, 2, 0, 3}, {40, 3, 0, 0, 3, 3, 3}, {41, 1, 2, 0, 3, 3, 3},
      {42, 3, 3, 3, 3, 3, 3}, {43, 1, 1, 3, 3, 3, 3}, {44, 3, 0, 2, 1, 3, 3},
      {45, 1, 2, 2, 1, 3, 3}, {46, 3, 3, 1, 1, 3, 3}, {47, 1, 1, 1, 1, 3, 3},
      {48, 3, 0, 0, 0, 2, 1}, {49, 1, 2, 0, 0, 2, 1}, {50, 3, 3, 3, 0, 2, 1},
      {51, 1, 1, 3, 0, 2, 1}, {52, 3, 0, 2, 2, 2, 1}, {53, 1, 2, 2, 2, 2, 1},
      {54, 3, 3, 1, 2, 2, 1}, {55, 1, 1, 1, 2, 2, 1}, {56, 3, 0, 0, 3, 1, 1},
      {57, 1, 2, 0, 3, 1, 1}, {58, 3, 3, 3, 3, 1, 1}, {59, 1, 1, 3, 3, 1, 1},
      {60, 3, 0, 2, 1, 1, 1}, {61, 1, 2, 2, 1, 1, 1}, {62, 3, 3, 1, 1, 1, 1},
      {63, 1, 1, 1, 1, 1, 1},
  };
  return table[bitmaskIndex][direction];
}

// FUNCTION: IMPERIALISM 0x00517410
int TMapMgr::MapImprovementOffsetFromAdjacencyVariant(char bitmaskIndex, char direction,
                                                      char useAltOffset) {
  if (LookupAdjacencyBitmaskVariantByDirection(bitmaskIndex, direction) == 0) {
    return 0;
  }
  if (useAltOffset == 0) {
    return (LookupAdjacencyBitmaskVariantByDirection(bitmaskIndex, direction) + 0x15) << 6;
  }
  return (LookupAdjacencyBitmaskVariantByDirection(bitmaskIndex, direction) + 0x20) << 6;
}

// FUNCTION: IMPERIALISM 0x00517480
short TMapMgr::MapImprovementOffsetFromAdjacencyVariantTriple(char bitmaskIndex, char direction,
                                                              short param3) {
  if (LookupAdjacencyBitmaskVariantByDirection(bitmaskIndex, direction) == 0) {
    return 0;
  }
  short offset = LookupAdjacencyBitmaskVariantByDirection(bitmaskIndex, direction);
  offset = (offset + 0x29) << 6;
  if (LookupAdjacencyBitmaskVariantByDirection(bitmaskIndex, direction) == 1) {
    if (param3 == 0x33 || param3 == 0x36 || param3 == 0x3a || param3 == 0x39) {
      offset += 0xc0;
    }
  }
  return offset;
}

// FUNCTION: IMPERIALISM 0x00517520
short TMapMgr::GetFixedConstant0xc80() {
  return 0xc80;
}

// FUNCTION: IMPERIALISM 0x00517540
int TMapMgr::GetMapImprovementOffsetByActiveFlagsAndCityStage(short tileIndex, short categoryCode) {
  TTerrainStateRecordView* tile = &terrainStateTable[tileIndex];
  unsigned char flags = tile->activeFlags1c;
  if (categoryCode < 7) {
    if (flags & 1) {
      return 0x6c0;
    }
    if (flags & 2) {
      short cityRecordIndex = tile->cityRecordIndex;
      switch (cityScoreTable[cityRecordIndex].developmentStage) {
      case 0:
        return 0x700;
      case 1:
        return 0x740;
      case 2:
        return 0x780;
      }
    }
    return 0;
  }
  if (flags & 1) {
    return 0x9c0;
  }
  if (flags & 2) {
    return 0x980;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x00517600
short TMapMgr::GetMapImprovementOffsetByTownTransportLink(short tileIndex, int unusedParam2) {
  (void)unusedParam2;
  unsigned char flags = terrainStateTable[tileIndex].activeFlags1c;
  TTown* town = FindTownMarkerForTileByOwnerNation(tileIndex);
  unsigned char linked = (town != nullptr) ? town->transportLinkedFlag4c : 1;
  if (flags & 4) {
    if (flags & 0x10) {
      return linked ? 0x840 : 0xa40;
    }
    return linked ? 0x880 : 0xa00;
  }
  if (flags & 0x10) {
    return linked ? 0x7c0 : 0x800;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x005176a0
int TMapMgr::GetMapImprovementBitmapRowOffsetForIndex(int index) {
  return (index + 0x23) << 6;
}

// FUNCTION: IMPERIALISM 0x005176c0
int TMapMgr::ComputeTerrainRecordByteOffsetForIndex(int index) {
  return (index + index * 8) << 2;
}

// FUNCTION: IMPERIALISM 0x005176e0
short TMapMgr::GetMapImprovementTierBucketOffset(short tier) {
  if (tier < 7) {
    return tier * 9;
  }
  return 0x3f;
}

// FUNCTION: IMPERIALISM 0x00517710
void TMapMgr::ApplyMapImprovementSelectionState(TCivUnit* civUnit) {
  if (civUnit->field_1C != 0) {
    GetMapImprovementSpriteBaseOffset(civUnit->orderType, 1, 0);
  } else {
    char idleState = static_cast<char>(civUnit->IsInIdleSelectionState());
    GetMapImprovementSpriteBaseOffset(civUnit->orderType, 0, idleState);
  }
}

// FUNCTION: IMPERIALISM 0x00517780
short TMapMgr::GetMapImprovementSpriteBaseOffset(short param_1, char param_2, char param_3) {
  if (param_2 != 0) {
    return 0x6c0;
  }
  short offset = g_anMapImprovementSpriteClassByOrderType[param_1] << 6;
  if (param_3 == 0) {
    offset += 0x480;
  }
  return offset;
}

// FUNCTION: IMPERIALISM 0x005177d0
int TMapMgr::GetMapImprovementTileOffsetFromClass(char classCode, int unusedParam2) {
  (void)unusedParam2;
  return classCode * 16;
}

// FUNCTION: IMPERIALISM 0x005177f0
short TMapMgr::GetMapImprovementTileSpriteOffset(short tileIndex) {
  TTerrainStateRecordView* tile = &terrainStateTable[tileIndex];
  unsigned char flags = tile->activeFlags1c;
  if (flags & 1) {
    if (tile->ownerNationTag04 < 7) {
      return (tile->ownerNationTag04 + 0x16) << 4;
    }
    return 0x1d << 4;
  }
  if ((flags >> 5) & 1) {
    if (tile->ownerNationTag04 < 7) {
      return (tile->ownerNationTag04 * 2 + 0x40) << 4;
    }
    return 0x4e << 4;
  }
  if ((flags >> 2) & 1) {
    if (tile->ownerNationTag04 < 7) {
      return (tile->ownerNationTag04 + 0x26) << 4;
    }
    return 0x2d << 4;
  }
  return 0;
}

// FUNCTION: IMPERIALISM 0x005178c0
void TMapMgr::ResetAllTileSpriteVariantIndexToSentinel() {
  for (int tileIndex = 0; tileIndex < 0x1950; ++tileIndex) {
    terrainStateTable[tileIndex].spriteVariantIndex01 = (signed char)0xff;
  }
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
    if (ownedRegions != 0 && ownedRegions->GetCount() > 0) {
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
    if (candidateRecord.terrainType00 != 5) {
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
  if (regionList->GetCount() < 1) {
    return 0;
  }
  int ordinal = 1;
  do {
    int regionId = regionList->GetIntByOrdinal(ordinal);
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
  } while (ordinal <= regionList->GetCount());
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
      if (walkRecord.terrainType00 == 5) {
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
