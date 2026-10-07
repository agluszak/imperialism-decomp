#pragma once

#include "compat.h"

#include "game/map_domain_types.h"
#include "game/strategic_terrain.h"
#include "game/core/CString.h"

class TCivUnit;
class TMilitaryUnit;

struct GlobalMapTileRecord {
  char pad_00_to_1f[0x20];
  TCivUnit* firstCivilianOrder;
};

struct ScenarioTileDiskRecord {
  unsigned char bytes00[4];
  signed char ownerNationTag;
  unsigned char bytes05[0x14 - 0x05];
  unsigned char cityRecordIndex[2];
  unsigned char bytes16[0x1a - 0x16];
  unsigned char tileActionOrdinal[2];
  unsigned char activeFlags[2];
  unsigned char bytes1e[2];
  int transientPointerBits;
};
ASSERT_SIZE(ScenarioTileDiskRecord, 0x24);

// Packed 108x60 source tile pairs used by TMapMgr::ReadInRGBMap.
struct MapPixelSourceView {
  int unknown00;
  int unknown04;
  const short* packedTiles;
};

struct TTerrainStateRecord {
  // -1 is the unassigned terrain sentinel; use the typed accessors below.
  StrategicTerrainKindStorage terrainKindStorage;
  StrategicTerrainKind GetTerrainKind() const {
    return static_cast<StrategicTerrainKind>(terrainKindStorage);
  }
  void SetTerrainKind(StrategicTerrainKind terrainKind) {
    terrainKindStorage = static_cast<StrategicTerrainKindStorage>(terrainKind);
  }
  signed char spriteVariantIndex;
  // High bit marks a staged editor value; finalized variants are 0x0b..0x3a.
  RiverSpriteCodeStorage riverSpriteCode;
  // Previous owner used by the map context's "formerly of" label.
  signed char formerOwnerNationTag;
  signed char ownerNationTag;
  signed char regionSubtypeTag;
  signed char adjacencyBits;
  unsigned char ownerBorderMask;
  unsigned char cityBorderMask;
  unsigned char waterAdjacencyMask;
  // Per-direction coastline and region/water border masks.
  unsigned char adjacencyMaskA0a;
  unsigned char adjacencyMaskB0b;
  signed char developmentClassNibbles;
  // 0 or 0x7f; gates recruit-search eligibility.
  unsigned char pendingDevelopmentFlag;
  unsigned char recruitSearchVisited;
  signed char perTileVisitedFlag;
  signed char markerSlotIndex;
  signed char resourceTypeByEdge[2];
  signed char gateFlag;
  ProvinceIndexStorage cityRecordIndex;
  // Fleet/zone marker state; -1 is the reset sentinel.
  MapTileActionStateStorage tileActionState;
  unsigned char railFlags;
  signed char secondaryOwnerNationTag;
  unsigned char pad19;
  // Position within the tile action-state bucket.
  short tileActionOrdinal;
  unsigned short activeFlags;
  unsigned char pad1e[0x20 - 0x1e];
  TCivUnit* firstCivilianOrder; // queue head for this tile
};
ASSERT_SIZE(TTerrainStateRecord, 0x24);

struct Province {
  Province();
  Province& operator=(const Province& source);
  ProvinceIndex GetIndex() const;

  signed char ownerNationCode;
  // Founding owner for the context panel's "formerly of" label.
  signed char formerOwnerNationCode;
  signed char developmentStage;
  signed char fortLevel;
  StrategicTileIndex cityTileIndex; // -1 when unanchored
  short lastTurnTick;
  signed char adjacentRegionCount;
  unsigned char pad09;
  ProvinceIndexStorage adjacentRegionIds[0xc]; // -1-terminated, up to 12
  // Parallel representative tiles for each adjacent province.
  StrategicTileIndex adjacentRegionAnchorTiles[0xc];
  signed char linkedRegionCount;
  unsigned char byte3B;
  unsigned char byte3C;
  unsigned char pad3D;
  StrategicTileIndex secondaryNeighborTileIndex;
  StrategicTileIndex primaryNeighborTileIndex;
  StrategicTileIndex linkedTileIndices[0x20];
  short resourceDevelopmentCounts[10]; // resource types 7..0x10
  unsigned char pad96[2];
  TMilitaryUnit* stationedUnitChain;
  int cityScoreValue;
  unsigned char navyOrderReachable; // transient navy-order eligibility
  unsigned char exploredByNationMask;
  signed char resourcePresenceMask;
  signed char regionClass;
  CString cityName;
};
ASSERT_SIZE(Province, 0xa8);

struct HexSpiralSearchState {
  int row;
  int col;
  int ring;
  int direction;
  int stepInRing;
};
