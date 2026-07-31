#pragma once

#include "compat.h"

#include "game/map_domain_types.h"
#include "game/strategic_terrain.h"
#include "game/core/CString.h"

class TCivUnit;
class TMilitaryUnit;

struct GlobalMapTileRecord {
  char pad_00_to_1f[0x20];
  TCivUnit* firstCivilianOrder; // 0x20
};

// Raw 0x24-byte tile record as stored in a Mac-endian scenario file. It remains separate
// from the runtime tile view because its word fields are swapped only at the load boundary.
struct ScenarioTileDiskRecord {
  unsigned char bytes00[4];
  signed char ownerNationTag04;
  unsigned char bytes05[0x14 - 0x05];
  unsigned char cityRecordIndex14[2];
  unsigned char bytes16[0x1a - 0x16];
  unsigned char tileActionOrdinal1a[2];
  unsigned char activeFlags1c[2];
  unsigned char bytes1e[2];
  int transientPointerBits20;
};
ASSERT_SIZE(ScenarioTileDiskRecord, 0x24);

// Packed 108x60 source tile pairs used by TMapMgr::ReadInRGBMap.
struct MapPixelSourceView {
  int unknown00;
  int unknown04;
  const short* packedTiles; // +0x08
};

// Runtime state for one strategic-map tile. It is distinct from ScenarioTileDiskRecord:
// the latter retains the Mac-endian bytes only at the scenario-load boundary.
struct TTerrainStateRecord {
  // -1 is the unassigned terrain sentinel; use the typed accessors below.
  StrategicTerrainKindStorage terrainKindStorage00;
  StrategicTerrainKind GetTerrainKind() const {
    return static_cast<StrategicTerrainKind>(terrainKindStorage00);
  }
  void SetTerrainKind(StrategicTerrainKind terrainKind) {
    terrainKindStorage00 = static_cast<StrategicTerrainKindStorage>(terrainKind);
  }
  signed char spriteVariantIndex01;
  // High bit marks a staged editor value; finalized variants are 0x0b..0x3a.
  RiverSpriteCodeStorage riverSpriteCode;
  // Previous owner used by the map context's "formerly of" label.
  signed char formerOwnerNationTag03;
  signed char ownerNationTag04;
  signed char regionSubtypeTag05;
  signed char adjacencyBits06;
  unsigned char ownerBorderMask07;
  unsigned char cityBorderMask08;
  unsigned char waterAdjacencyMask09;
  // Per-direction coastline and region/water border masks.
  unsigned char adjacencyMaskA0a;
  unsigned char adjacencyMaskB0b;
  signed char developmentClassNibbles0c;
  // 0 or 0x7f; gates recruit-search eligibility.
  unsigned char pendingDevelopmentFlag0d;
  unsigned char recruitSearchVisited0e;
  signed char perTileVisitedFlag0f;
  signed char markerSlotIndex10;
  signed char resourceTypeByEdge[2];
  signed char gateFlag;
  ProvinceIndexStorage cityRecordIndex;
  // Fleet/zone marker state; -1 is the reset sentinel.
  MapTileActionStateStorage tileActionState16;
  unsigned char railFlags17;
  signed char secondaryOwnerNationTag18;
  unsigned char pad19;
  // Position within the tile action-state bucket.
  short tileActionOrdinal1a;
  unsigned short activeFlags1c;
  unsigned char pad1e[0x20 - 0x1e];
  TCivUnit* firstCivilianOrder20; // queue head for this tile
};
ASSERT_SIZE(TTerrainStateRecord, 0x24);

// Runtime city/province record. The city-redraw packet snapshots its fields directly;
// the short link fields at 0x3e, 0x40, and 0x94 and CString at 0xa4 are ABI-significant.
struct Province {
  Province();
  Province& operator=(const Province& source);
  // Mac oracle: Province::GetIndex() const. Returns this record's index in the
  // active map's cityScoreTable. 0x0050e2c0.
  ProvinceIndex GetIndex() const;

  signed char ownerNationCode00;
  // Founding owner for the context panel's "formerly of" label.
  signed char formerOwnerNationCode01;
  signed char developmentStage;
  unsigned char fortLevel03;
  StrategicTileIndex cityTileIndex04; // -1 when unanchored
  short lastTurnTick;
  signed char adjacentRegionCount08;
  unsigned char pad09;
  ProvinceIndexStorage adjacentRegionIds0A[0xc]; // -1-terminated, up to 12
  // Parallel representative tiles for each adjacent province.
  StrategicTileIndex adjacentRegionAnchorTiles22[0xc];
  signed char linkedRegionCount;
  unsigned char byte3B;
  unsigned char byte3C;
  unsigned char pad3D;
  StrategicTileIndex secondaryNeighborTileIndex3e;
  StrategicTileIndex primaryNeighborTileIndex40;
  StrategicTileIndex linkedTileIndices42[0x20];
  short resourceDevelopmentCounts82[10]; // resource types 7..0x10
  unsigned char pad96[2];
  TMilitaryUnit* stationedUnitChain98;
  int cityScoreValue;
  unsigned char navyOrderReachableA0; // transient navy-order eligibility
  unsigned char exploredByNationMaskA1;
  signed char resourcePresenceMaskA2;
  signed char regionClassA3;
  CString cityNameA4;
};
ASSERT_SIZE(Province, 0xa8);

struct HexSpiralSearchState {
  int row;
  int col;
  int ring;
  int direction;
  int stepInRing;
};
