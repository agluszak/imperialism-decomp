#pragma once

class TStationedUnitNode;

#define TGLOBALMAPSTATE_VTABLE_SLOT(n) virtual void GlobalMapStateDummy##n(void) = 0

struct GlobalMapTileRecord {
  char pad_00_to_1f[0x20];
  class TCivilianOrderState* firstCivilianOrder; // 0x20
};

struct TTerrainStateRecordView {
  unsigned char pad00[2];
  unsigned char roadFlag;
  unsigned char pad03;
  signed char ownerNationTag04; // 0x04 — owning nation code (flood fill 0x004dbac0)
  unsigned char pad05;
  signed char adjacencyBits06; // 0x06 — 6-direction neighbor-link bitmask
  unsigned char pad07[0x11 - 0x07];
  signed char resourceTypeByEdge[2];
  unsigned char gateFlag;
  short cityRecordIndex;
  unsigned char pad16[0x1c - 0x16];
  unsigned char activeFlags1c; // bit 0 tested by 0x004d71b0 / 0x004dfae0 region scans
  unsigned char pad1d[0x24 - 0x1d];
};

struct TGlobalMapCityScoreRecord {
  signed char ownerNationCode00; // 0x00 — owning nation code (0x00517c30 compares it)
  unsigned char pad01;
  unsigned char developmentStage;
  unsigned char pad03;
  short ownerNationSlot;
  short lastTurnTick;
  signed char adjacentRegionCount08; // 0x08 — entries used in adjacentRegionIds0A
  unsigned char pad09;
  short adjacentRegionIds0A[0x18]; // 0x0a..0x3a — neighboring region record ids
  signed char linkedRegionCount;
  unsigned char pad3B[0x42 - 0x3B];
  short linkedRegionIds[0x21];
  short stage1CounterA;
  short stage1CounterB;
  short pad88;
  short stage1CounterC;
  short stage1CounterD;
  short stage2CounterA;
  short stage2CounterB;
  short stage2CounterC;
  unsigned char pad94[0x98 - 0x94];
  TStationedUnitNode* stationedUnitChain98; // 0x98 — singly-linked unit chain (next at +0x14)
  int cityScoreValue;
  unsigned char padA0[0xA8 - 0xA0];
};

class TGlobalMapState {
public:
  TGLOBALMAPSTATE_VTABLE_SLOT(00);
  TGLOBALMAPSTATE_VTABLE_SLOT(01);
  TGLOBALMAPSTATE_VTABLE_SLOT(02);
  TGLOBALMAPSTATE_VTABLE_SLOT(03);
  TGLOBALMAPSTATE_VTABLE_SLOT(04);
  TGLOBALMAPSTATE_VTABLE_SLOT(05);
  TGLOBALMAPSTATE_VTABLE_SLOT(06);
  TGLOBALMAPSTATE_VTABLE_SLOT(07);
  TGLOBALMAPSTATE_VTABLE_SLOT(08);
  TGLOBALMAPSTATE_VTABLE_SLOT(09);
  TGLOBALMAPSTATE_VTABLE_SLOT(10);
  TGLOBALMAPSTATE_VTABLE_SLOT(11);
  TGLOBALMAPSTATE_VTABLE_SLOT(12);
  TGLOBALMAPSTATE_VTABLE_SLOT(13);
  TGLOBALMAPSTATE_VTABLE_SLOT(14);
  TGLOBALMAPSTATE_VTABLE_SLOT(15);
  TGLOBALMAPSTATE_VTABLE_SLOT(16);
  TGLOBALMAPSTATE_VTABLE_SLOT(17);
  TGLOBALMAPSTATE_VTABLE_SLOT(18);
  TGLOBALMAPSTATE_VTABLE_SLOT(19);
  TGLOBALMAPSTATE_VTABLE_SLOT(20);
  TGLOBALMAPSTATE_VTABLE_SLOT(21);
  TGLOBALMAPSTATE_VTABLE_SLOT(22);
  TGLOBALMAPSTATE_VTABLE_SLOT(23);
  TGLOBALMAPSTATE_VTABLE_SLOT(24);
  TGLOBALMAPSTATE_VTABLE_SLOT(25);
  TGLOBALMAPSTATE_VTABLE_SLOT(26);
  TGLOBALMAPSTATE_VTABLE_SLOT(27);
  TGLOBALMAPSTATE_VTABLE_SLOT(28);
  TGLOBALMAPSTATE_VTABLE_SLOT(29);
  TGLOBALMAPSTATE_VTABLE_SLOT(30);
  TGLOBALMAPSTATE_VTABLE_SLOT(31);
  TGLOBALMAPSTATE_VTABLE_SLOT(32);
  TGLOBALMAPSTATE_VTABLE_SLOT(33);
  TGLOBALMAPSTATE_VTABLE_SLOT(34);
  TGLOBALMAPSTATE_VTABLE_SLOT(35);
  TGLOBALMAPSTATE_VTABLE_SLOT(36);
  TGLOBALMAPSTATE_VTABLE_SLOT(37);
  TGLOBALMAPSTATE_VTABLE_SLOT(38);
  TGLOBALMAPSTATE_VTABLE_SLOT(39);
  TGLOBALMAPSTATE_VTABLE_SLOT(40);
  TGLOBALMAPSTATE_VTABLE_SLOT(41);
  TGLOBALMAPSTATE_VTABLE_SLOT(42);
  TGLOBALMAPSTATE_VTABLE_SLOT(43);
  TGLOBALMAPSTATE_VTABLE_SLOT(44);
  TGLOBALMAPSTATE_VTABLE_SLOT(45);
  TGLOBALMAPSTATE_VTABLE_SLOT(46);
  TGLOBALMAPSTATE_VTABLE_SLOT(47);
  TGLOBALMAPSTATE_VTABLE_SLOT(48);
  virtual char CallMetricSlotC4(int regionIndex, int edgeIndex) = 0;
  TGLOBALMAPSTATE_VTABLE_SLOT(50);
  TGLOBALMAPSTATE_VTABLE_SLOT(51);
  TGLOBALMAPSTATE_VTABLE_SLOT(52);
  TGLOBALMAPSTATE_VTABLE_SLOT(53);
  TGLOBALMAPSTATE_VTABLE_SLOT(54);
  TGLOBALMAPSTATE_VTABLE_SLOT(55);
  TGLOBALMAPSTATE_VTABLE_SLOT(56);
  TGLOBALMAPSTATE_VTABLE_SLOT(57);
  TGLOBALMAPSTATE_VTABLE_SLOT(58);
  TGLOBALMAPSTATE_VTABLE_SLOT(59);
  TGLOBALMAPSTATE_VTABLE_SLOT(60);
  TGLOBALMAPSTATE_VTABLE_SLOT(61);
  TGLOBALMAPSTATE_VTABLE_SLOT(62);
  TGLOBALMAPSTATE_VTABLE_SLOT(63);
  TGLOBALMAPSTATE_VTABLE_SLOT(64);
  TGLOBALMAPSTATE_VTABLE_SLOT(65);
  TGLOBALMAPSTATE_VTABLE_SLOT(66);
  TGLOBALMAPSTATE_VTABLE_SLOT(67);
  TGLOBALMAPSTATE_VTABLE_SLOT(68);
  TGLOBALMAPSTATE_VTABLE_SLOT(69);
  TGLOBALMAPSTATE_VTABLE_SLOT(70);
  TGLOBALMAPSTATE_VTABLE_SLOT(71);
  TGLOBALMAPSTATE_VTABLE_SLOT(72);
  TGLOBALMAPSTATE_VTABLE_SLOT(73);
  TGLOBALMAPSTATE_VTABLE_SLOT(74);
  // slot 0x12c — notify a city record changed (TGreatPower slot 0x0c, body 0x004d71b0).
  virtual void NotifyCityRecordSlot12C(int cityRecordIndex) = 0;
  TGLOBALMAPSTATE_VTABLE_SLOT(76);
  // slot 0x134 — link a region/marker to a nation (TGreatPower slot 0x3b, 0x004dfae0).
  virtual void LinkRegionToNationSlot134(int regionId, int nationSlot) = 0;

  unsigned char pad04[8];
  TTerrainStateRecordView* terrainStateTable;
  TGlobalMapCityScoreRecord* cityScoreTable;
  unsigned char pad14[4];
  int cityScoreTotal;
  char* scenarioTagText1c; // 0x1c — first char '+' enables extra seeding in 0x004d71b0

  // True when any region owned by nationA has a neighboring region owned by nationB.
  // Walks g_apTerrainTypeDescriptorTable[nationA]->ownedRegionList90 against the
  // 0xa8-stride region records in cityScoreTable.
  char AreNationsBorderLinked(int nationA, int nationB);

  static void ComputeHexNeighborTileIndices(short tileIndex, short* neighborTiles,
                                            char wrapHorizontally);
  static short GetWrappedHexNeighborTileIndexByDirection(short tileIndex, short direction);

  class TCivilianOrderState* GetFirstCivilianOrderOnTile(short tileIndex) {
    return reinterpret_cast<struct GlobalMapTileRecord*>(terrainStateTable)[tileIndex]
        .firstCivilianOrder;
  }
};

extern "C" TGlobalMapState* g_pGlobalMapState;
