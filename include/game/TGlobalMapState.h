#pragma once

#define TGLOBALMAPSTATE_VTABLE_SLOT(n) virtual void GlobalMapStateDummy##n(void) = 0

struct GlobalMapTileRecord {
  char pad_00_to_1f[0x20];
  class TCivilianOrderState* firstCivilianOrder; // 0x20
};

struct TTerrainStateRecordView {
  unsigned char pad00[2];
  unsigned char roadFlag;
  unsigned char pad03[0x11 - 0x03];
  signed char resourceTypeByEdge[2];
  unsigned char gateFlag;
  short cityRecordIndex;
  unsigned char pad16[0x24 - 0x16];
};

struct TGlobalMapCityScoreRecord {
  unsigned char pad00[2];
  unsigned char developmentStage;
  unsigned char pad03;
  short ownerNationSlot;
  short lastTurnTick;
  unsigned char pad08[0x3A - 0x08];
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
  unsigned char pad94[0x9C - 0x94];
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

  unsigned char pad04[8];
  TTerrainStateRecordView* terrainStateTable;
  TGlobalMapCityScoreRecord* cityScoreTable;
  unsigned char pad14[4];
  int cityScoreTotal;

  class TCivilianOrderState* GetFirstCivilianOrderOnTile(short tileIndex) {
    return reinterpret_cast<struct GlobalMapTileRecord*>(terrainStateTable)[tileIndex]
        .firstCivilianOrder;
  }
};

extern "C" TGlobalMapState* g_pGlobalMapState;
