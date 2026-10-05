#pragma once

#include "decomp_types.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_military.h"

struct CStr32 {
  char data[0x20];

  // FUNCTION: IMPERIALISM 0x004a31c0
  CStr32() {
    data[0] = 0;
  }
};
ASSERT_SIZE(CStr32, 0x20);

struct CStr255 {
  char data[0xff];

  // In-class for the same reason as CStr32 above (stride-0xff loop at 0x4a1c58).
  // FUNCTION: IMPERIALISM 0x004a31e0
  CStr255() {
    data[0] = 0;
  }
};
ASSERT_SIZE(CStr255, 0xff);

enum MapContextReportKind {
  kMapContextReportLandBattle = 0,
  kMapContextReportSeaBattle = 1,
  kMapContextReportMerchantInterception = 2,
  kMapContextReportPreemptedLandBattle = 3,
  kMapContextReportUncontestedTakeover = 4
};
typedef int MapContextReportKindStorage;

struct MapOrderBattleSideChildRecord {
  short resourceType;    // +0x00 -- child TShip::type
  short stockOrRequired; // +0x02 -- child TShip::strength
  char nameBuffer[0x20]; // +0x04 -- copy of child TShip::name
  short strengthBucket;  // +0x24 -- child TShip::experience / 100
  char pad26[2];
  unsigned int detailIdentity; // +0x28

  MapOrderBattleSideChildRecord() {
    nameBuffer[0] = 0;
  }
};
ASSERT_SIZE(MapOrderBattleSideChildRecord, 0x2c);

struct MapOrderBattleSnapshot {
  unsigned char nationIds[2];               // +0x00/+0x01, indexed by participant side
  unsigned char reportParticipantIndex;     // +0x02
  unsigned char displayedParticipantIndex;  // +0x03
  MapContextReportKindStorage reportKind04; // +0x04
  void* targetObject;                       // +0x08
  CStr32 nameBuffer[2];                     // +0x0c..+0x4b -- per-side terrain/nation label text
  CStr255 overlayLabel[2]; // +0x4c..+0x249 -- per-side selection overlay label text
  short childCount[2];     // +0x24a/+0x24c
  MapOrderBattleSideChildRecord* childRecords[2]; // +0x250/+0x254

  ~MapOrderBattleSnapshot() {
    delete[] childRecords[0];
    delete[] childRecords[1];
  }
};
ASSERT_SIZE(MapOrderBattleSnapshot, 0x258);

class TTaskForce;

void BuildMapOrderBattleSideSnapshot(MapOrderBattleSnapshot* snapshot, int side, TTaskForce* entry);
void RefreshMapOrderBattleSideSnapshot(MapOrderBattleSnapshot* snapshot, int side,
                                       TTaskForce* entry);
