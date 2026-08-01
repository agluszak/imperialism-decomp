#pragma once

#include "decomp_types.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_military.h"

struct CStr32 {
  char data[0x20];

  // Defined in-class: the original inlines this into every stack declaration (the
  // stride-0x20 store loop at 0x4a1c47 in TArmyMgr::ReadFrom is an array of two of
  // these being constructed), while still emitting the standalone copy below because
  // the vector-construction helper takes the constructor's address.
  // FUNCTION: IMPERIALISM 0x004a31c0
  CStr32() {
    data[0] = 0;
  }
};
ASSERT_SIZE(CStr32, 0x20);

// Fixed-capacity long string used by the map-action report records. The Windows
// constructor is the six-byte body at 0x4a31e0; an array of two instances is why
// ResolveStrategicBattle invokes VC5's vector-construction helper with a
// 0xff-byte stride. Mac symbols call the corresponding type CStr255.
struct CStr255 {
  char data[0xff];

  // In-class for the same reason as CStr32 above (stride-0xff loop at 0x4a1c58).
  // FUNCTION: IMPERIALISM 0x004a31e0
  CStr255() {
    data[0] = 0;
  }
};
ASSERT_SIZE(CStr255, 0xff);

// One detail row in a map-order action report. Conflict resolution initially retains a
// live unit pointer while refreshing ship state, then finalizes that four-byte slot to
// the category tag consumed by the battle-report UI.
struct MapOrderBattleSideChildRecord {
  short resourceType;    // +0x00 -- child TShip::type
  short stockOrRequired; // +0x02 -- child TShip::strength
  char nameBuffer[0x20]; // +0x04 -- copy of child TShip::name
  short strengthBucket;  // +0x24 -- child TShip::experience / 100
  char pad26[2];
  unsigned int detailIdentity28; // +0x28

  MapOrderBattleSideChildRecord() {
    nameBuffer[0] = 0;
  }
};
ASSERT_SIZE(MapOrderBattleSideChildRecord, 0x2c);

// Stack-local working record shared by task-force conflict resolution and nation
// map-order interaction processing. Its 0x0c..0x257 tail is also embedded unchanged in
// MapContextActionRecord, which takes ownership of the finalized per-side detail rows.
struct MapOrderBattleSnapshot {
  unsigned char nationIds[2];       // +0x00/+0x01, indexed by participant side
  unsigned char participantIndex02; // +0x02
  unsigned char reservedByte03;     // +0x03
  int actionType04;                 // +0x04
  void* targetObject08;             // +0x08
  CStr32 nameBuffer[2];             // +0x0c..+0x4b -- per-side terrain/nation label text
  CStr255 overlayLabel[2];          // +0x4c..+0x249 -- per-side selection overlay label text
  short childCount[2];              // +0x24a/+0x24c
  MapOrderBattleSideChildRecord* childRecords[2]; // +0x250/+0x254

  ~MapOrderBattleSnapshot() {
    delete[] childRecords[0];
    delete[] childRecords[1];
  }
};
ASSERT_SIZE(MapOrderBattleSnapshot, 0x258);

class TTaskForce;

// 0x0054f110
void BuildMapOrderBattleSideSnapshot(MapOrderBattleSnapshot* snapshot, int side, TTaskForce* entry);
// 0x0054f340
void RefreshMapOrderBattleSideSnapshot(MapOrderBattleSnapshot* snapshot, int side,
                                       TTaskForce* entry);
