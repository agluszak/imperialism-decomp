#pragma once

#include "decomp_types.h"

struct CStr32 {
  char data[0x20];

  CStr32() {
    data[0] = 0;
  }
};
ASSERT_SIZE(CStr32, 0x20);

// Fixed-capacity long string used by the map-action report records. The Windows
// constructor is the six-byte body at 0x4a31e0; an array of two instances is why
// ResolveMapOrderPairConflictStep invokes VC5's vector-construction helper with a
// 0xff-byte stride. Mac symbols call the corresponding type CStr255.
struct CStr255 {
  char data[0xff];

  CStr255();
};
ASSERT_SIZE(CStr255, 0xff);

// Per-child record built by BuildMapOrderBattleSideSnapshot for one side of a task-force
// order conflict. Populated from a TShip node reached through the owning TTaskForce's
// childOrderList (TMapOrderChildLinkNode::payload, reinterpreted here since these
// particular children are ships, not nested task-force entries -- see the field-offset
// evidence in BuildMapOrderBattleSideSnapshot).
struct MapOrderBattleSideChildRecord {
  short resourceType;    // +0x00 -- child TShip::resourceType04
  short stockOrRequired; // +0x02 -- child TShip::stockLevel1c
  char nameBuffer[0x20]; // +0x04 -- copy of child TShip::displayName18
  short strengthBucket;  // +0x24 -- signed-divide-by-100 bucket of child TShip::field30
  char pad26[2];
  void* childPtr; // +0x28 -- the child TShip* itself
};
ASSERT_SIZE(MapOrderBattleSideChildRecord, 0x2c);

// Stack-local working record ResolveMapOrderPairConflictStep builds for each side (0 =
// left, 1 = right) of a task-force order conflict: display strings for the eventual
// conflict-resolution message, plus a snapshot of each side's current children.
struct MapOrderBattleSnapshot {
  char requiredCountByte[2]; // +0x00/+0x01, indexed by side: low byte of
                             // entry->required_count (used elsewhere as a nation slot)
  char pad02[0xa];           // +0x02..+0x0b
  CStr32 nameBuffer[2];      // +0x0c..+0x4b -- per-side terrain/nation label text
  CStr255 overlayLabel[2];   // +0x4c..+0x249 -- per-side selection overlay label text
  short childCount[2];       // +0x24a/+0x24c
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
