#pragma once

#include "compat.h"

// One 0x2c-byte entry in BattleRecord's per-participant detail arrays. The tag at
// +0x28 is the discriminator used by TBatRepDetLine::InstallViews. The payloads
// deliberately remain separate: the first two words and +0x24 word have different
// meanings for army, navy, merchant and item/interrupt report rows.
struct BattleReportArmyDetailPayload {
  short unitType00;
  short trainingLevel02;
  char unitName04[0x20];
  short experiencePercent24;
  short padding26;
};

struct BattleReportNavyDetailPayload {
  short shipType00;
  short trainingLevel02;
  char shipName04[0x20];
  short unused24;
  short padding26;
};

struct BattleReportMerchantDetailPayload {
  short commodityType00;
  short completed02;
  unsigned char padding04[0x24];
};

struct BattleReportItemDetailPayload {
  short itemType00;
  short itemCount02;
  unsigned char padding04[0x24];
};

struct BattleReportInterruptDetailPayload {
  short itemType00;
  short itemCount02;
  unsigned char padding04[0x20];
  short minorNationSlot24;
  short padding26;
};

union BattleReportDetailPayload {
  BattleReportArmyDetailPayload army;
  BattleReportNavyDetailPayload navy;
  BattleReportMerchantDetailPayload merchant;
  BattleReportItemDetailPayload item;
  BattleReportInterruptDetailPayload interrupt;
};

struct BattleReportDetailRecord {
  BattleReportDetailPayload payload; // +0x00
  unsigned int categoryTag28;        // +0x28: 'army', 'navy', 'merc', 'item', or 'rupt'
};

ASSERT_SIZE(BattleReportArmyDetailPayload, 0x28);
ASSERT_SIZE(BattleReportDetailPayload, 0x28);
ASSERT_SIZE(BattleReportDetailRecord, 0x2c);

// Only the region consumed by TBattleUnitsView is modeled. The participant detail
// counts and arrays are indexed in lockstep by participantIndex.
struct BattleRecord {
  unsigned char padding00[4];
  int battleType04;
  unsigned char padding08[0x242];
  short participantDetailCounts24a[2];
  unsigned char padding24e[2];
  BattleReportDetailRecord* participantDetails250[2];
};
