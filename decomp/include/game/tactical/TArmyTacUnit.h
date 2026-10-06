#pragma once

#include "game/tactical/TTacticalUnit.h"
#include "game/mfc.h"

class TMilitaryUnit;

// VTABLE: IMPERIALISM 0x00669660
class TArmyTacUnit : public TTacticalUnit {
public:
  DECLARE_DYNCREATE(TArmyTacUnit)
  // NOOP: verified empty in original 0x0059b3c0
  virtual ~TArmyTacUnit() override {}          // slot 0x01 (scalar deleting destructor)
  virtual int GetBaseActionPoints() override;  // slot 0x0a 0x5a6120
  virtual int GetUnitRange() override;         // slot 0x0b 0x5a6140
  virtual float GetBaseAttackPower() override; // slot 0x0c 0x5a6180
  virtual float GetDamageScale() override;     // slot 0x0d 0x5a61a0
  virtual void ApplyDamage(int damageA, int damageB) override; // slot 0x0e 0x5a61c0

  // Army state appended to TTacticalUnit at +0x34.
  int morale34;                // +0x34 init = sourceUnit38->strength34; floors at 0 -> state1c = 1
  TMilitaryUnit* sourceUnit38; // +0x38 back-pointer (persisted as its persistentUnitId20 id)
  unsigned char flag3c;        // +0x3c = (source unitOrder == 2 && category[type] == 0)
  unsigned char pad3d[3];      // +0x3d
  int sapTargetTileIndex;      // +0x40 pending sap/mine target tile; -1 = none
  float projectionScores[5];   // +0x44 strength/quality-weighted military attributes 0..4

  // NOOP: verified empty in original 0x005a5ed2
  TArmyTacUnit() {}

  void IArmyTacUnit(TMilitaryUnit* source);

  void ComputeTacticalProjectionScoreVector(); // 0x5a5fe0, __thiscall
  int GetUID() const;                          // 0x5a6210, Mac oracle
};

ASSERT_SIZE(TArmyTacUnit, 0x58);
ASSERT_OFFSET(TArmyTacUnit, projectionScores, 0x44);
