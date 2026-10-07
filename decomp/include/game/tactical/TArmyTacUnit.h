#pragma once

#include "game/tactical/TTacticalUnit.h"
#include "game/mfc.h"

class TMilitaryUnit;

// VTABLE: IMPERIALISM 0x00669660
class TArmyTacUnit : public TTacticalUnit {
public:
  DECLARE_DYNCREATE(TArmyTacUnit)
  // NOOP: verified empty in original 0x0059b3c0
  virtual ~TArmyTacUnit() override {}
  virtual int GetBaseActionPoints() override;
  virtual int GetUnitRange() override;
  virtual float GetBaseAttackPower() override;
  virtual float GetDamageScale() override;
  virtual void ApplyDamage(int damageA, int damageB) override;

  // Army state appended to TTacticalUnit at +0x34.
  int morale;                // +0x34 init = sourceUnit->strength; floors at 0 -> state1c = 1
  TMilitaryUnit* sourceUnit; // +0x38 back-pointer (persisted as its persistentUnitId id)
  unsigned char flag3c;      // +0x3c = (source unitOrder == 2 && category[type] == 0)
  int sapTargetTileIndex;    // +0x40 pending sap/mine target tile; -1 = none
  float projectionScores[5]; // +0x44 strength/quality-weighted military attributes 0..4

  // NOOP: verified empty in original 0x005a5ed2
  TArmyTacUnit() {}

  void IArmyTacUnit(TMilitaryUnit* source);

  void ComputeTacticalProjectionScoreVector();
  int GetUID() const;
};

ASSERT_SIZE(TArmyTacUnit, 0x58);
ASSERT_OFFSET(TArmyTacUnit, projectionScores, 0x44);
