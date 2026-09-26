#pragma once

#include "game/tactical/TTacticalUnit.h"
#include "game/mfc.h"

class TMilitaryUnit;

// One land unit in a tactical battle. The grid/state slice (+0x04..+0x30) lives on
// TTacticalUnit; this class appends the army slice at +0x34. Base edge (TTacticalUnit)
// recovered from RTTI CRuntimeClass chain: TArmyTacUnit -> TTacticalUnit -> TObject ->
// CObject.
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
  virtual void ApplyTacticalDamage(int damageA, int damageB) override; // slot 0x0e 0x5a61c0

  // Army state appended to TTacticalUnit at +0x34.
  int morale34;                // +0x34 init = sourceUnit38->strength34; floors at 0 -> state1c = 1
  TMilitaryUnit* sourceUnit38; // +0x38 back-pointer (persisted as its persistentUnitId20 id)
  unsigned char flag3c;        // +0x3c = (source unitOrder == 2 && category[type] == 0)
  unsigned char pad3d[3];      // +0x3d
  int sapTargetTileIndex40;    // +0x40 pending sap/mine target tile; -1 = none
  float projectionScores44[5]; // +0x44 strength/quality-weighted military attributes 0..4

  // Both original construction sites inline the ctor as a bare vptr store.
  // NOOP: verified empty in original 0x005a5ed2 (no standalone TArmyTacUnit::TArmyTacUnit body exists: construction is fully inlined into CreateObject 0x005a5ed0; that address is its operator-new call site)
  TArmyTacUnit() {}

  // Initializes a newly allocated tactical record from its strategic army unit.
  // 0x005a5f20, __thiscall.
  void IArmyTacUnit(TMilitaryUnit* source);

  // Mac oracle: CalculateAttributes. Rebuilds the five projection scores from
  // the source unit's attributes and experience, using current tactical strength.
  void ComputeTacticalProjectionScoreVector(); // 0x5a5fe0, __thiscall
  int GetUID() const;                          // 0x5a6210, Mac oracle
};

ASSERT_SIZE(TArmyTacUnit, 0x58);
ASSERT_OFFSET(TArmyTacUnit, projectionScores44, 0x44);
