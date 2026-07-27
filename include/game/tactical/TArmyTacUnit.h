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
  virtual ~TArmyTacUnit() override;            // slot 0x01 (scalar deleting destructor)
  virtual int GetBaseActionPoints() override;  // slot 0x0a 0x5a6120
  virtual int GetUnitRange() override;         // slot 0x0b 0x5a6140
  virtual float GetBaseAttackPower() override; // slot 0x0c 0x5a6180
  virtual float GetDamageScale() override;     // slot 0x0d 0x5a61a0
  virtual void ApplyTacticalDamage(int damageA, int damageB) override; // slot 0x0e 0x5a61c0

  // Army slice (+0x34..+0x54), from the duplicated init in TArmyBattle::ReadFrom
  // (0x5a4990), the base-state ctor 0x5a5f20, and the float writers at 0x5a5fe0.
  int morale34;                // +0x34 init = sourceUnit38->strength34; floors at 0 -> state1c = 1
  TMilitaryUnit* sourceUnit38; // +0x38 back-pointer (persisted as its persistentUnitId20 id)
  unsigned char flag3c;        // +0x3c = (source unitOrder == 2 && category[type] == 0)
  unsigned char pad3d[3];      // +0x3d
  int sapTargetTileIndex40;    // +0x40 pending sap/mine target tile; -1 = none
  float field44;               // +0x44
  float field48;               // +0x48
  float field4c;               // +0x4c
  float field50;               // +0x50
  float field54;               // +0x54

  // Both original construction sites inline the ctor as a bare vptr store.
  // NOOP: verified empty in original 0x005a5ed2 (no standalone TArmyTacUnit::TArmyTacUnit body exists: construction is fully inlined into CreateObject 0x005a5ed0; that address is its operator-new call site)
  TArmyTacUnit() {}

  // Post-construction init from the source army unit (called unconditionally after
  // `new TArmyTacUnit()`, even on alloc failure -- a real init method, not the ctor).
  // TArmyBattle::ReadFrom duplicates this fill inline. 0x005a5f20, __thiscall.
  void IArmyTacUnit(TMilitaryUnit* source);

  // Fills the float projection vector (+0x44..+0x54) from the source unit's five
  // per-type stat percentages scaled by strength. 0x5a5fe0, __thiscall.
  void ComputeTacticalProjectionScoreVector();
};

ASSERT_SIZE(TArmyTacUnit, 0x58);
