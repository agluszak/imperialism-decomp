#pragma once

#include "compat.h"

#include "game/navy_tactical_types.h"
#include "game/tactical/TTacticalUnit.h"
#include "game/mfc.h"

class TShip;

// VTABLE: IMPERIALISM 0x00669708
class TNavyTacUnit : public TTacticalUnit {
public:
  DECLARE_DYNCREATE(TNavyTacUnit)
  // NOOP: verified empty in original 0x0059edb0
  virtual ~TNavyTacUnit() override {}          // slot 0x01 (scalar deleting destructor)
  virtual int GetBaseActionPoints() override;  // slot 0x0a 0x5a6310
  virtual int GetUnitRange() override;         // slot 0x0b 0x5a6330
  virtual float GetBaseAttackPower() override; // slot 0x0c 0x5a6350
  virtual float GetDamageScale() override;     // slot 0x0d 0x5a6370
  short GetSourceShipTypeDescriptorWord();     // 0x5a6390
  // Navy-only added virtual: returns the unit's source fleet (the old
  // ConstructTNavyPlayerBaseState name was Ghidra junk).
  virtual TShip* GetSourceShip(); // slot 0x10 0x59ed60 (Mac: GetRealShip)

  // Non-virtual (TNavyBattle::EvaluateAndResolveTacticalActionAgainstTileOccupant, 0x5a5730,
  // calls it directly on a downcast occupant4 -- TNavyBattle only ever holds navy occupants).
  // targeting is the attacking side's TNavyPlayer::targetingMode2c. Mode 0 applies
  // ratio A to strength4 and full damage to the second combat pool; mode 1 applies
  // ratio B to strength4 and ratio A to the second pool; mode 2 applies ratio A only
  // to the second pool and may also remove 10 action points. Destroys the unit
  // (state1c = 3) when either combat pool drops to <= 0. 0x5a63c0, __thiscall, RET 0x8.
  void ApplyNavalDamage(float damageAmount, NavyTargeting targeting);

  // Navy slice (+0x34..+0x40): fully covered. A field-xref sweep finds every access --
  // +0x34 in GetSourceShip/InitializeFromSourceShip/GetUnitRange, +0x38 in
  // InitializeFromSourceShip and ApplyNavalDamage, +0x3c in
  // GetBaseActionPoints (0x5a6310) -- and nothing touches +0x40 or beyond.
  TShip* sourceShip34; // +0x34 source strategic ship (range delegate, 0x5a6330)
  // Second combat-resource pool alongside strength4 (TTacticalUnit); its domain is not
  // yet cross-checked against a UI reader.
  int secondaryCombatStrength38; // +0x38
  int baseActionPoints3c;        // +0x3c

  // NOOP: verified empty in original 0x005a6242 (no standalone TNavyTacUnit::TNavyTacUnit body exists: construction is fully inlined into CreateObject 0x005a6240; that address is its operator-new call site)
  TNavyTacUnit() {}

  void InitializeFromSourceShip(TShip* sourceShip); // 0x5a6290
};
ASSERT_SIZE(TNavyTacUnit, 0x40);
