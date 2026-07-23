#pragma once

#include "compat.h"

#include "game/tactical/TTacticalUnit.h"
#include "game/mfc.h"

class TShip;

// VTABLE: IMPERIALISM 0x00669708
class TNavyTacUnit : public TTacticalUnit {
public:
  DECLARE_DYNCREATE(TNavyTacUnit)
  virtual ~TNavyTacUnit() override;            // slot 0x01 (scalar deleting destructor)
  virtual int GetBaseActionPoints() override;  // slot 0x0a 0x5a6310
  virtual int GetUnitRange() override;         // slot 0x0b 0x5a6330
  virtual float GetBaseAttackPower() override; // slot 0x0c 0x5a6350
  virtual float GetDamageScale() override;     // slot 0x0d 0x5a6370
  // Navy-only added virtual: returns the unit's source fleet (the old
  // ConstructTNavyPlayerBaseState name was Ghidra junk).
  virtual TShip* GetSourceShip(); // slot 0x10 0x59ed60 (Mac: GetRealShip)

  // Non-virtual (TNavyBattle::EvaluateAndResolveTacticalActionAgainstTileOccupant, 0x5a5730,
  // calls it directly on a downcast occupant4 -- TNavyBattle only ever holds navy occupants).
  // damageMode is the attacking side's TNavyPlayer::shipDisplayMode2c (the hull/crew/sail
  // ship-panel toggle also serves as the aim-point selector): 0 = hull (full damage to strength4,
  // 25% splash to crewStrength38), 1 = crew (25%/75% split between strength4/crewStrength38),
  // 2 = sail (25% to strength4, plus a 1-in-10-chance 10-point hit to baseActionPoints3c
  // when rand()%10 < damageAmount). Destroys the unit (state1c = 3) when strength4 or
  // crewStrength38 drops to <= 0. 0x5a63c0, __thiscall, RET 0x8.
  void ApplyTacticalDamageAndDeathState(float damageAmount, int damageMode);

  // Navy slice (+0x34..+0x40): fully covered. A field-xref sweep finds every access --
  // +0x34 in GetSourceShip/InitializeFromSourceShip/GetUnitRange, +0x38 in
  // InitializeFromSourceShip and ApplyTacticalDamageAndDeathState, +0x3c in
  // GetBaseActionPoints (0x5a6310) -- and nothing touches +0x40 or beyond.
  TShip* sourceShip34; // +0x34 source strategic ship (range delegate, 0x5a6330)
  // Second combat-resource pool alongside strength4 (TTacticalUnit); provisional name from
  // ApplyTacticalDamageAndDeathState's damage-mode split (see above) -- not yet cross-checked
  // against a UI reader.
  int crewStrength38;     // +0x38
  int baseActionPoints3c; // +0x3c

  TNavyTacUnit();
  void InitializeFromSourceShip(TShip* sourceShip); // 0x5a6290
};
ASSERT_SIZE(TNavyTacUnit, 0x40);
