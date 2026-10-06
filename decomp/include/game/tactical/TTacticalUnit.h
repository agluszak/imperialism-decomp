#pragma once

#include "game/app/TObject.h"
#include "game/map_domain_types.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0066a1b8
class TTacticalUnit : public TObject {
public:
  DECLARE_DYNCREATE(TTacticalUnit)
  // FUNCTION: IMPERIALISM 0x005a5df0
  virtual ~TTacticalUnit() override {}                // slot 0x01 (scalar deleting destructor)
  virtual int GetBaseActionPoints();                  // slot 0x0a 0x5a5d40
  virtual int GetUnitRange();                         // slot 0x0b 0x5a5d60
  virtual float GetBaseAttackPower();                 // slot 0x0c 0x5a5d80
  virtual float GetDamageScale();                     // slot 0x0d 0x5a5da0
  virtual void ApplyDamage(int damageA, int damageB); // slot 0x0e 0x5a5e70
  virtual void FlipUnitSideAffiliation();             // slot 0x0f 0x5a5eb0

  int strength4;                // +0x04 current strength; ApplyDamage floors at 0 -> state1c = 3
  TacticalTileIndex tileIndex8; // +0x08 tactical grid index (init -2 = not yet placed)
  int unitTypeC;                // +0x0c unit-type id; indexes the 0x669858/0x669898 per-type tables
  int qualityLevel10;           // +0x10 = source unit experiencePercent / 100 at army init
  int ownerNationIndex14;       // +0x14 owning nation index (matched vs the stack's side)
  char selectedFlag;            // +0x18
  unsigned char pad19[3];       // +0x19
  int state1c;                  // +0x1c 0 = ok, 1 = morale broken, 3 = destroyed
  int side20;                   // +0x20 battle side (serialized)
  short field24;                // +0x24 serialized word
  short pad26;                  // +0x26
  int actionPoints28;           // +0x28 remaining action points (seeded from GetBaseActionPoints)
  int aiStateCode2c;            // +0x2c AI stance code (indexes the 0x699500 weight rows)
  TTacticalUnit* attackTarget;

  // NOOP: verified empty in original 0x005a5d12
  TTacticalUnit() {}

  void ITacticalUnit();
};

ASSERT_SIZE(TTacticalUnit, 0x34);
