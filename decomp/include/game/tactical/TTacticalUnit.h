#pragma once

#include "game/app/TObject.h"
#include "game/map_domain_types.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x0066a1b8
class TTacticalUnit : public TObject {
public:
  DECLARE_DYNCREATE(TTacticalUnit)
  // FUNCTION: IMPERIALISM 0x005a5df0
  virtual ~TTacticalUnit() override {}
  virtual int GetBaseActionPoints();
  virtual int GetUnitRange();
  virtual float GetBaseAttackPower();
  virtual float GetDamageScale();
  virtual void ApplyDamage(int damageA, int damageB);
  virtual void FlipUnitSideAffiliation();

  int strength;                // current strength; ApplyDamage floors at 0 -> status = 3
  TacticalTileIndex tileIndex; // tactical grid index (init -2 = not yet placed)
  int unitType;                // unit-type id; indexes the 0x669858/0x669898 per-type tables
  int qualityLevel;            // = source unit experiencePercent / 100 at army init
  int ownerNationIndex;        // owning nation index (matched vs the stack's side)
  bool selectedFlag;
  unsigned char pad19[3];
  int status;    // 0 = ok, 1 = morale broken, 3 = destroyed
  int side;      // battle side (serialized)
  short field24; // serialized word
  short pad26;
  int actionPoints; // remaining action points (seeded from GetBaseActionPoints)
  int aiStateCode;  // AI stance code (indexes the 0x699500 weight rows)
  TTacticalUnit* attackTarget;

  // NOOP: verified empty in original 0x005a5d12
  TTacticalUnit() {}

  void ITacticalUnit();
};

ASSERT_SIZE(TTacticalUnit, 0x34);
