#pragma once

#include "game/app/TObject.h"
#include "game/map_domain_types.h"
#include "game/mfc.h"

// Base class for one unit taking part in a tactical battle (army or navy). Owns the
// grid/state slice shared by both branches; TArmyTacUnit/TNavyTacUnit append their
// own fields at +0x34. Base edge (TObject) recovered from RTTI CRuntimeClass chain:
// TTacticalUnit -> TObject -> CObject.
// VTABLE: IMPERIALISM 0x0066a1b8
class TTacticalUnit : public TObject {
public:
  DECLARE_DYNCREATE(TTacticalUnit)
  virtual ~TTacticalUnit() override; // slot 0x01 (scalar deleting destructor)
  virtual int GetBaseActionPoints(); // slot 0x0a 0x5a5d40
  // Fire/attack range in hex tiles -- the max distance at which this unit can engage a
  // target (NOT movement range; that derives from action points, slot 0x0a). Consumed by
  // IsTacticalTargetTileReachableForAction (gates on hexDistance <= range) and by the
  // threat-field seed (GetUnitRange() + 1). Base returns 0; the army/navy overrides read
  // the per-unit-type 0x6699e8 range table (defending artillery gets +1). Mac oracle name
  // is TTacticalUnit::GetRange().
  virtual int GetUnitRange(); // slot 0x0b 0x5a5d60
  // Per-unit-type base attack power / incoming-damage scale, indexed by unitTypeC on the
  // Army/Navy overrides (g_afTacticalBaseAttackPowerByUnitType / g_afTacticalDamageScaleByUnitType
  // / g_afTacticalNavyBaseAttackPowerByUnitType / g_afTacticalNavyDamageScaleByUnitType); also
  // reused generically by TTacticalBattle::ProcessTacticalUnitState1TurnStep to score
  // morale-break retreat/destruction odds. Base class returns the shared default constant.
  // Real x87 float return (FLD/RET), not an int -- verify any override matches.
  virtual float GetBaseAttackPower();                         // slot 0x0c 0x5a5d80
  virtual float GetDamageScale();                             // slot 0x0d 0x5a5da0
  virtual void ApplyTacticalDamage(int damageA, int damageB); // slot 0x0e 0x5a5e70
  // Toggles side20 between 0 and 1; invoked when a unit is handed to the other
  // side's list (TTacticalPlayer::AddTacticalUnitToUnitListHead).
  virtual void FlipUnitSideAffiliation(); // slot 0x0f 0x5a5eb0

  // Layout (object is 0x34 per RTTI; derived classes append at +0x34). Recovered from
  // the tactical receive/command handlers (0x5a1010..0x5a53e0), ApplyTacticalDamage
  // (0x5a5e70), and the duplicated unit init in TArmyBattle::ReadFrom (0x5a4990).
  int strength4; // +0x04 current strength; ApplyTacticalDamage floors at 0 -> state1c = 3
  TacticalTileIndex tileIndex8; // +0x08 tactical grid index (init -2 = not yet placed)
  int unitTypeC;                // +0x0c unit-type id; indexes the 0x669858/0x669898 per-type tables
  int qualityLevel10;           // +0x10 = source unit experiencePercent38 / 100 at army init
  int ownerNationIndex14;       // +0x14 owning nation index (matched vs the stack's side)
  char selectedFlag18;          // +0x18
  unsigned char pad19[3];       // +0x19
  int state1c;                  // +0x1c 0 = ok, 1 = morale broken, 3 = destroyed
  int side20;                   // +0x20 battle side (serialized)
  short field24;                // +0x24 serialized word
  short pad26;                  // +0x26
  int actionPoints28;           // +0x28 remaining action points (seeded from GetBaseActionPoints)
  int aiStateCode2c;            // +0x2c AI stance code (indexes the 0x699500 weight rows)
  // +0x30 current attack-target unit (in the opposing side's list). Read and written by
  // HandleTacticalCommandTag_targ (0x005a3f42 read, 0x005a4101 write on selectedUnit1c),
  // which looks the value up in the opposing unit list and stores the newly cycled target.
  // (The earlier "0-499 bar" scalar reading was a wrong-offset mismodel: TTacArmyView's
  // second stat bar reads [occupant+0x34] = TArmyTacUnit::morale34, not +0x30.)
  TTacticalUnit* attackTarget30;

  // NOOP: verified empty in original (trivial inline ctor: both concrete branches
  // inline construction as a bare vptr store, so the base ctor must stay empty and
  // in-class).
  // NOOP: verified empty in original 0x005a5d12 (no standalone TTacticalUnit::TTacticalUnit body exists: construction is fully inlined into CreateObject 0x005a5d10; that address is its operator-new call site)
  TTacticalUnit() {}

  // Seeds the common per-unit-in-battle state (tileIndex8=-2 "not placed" sentinel,
  // actionPoints28 from the virtual GetBaseActionPoints()) after a concrete derived
  // class (TArmyTacUnit/TNavyTacUnit) has already installed its own vtable. No
  // confirmed caller found yet (not reached via a direct xref). 0x5a5e30.
  void ITacticalUnit();
};

ASSERT_SIZE(TTacticalUnit, 0x34);
