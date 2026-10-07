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
  virtual TShip* GetRealShip();                // slot 0x10 0x59ed60 (Mac: GetRealShip)

  void ApplyNavalDamage(float damageAmount, NavyTargeting targeting);

  TShip* sourceShip;           // +0x34 source strategic ship (range delegate, 0x5a6330)
  int secondaryCombatStrength; // +0x38
  int baseActionPoints;        // +0x3c

  // NOOP: verified empty in original 0x005a6242 (no standalone TNavyTacUnit::TNavyTacUnit body exists: construction is fully inlined into CreateObject 0x005a6240; that address is its operator-new call site)
  TNavyTacUnit() {}

  void InitializeFromSourceShip(TShip* sourceShip); // 0x5a6290
};
ASSERT_SIZE(TNavyTacUnit, 0x40);
