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
  virtual ~TNavyTacUnit() override {}
  virtual int GetBaseActionPoints() override;
  virtual int GetUnitRange() override;
  virtual float GetBaseAttackPower() override;
  virtual float GetDamageScale() override;
  short GetSourceShipTypeDescriptorWord();
  virtual TShip* GetRealShip(); // slot 0x10 0x59ed60 (Mac: GetRealShip)

  void ApplyNavalDamage(float damageAmount, NavyTargeting targeting);

  TShip* sourceShip; // +0x34 source strategic ship
  int secondaryCombatStrength;
  int baseActionPoints;

  // NOOP: verified empty in original 0x005a6242
  TNavyTacUnit() {}

  void InitializeFromSourceShip(TShip* sourceShip);
};
ASSERT_SIZE(TNavyTacUnit, 0x40);
