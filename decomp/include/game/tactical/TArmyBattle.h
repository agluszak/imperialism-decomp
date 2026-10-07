#pragma once

#include "compat.h"

#include "game/tactical/TTacticalBattle.h"
#include "game/ui_tags_common.h"
#include "game/mfc.h"

class TStream;
class TTacticalUnit;

// VTABLE: IMPERIALISM 0x0064ca68
class TArmyBattle : public TTacticalBattle {
public:
  DECLARE_DYNCREATE(TArmyBattle)
  // FUNCTION: IMPERIALISM 0x004a5c80
  virtual ~TArmyBattle() override {}
  virtual void WriteTo(TStream* stream) override;
  virtual void ReadFrom(TStream* stream) override;
  virtual void DeployUnit(TTacticalUnit* unit, TacticalTileIndex tileIndex) override;
  virtual void EndBattle(unsigned char sideWonFlag) override;

  TArmyBattle() {}

  void AllocateRecordList();

  void InitializeBattleSetupAndMaybeShowTacticalView(class TArmyStack* ourStack,
                                                     class TArmyStack* enemyStack,
                                                     int compositionClass, int fortLevel,
                                                     int battleSiteIndex);

  void LoadMap(int compositionClass, int fortLevel);

  void ComputeBattlefieldColumnCountFromUnitRanges();
};
ASSERT_SIZE(TArmyBattle, 0x78);
