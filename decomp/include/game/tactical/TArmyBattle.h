#pragma once

#include "compat.h"

#include "game/tactical/TTacticalBattle.h"
#include "game/ui_tags_common.h"
#include "game/mfc.h"

// Forward declarations for types referenced by generated signatures.
class TStream;
class TTacticalUnit;

// VTABLE: IMPERIALISM 0x0064ca68
class TArmyBattle : public TTacticalBattle {
public:
  DECLARE_DYNCREATE(TArmyBattle)
  // FUNCTION: IMPERIALISM 0x004a5c80
  virtual ~TArmyBattle() override {}               // slot 0x01 (scalar deleting destructor)
  virtual void WriteTo(TStream* stream) override;  // slot 0x05 0x5a4da0
  virtual void ReadFrom(TStream* stream) override; // slot 0x06 0x5a4990
  virtual void DeployUnit(TTacticalUnit* unit,
                                        TacticalTileIndex tileIndex) override; // slot 0x0c 0x5a51e0
  virtual void EndBattle(unsigned char sideWonFlag) override; // slot 0x12 0x5a5320, Mac oracle

  TArmyBattle() : TTacticalBattle() {}

  void AllocateRecordList();

  void InitializeBattleSetupAndMaybeShowTacticalView(class TArmyStack* ourStack,
                                                         class TArmyStack* enemyStack,
                                                         int compositionClass, int fortLevel,
                                                         int battleSiteIndex);

  void LoadMap(int compositionClass, int fortLevel);

  void ComputeBattlefieldColumnCountFromUnitRanges();
};
ASSERT_SIZE(TArmyBattle, 0x78);
