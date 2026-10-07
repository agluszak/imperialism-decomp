#pragma once

#include "compat.h"

#include "game/tactical/TTacticalBattleView.h"
#include "game/ui_tags_common.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00644fd0
class TTacArmyView : public TTacticalBattleView {
public:
  DECLARE_DYNCREATE(TTacArmyView)
  virtual ~TTacArmyView() override;
  virtual void Draw(RECT* rectBuffer) override;
  virtual void DrawTile(TacticalTileIndex tileIndex, RECT* clipRect) override;
  short battlefieldColumnCount; // +0xd8 copy of battle battlefieldColumnCount
  unsigned char padDA[2];

  // NOOP: verified empty in original 0x005a9d26
  TTacArmyView() {}

  void StuffValues(int compositionClass, class TArmyBattle* battle);
};
ASSERT_SIZE(TTacArmyView, 0xdc);
