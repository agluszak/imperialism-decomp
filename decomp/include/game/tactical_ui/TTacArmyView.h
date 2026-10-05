#pragma once

#include "compat.h"

#include "game/tactical/TTacticalBattleView.h"
#include "game/ui_tags_common.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00644fd0
class TTacArmyView : public TTacticalBattleView {
public:
  DECLARE_DYNCREATE(TTacArmyView)
  virtual ~TTacArmyView() override;             // slot 0x01 (scalar deleting destructor)
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x5aa2e0
  virtual void DrawTile(TacticalTileIndex tileIndex,
                        RECT* clipRect) override; // slot 0x6c 0x5aa900
  short battlefieldColumnCount; // +0xd8 copy of battle battlefieldColumnCount
  unsigned char padDA[2];       // +0xda

  // NOOP: verified empty in original 0x005a9d26 (no standalone TTacArmyView::TTacArmyView body exists: CreateObject 0x005a9cf0 inlines this default ctor, calling the TTacticalBattleView base ctor directly at that site)
  TTacArmyView() {}

  void StuffValues(int compositionClass, class TArmyBattle* battle);
};
ASSERT_SIZE(TTacArmyView, 0xdc);
