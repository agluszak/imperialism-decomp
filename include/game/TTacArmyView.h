#pragma once

#include "game/TTacticalBattleView.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00644fd0
class TTacArmyView : public TTacticalBattleView {
public:
  DECLARE_DYNCREATE(TTacArmyView)
  virtual ~TTacArmyView() override;             // slot 0x01 (scalar deleting destructor)
  virtual void Draw(RECT* rectBuffer) override; // slot 0x44 0x5aa2e0
  virtual void DrawTacticalTileInClipRect(TacticalTileIndex tileIndex,
                                          RECT* clipRect) override; // slot 0x6c 0x5aa900
  // Base TTacticalBattleView actually ends at +0xd8 -- toolbarD0/battlefieldOriginOffsetXD4
  // (written by the live-battle initializer 0x5a9d90; battlefieldOriginOffsetXD4 is
  // re-derived as the backdrop source-x origin in the rect applier 0x5aa2e0) are
  // TTacticalBattleView's own fields (its sole subclass), inherited here, not
  // TTacArmyView-own. This class's only genuinely own bytes:
  short battlefieldColumnCountD8; // +0xd8 copy of battle battlefieldColumnCount34
  unsigned char padDA[2];         // +0xda

  TTacArmyView();

  // Initializes the live battle-view state from the freshly set-up TArmyBattle
  // (called by InitializeBattleSetupAndMaybeDispatchTurnEventED8 after resolving the
  // 'DLOG' control). Not a real constructor despite the symbols.csv name.
  // 0x5a9d90, __thiscall, ret 8.
  void InitializeBattlefieldView(int compositionClass, class TArmyBattle* battle);
};
