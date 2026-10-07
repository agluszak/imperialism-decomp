#pragma once

#include "compat.h"

#include "game/tactical/TNavyPlayer.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x006697c0
class TNavyAutoPlayer : public TNavyPlayer {
public:
  void INavyAutoPlayer(TTaskForce* force, char isOurSide, int nationIndex);

  DECLARE_DYNCREATE(TNavyAutoPlayer)
  // NOOP: verified empty in original 0x0059f0a0
  virtual ~TNavyAutoPlayer() override {}
  virtual void StartBattle() override;
  virtual void NextMove() override;

  // NOOP: verified empty in original 0x0059f042
  TNavyAutoPlayer() {}
};
ASSERT_SIZE(TNavyAutoPlayer, 0x30);
