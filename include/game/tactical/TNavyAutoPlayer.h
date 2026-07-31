#pragma once

#include "compat.h"

#include "game/tactical/TNavyPlayer.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x006697c0
class TNavyAutoPlayer : public TNavyPlayer {
public:
  // Two-phase init: forwards to TNavyPlayer::INavyPlayer with the watch flag set.
  // 0x0059f0e0, __thiscall.
  void INavyAutoPlayer(TTaskForce* force, char isOurSide, int nationIndex);

  DECLARE_DYNCREATE(TNavyAutoPlayer)
  // NOOP: verified empty in original 0x0059f0a0
  virtual ~TNavyAutoPlayer() override {}            // slot 0x01 (scalar deleting destructor)
  virtual void StartBattle() override;              // slot 0x0a 0x59f110
  virtual void AdvanceTacticalTurnPulse() override; // slot 0x0b 0x59f160

  // NOOP: verified empty in original 0x0059f042 (no standalone TNavyAutoPlayer::TNavyAutoPlayer body exists: construction is fully inlined into CreateObject 0x0059f040; that address is its operator-new call site)
  TNavyAutoPlayer() {}
};
ASSERT_SIZE(TNavyAutoPlayer, 0x30);
