#pragma once

#include "game/TNavyPlayer.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x006697c0
class TNavyAutoPlayer : public TNavyPlayer {
public:
  DECLARE_DYNCREATE(TNavyAutoPlayer)
  virtual ~TNavyAutoPlayer() override;              // slot 0x01 (scalar deleting destructor)
  virtual void StartBattle() override;              // slot 0x0a 0x59f110
  virtual void AdvanceTacticalTurnPulse() override; // slot 0x0b 0x59f160

  TNavyAutoPlayer();
};
