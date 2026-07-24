#pragma once

#include "compat.h"

#include "game/tactical/TNavyPlayer.h"
#include "game/map_domain_types.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00669760
class TNavyHumanPlayer : public TNavyPlayer {
public:
  DECLARE_DYNCREATE(TNavyHumanPlayer)
  virtual ~TNavyHumanPlayer() override; // slot 0x01 (scalar deleting destructor)
  virtual void DeploymentClick(TacticalTileIndex tileIndex); // slot 0x12 0x59efc0

  TNavyHumanPlayer();
};
ASSERT_SIZE(TNavyHumanPlayer, 0x30);
