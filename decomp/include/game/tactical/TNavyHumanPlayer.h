#pragma once

#include "compat.h"

#include "game/tactical/TNavyPlayer.h"
#include "game/map_domain_types.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00669760
class TNavyHumanPlayer : public TNavyPlayer {
public:
  void INavyHumanPlayer(TTaskForce* force, char isOurSide, int nationIndex);

  DECLARE_DYNCREATE(TNavyHumanPlayer)
  // NOOP: verified empty in original 0x0059ef50
  virtual ~TNavyHumanPlayer() override {}
  virtual void DeploymentClick(TacticalTileIndex tileIndex);

  // NOOP: verified empty in original 0x0059eef2
  TNavyHumanPlayer() {}
};
ASSERT_SIZE(TNavyHumanPlayer, 0x30);
