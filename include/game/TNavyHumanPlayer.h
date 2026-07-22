#pragma once

#include "game/TNavyPlayer.h"
#include "game/map_domain_types.h"
#include "game/mfc.h"

// VTABLE: IMPERIALISM 0x00669760
class TNavyHumanPlayer : public TNavyPlayer {
public:
  DECLARE_DYNCREATE(TNavyHumanPlayer)
  virtual ~TNavyHumanPlayer() override; // slot 0x01 (scalar deleting destructor)
  // slot 0x02 Serialize inherited unchanged (0x485e90)
  // slot 0x03 AssertValid inherited unchanged (0x412bf0)
  // slot 0x04 Dump inherited unchanged (0x412c10)
  // slot 0x05 WriteTo inherited unchanged (0x485f70)
  // slot 0x06 ReadFrom inherited unchanged (0x485f90)
  // slot 0x07 Free inherited unchanged (0x59aee0)
  // slot 0x08 ShallowClone inherited unchanged (0x4798d0)
  // slot 0x09 ShallowFree inherited unchanged (0x415ce0)
  // slot 0x0a StartBattle inherited unchanged (0x59ad70)
  // slot 0x0b AdvanceTacticalTurnPulse inherited unchanged (0x59ad90)
  // slot 0x0c NoOpTacticalPlayerHook0C inherited unchanged (0x59adb0)
  // slot 0x0d CommitTacticalResultsToSourceUnits inherited unchanged (0x59edd0)
  // slot 0x0e RemoveTacticalUnitFromUnitList inherited unchanged (0x59ee60)
  // slot 0x0f AddTacticalUnitToUnitListHead inherited unchanged (0x59eea0)
  // slot 0x10 AlwaysTrueTacticalPredicate10 inherited unchanged (0x59adf0)
  // slot 0x11 ProceedAfterBattleIntroAccepted inherited unchanged (0x59ae10)
  virtual void DeploymentClick(TacticalTileIndex tileIndex); // slot 0x12 0x59efc0

  TNavyHumanPlayer();
};
