#pragma once

#include "game/TTacticalPlayer.h"
#include "game/mfc.h"

class TTacticalUnit;

// VTABLE: IMPERIALISM 0x006696b0
class TNavyPlayer : public TTacticalPlayer {
public:
  DECLARE_DYNCREATE(TNavyPlayer)
  virtual ~TNavyPlayer() override; // slot 0x01 (scalar deleting destructor)
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
  virtual void CommitTacticalResultsToSourceUnits(int unused) override;      // slot 0x0d 0x59edd0
  virtual void RemoveTacticalUnitFromUnitList(TTacticalUnit* unit) override; // slot 0x0e 0x59ee60
  virtual void AddTacticalUnitToUnitListHead(TTacticalUnit* unit) override;  // slot 0x0f 0x59eea0
  // slot 0x10 AlwaysTrueTacticalPredicate10 inherited unchanged (0x59adf0)
  // slot 0x11 ProceedAfterBattleIntroAccepted inherited unchanged (0x59ae10)
  // Navy slice (base TTacticalPlayer ends at +0x28).
  class TTaskForce* taskForce28; // +0x28 the side's fleet order node (0x59edd0 marks it
                                 // eliminated and prunes its order head after commit)
  int shipDisplayMode2c;         // +0x2c ship-panel display mode set by the navy toolbar
                                 // (hull=0, crew=1, sail=2)

  TNavyPlayer();
};
