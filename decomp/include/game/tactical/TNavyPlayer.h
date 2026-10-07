#pragma once

#include "compat.h"

#include "game/navy_tactical_types.h"
#include "game/map/TTacticalPlayer.h"
#include "game/mfc.h"

class TTacticalUnit;

// VTABLE: IMPERIALISM 0x006696b0
class TNavyPlayer : public TTacticalPlayer {
public:
  DECLARE_DYNCREATE(TNavyPlayer)
  // NOOP: verified empty in original 0x0059ebe0
  virtual ~TNavyPlayer() override {}
  virtual void ApplyChanges(unsigned char sideWonFlag) override;
  virtual void RemoveCapturedUnit(TTacticalUnit* unit) override;
  virtual void AddCapturedUnit(TTacticalUnit* unit) override;
  // Navy slice (base TTacticalPlayer ends at +0x28).
  class TTaskForce* taskForce; // +0x28 the side's fleet order node
                               // eliminated and prunes its order head after commit)
  NavyTargeting targetingMode; // +0x2c targeting mode set by the navy toolbar

  void INavyPlayer(TTaskForce* force, char isOurSide, bool watchFlag, int nationIndex);

  // NOOP: verified empty in original 0x0059eb82
  TNavyPlayer() {}
};
ASSERT_SIZE(TNavyPlayer, 0x30);
