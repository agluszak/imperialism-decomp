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
  virtual ~TNavyPlayer() override {} // slot 0x01 (scalar deleting destructor)
  virtual void CommitTacticalResultsToSourceUnits(int unused) override;      // slot 0x0d 0x59edd0
  virtual void RemoveTacticalUnitFromUnitList(TTacticalUnit* unit) override; // slot 0x0e 0x59ee60
  virtual void AddTacticalUnitToUnitListHead(TTacticalUnit* unit) override;  // slot 0x0f 0x59eea0
  // Navy slice (base TTacticalPlayer ends at +0x28).
  class TTaskForce* taskForce28; // +0x28 the side's fleet order node (0x59edd0 marks it
                                 // eliminated and prunes its order head after commit)
  NavyTargeting targetingMode2c; // +0x2c targeting mode set by the navy toolbar

  // Two-phase init (MacApp IViewClass idiom): seeds the side's flags, allocates the
  // unit list, and builds one TNavyTacUnit per ship in `force`. No Mac oracle name
  // covers it, so it follows the IViewClass naming this tree already uses.
  // 0x0059ec20, __thiscall.
  void INavyPlayer(TTaskForce* force, char isOurSide, char watchFlag, int nationIndex);

  // In-class inline: the original has no out-of-line TNavyPlayer::TNavyPlayer -- every
  // caller absorbs it, so an out-of-line definition pessimizes them into a call.
  // NOOP: verified empty in original 0x0059eb82 (no standalone TNavyPlayer::TNavyPlayer body exists: construction is fully inlined into CreateObject 0x0059eb80; that address is its operator-new call site)
  TNavyPlayer() {}
};
ASSERT_SIZE(TNavyPlayer, 0x30);
