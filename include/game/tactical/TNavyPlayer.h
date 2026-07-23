#pragma once

#include "game/map/TTacticalPlayer.h"
#include "game/mfc.h"

class TTacticalUnit;

// VTABLE: IMPERIALISM 0x006696b0
class TNavyPlayer : public TTacticalPlayer {
public:
  DECLARE_DYNCREATE(TNavyPlayer)
  virtual ~TNavyPlayer() override; // slot 0x01 (scalar deleting destructor)
  virtual void CommitTacticalResultsToSourceUnits(int unused) override;      // slot 0x0d 0x59edd0
  virtual void RemoveTacticalUnitFromUnitList(TTacticalUnit* unit) override; // slot 0x0e 0x59ee60
  virtual void AddTacticalUnitToUnitListHead(TTacticalUnit* unit) override;  // slot 0x0f 0x59eea0
  // Navy slice (base TTacticalPlayer ends at +0x28).
  class TTaskForce* taskForce28; // +0x28 the side's fleet order node (0x59edd0 marks it
                                 // eliminated and prunes its order head after commit)
  int shipDisplayMode2c;         // +0x2c ship-panel display mode set by the navy toolbar
                                 // (hull=0, crew=1, sail=2)

  TNavyPlayer();
};
