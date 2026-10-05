#pragma once

#include "game/diplomacy_ui/TDiplomacyMapView.h"
#include "game/ui_tags_common.h"

// VTABLE: IMPERIALISM 0x00640258
class TCouncilView : public TDiplomacyMapView {
public:
  DECLARE_DYNCREATE(TCouncilView)

  TCouncilView();
  virtual ~TCouncilView() override; // slot 0x01 (scalar deleting destructor 0x430660)

  void DoEvent(int commandId, TEventHandler* sourceHandler,
               TEvent* event) override; // slot 0x0f 0x4fbd60
  void HandleCursorHoverSelectionByChildHitTestAndFallback(CPoint* point,
                                                           RgnHandle hitArg) override; // slot 0x35
  void DoPostCreate(int arg) override;

  void DisplayStats();

  void StartVoting();

  void NextTick();

  short councilNationCount; // +0x24c8 — compared (+2) against visibleVoteTier on hover
  short tickerSlots[10];    // +0x24ca — zeroed by the slot-0x37 rebuild
  short pad24de;
};

ASSERT_SIZE(TCouncilView, 0x24e0);
