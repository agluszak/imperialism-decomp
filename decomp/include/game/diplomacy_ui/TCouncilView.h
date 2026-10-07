#pragma once

#include "game/diplomacy_ui/TDiplomacyMapView.h"
#include "game/ui_tags_common.h"

// VTABLE: IMPERIALISM 0x00640258
class TCouncilView : public TDiplomacyMapView {
public:
  DECLARE_DYNCREATE(TCouncilView)

  TCouncilView();
  virtual ~TCouncilView() override;

  void DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) override;
  void HandleCursorHoverSelectionByChildHitTestAndFallback(CPoint* point,
                                                           RgnHandle hitArg) override;
  void DoPostCreate(int arg) override;

  void DisplayStats();

  void StartVoting();

  void NextTick();

  short councilNationCount; // compared (+2) against visibleVoteTier on hover
  short tickerSlots[10];    // zeroed by the slot-0x37 rebuild
};

ASSERT_SIZE(TCouncilView, 0x24e0);
