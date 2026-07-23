#pragma once

#include "game/diplomacy_ui/TDiplomacyMapView.h"
#include "game/ui_tags_common.h"

// Council-of-governors scene view (peace-council / voting screen). Extends the
// diplomacy map view with a small ticker/label tail (0x24c8..0x24e0). RTTI:
// classTCouncilView @ 0x00655020, base TDiplomacyMapView.
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
  // slot 0x37 — despite the inherited no-op name, TCouncilView's override rebuilds the
  // council nation-overlay geometry and labels (0x4fba70, 578 bytes).
  void DoPostCreate(int arg) override;

  // Rebuilds the council candidate name/coat-of-arms controls and (re)starts the vote
  // ticker. Non-virtual; called from DoEvent's "star" branch with ecx = this. Its
  // receiver is confirmed to be a TCouncilView (writes councilNationCount24c8 / visibleVoteTier528).
  // 0x4fc2e0, __thiscall.
  void InitializeDiplomacyCouncilViewControlsAndTicker();

  // 0x4fc630. Per-tick step driven by TCouncilTickerAnimation: advances the visible vote
  // tier, invalidates every tile marker whose pending-policy tier just became visible,
  // redraws the vote nuggets, and once the tier has swept every candidate nation,
  // resolves the 'end ' control and either re-enables it (prompting the player) or
  // silently advances the council turn state, depending on eligibility/localization
  // checks against the active nation.
  void AdvanceCivilianTerrainSelectionStep();

  short councilNationCount24c8; // +0x24c8 — compared (+2) against visibleVoteTier528 on hover
  short tickerSlots24ca[10];    // +0x24ca — zeroed by the slot-0x37 rebuild
  short pad24de;
};

ASSERT_SIZE(TCouncilView, 0x24e0);
