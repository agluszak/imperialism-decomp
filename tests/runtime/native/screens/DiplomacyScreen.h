#pragma once

#ifndef IMPERIALISM_DIPLOMACY_SCREEN_H
#define IMPERIALISM_DIPLOMACY_SCREEN_H

#ifndef IMPERIALISM_RUNTIME_TESTS
#error DiplomacyScreen is test-only and must not be included in the production build
#endif

#include "MainViewScreen.h"

class TDiplomacyMapView;
class TOffersPanelView;

// The foreign minister's diplomacy map.
//
// Two scenarios drive it -- DiplomacyScreenTest for its own sake and TradeScreenTest to declare
// a war before trading -- and both spelled out the same three vocabularies by hand: the minister
// topic buttons addressed as tag arithmetic ('scr0' + n, 'ovr0' + n), the policy toggle whose
// expected value depends on what the policy already was, and the offers panel's pre-armed
// response, which has to be queued *before* PoseOffer because PoseOffer does not return until
// the sheet is answered.
//
// A script asks this for a topic or a response; the tag arithmetic and the panel's blocking
// contract stay here.
class DiplomacyScreen : public MainViewScreen {
public:
  DiplomacyScreen();

  // This screen's view class, turn event and name -- the single source of the
  // identity. RT_OPEN_TO/RT_AWAIT_CURRENT read it, so a script never repeats either.
  static MainViewScreenIdentity Identity();

  static bool IsCurrent();

  TDiplomacyMapView* View() const;

  // The four controls the minister screen is not usable without: the info panel, the treaty
  // topic, the map key and the way back.
  bool HasMinisterControls() const;
  // The map toolbar's diplomacy button swaps to its selected artwork while this screen is up.
  // A question about the toolbar rather than about this view, but it is only meaningful here,
  // and the toolbar dialog outlives the map view it was raised from.
  bool ToolbarButtonShowsSelectedArt() const;

  // Actions. Selecting a nation is how every treaty action is applied: the action topic decides
  // what the click means, so the same call inspects a nation, or builds a consulate, or offers
  // an alliance.
  RuntimeActionResult SelectNation(short nationSlot);
  RuntimeActionResult ShowRelationshipOverlay();
  RuntimeActionResult ShowTreaties();
  RuntimeActionResult SelectAllianceAction();
  RuntimeActionResult SelectDeclareWarAction();
  RuntimeActionResult Close();

  // Queries.
  short SelectedNation() const;
  short RelationshipOverlaySourceNation() const;
  // The treaties topic is the selected one. Selecting it is asynchronous, so a script that goes
  // on to pick one of its actions waits for this first.
  bool TreatiesTopicIsSelected() const;
  // As above, and its default action is the consulate -- the state a nation click depends on
  // when no other treaty action has been chosen.
  bool TreatiesTopicIsActive() const;
  int ActionCode() const;
  // The icon the map draws over a nation for the policy currently posted towards it.
  short PolicyIconForNation(short nationSlot);

  // The offers panel. Posing an offer enters the game's own modal loop and does not return
  // until the player answers, so a response has to be queued first -- ArmAcceptResponse() then
  // PoseNonAggressionOffer(), never the other way round.
  bool AcceptPublishesOfferEvent() const;
  bool RejectPublishesOfferEvent() const;
  RuntimeActionResult ArmAcceptResponse();
  RuntimeActionResult ArmRejectResponse();
  RuntimeActionResult PoseNonAggressionOffer(short sourceNation, short targetNation);
  bool LastResponseWasAccept() const;
  bool LastResponseWasReject() const;

private:
  TOffersPanelView* OffersPanel() const;
  bool ResponsePublishesOfferEvent(int responseTag) const;
  RuntimeActionResult ArmResponse(int responseTag, const char* what);
  bool LastResponseWas(int responseTag) const;

  TDiplomacyMapView* diplomacyView;
};

// Reads as Diplomacy().ShowTreaties() in a script.
inline DiplomacyScreen Diplomacy() {
  return DiplomacyScreen();
}

#endif
