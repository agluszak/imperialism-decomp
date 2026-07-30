#pragma once

#ifndef IMPERIALISM_END_TURN_FLOW_H
#define IMPERIALISM_END_TURN_FLOW_H

#ifndef IMPERIALISM_RUNTIME_TESTS
#error EndTurnFlow is test-only and must not be included in the production build
#endif

#include "scenarios/RuntimeScriptFragment.h"

class TWindow;

// Ending one turn and coming back to the strategic map.
//
// Four scenarios each implemented this, and they diverged on which safety checks they kept.
// The differences were not deliberate:
//
//   game-over guard (0x11f8)            present in 2 of 4
//   modal default-command handling      present in 2 of 4
//   modal wait                          one waited for the stack to unwind, one only for idle
//   re-submitting Done after an alert   present in 2 of 4
//   modal-empty in the final predicate  MISSING from PlayerBuyOnlyTradeTest, which therefore
//                                       could have accepted the map "arriving" underneath a
//                                       dialog that was still up
//
// This fragment is the strict union of all four, so every caller gets every check. The
// consequence is deliberate: two migrated scenarios became stricter, which is why they have to
// be run rather than merely compiled.
//
// Options are opt-in because they change what the sequence is allowed to see, not how it
// behaves once it sees it.
class EndTurnFlow : public RuntimeScriptFragment {
public:
  EndTurnFlow();

  // Reject any trade offer put to the player during turn processing. Without this an offer
  // desk is an unexpected screen and the sequence fails.
  EndTurnFlow& RejectOffers();
  // Accept the offers instead. Mutually exclusive with RejectOffers; the last call wins.
  EndTurnFlow& AcceptOffers();
  // Require that exactly one economic turn elapsed. On by default; turn off only for a caller
  // that deliberately drives several turns in one sequence.
  EndTurnFlow& ExpectExactlyOneTurn();
  EndTurnFlow& AllowAnyTurnAdvance();

  // Activate Done and drive the whole sequence. Call from a script with RT_RUN. Safe to run
  // again for a second turn: it rewinds itself.
  RuntimeScriptStatus ToNextStrategicMap(RuntimeScriptScenario& scenario);

  // What the sequence saw, for a caller that asserts on it afterwards.
  short StartingTurn() const;
  short EndingTurn() const;
  bool SawTurnAlert() const;
  bool SawDealBook() const;
  bool SawNewspaper() const;
  bool SawOfferDesk() const;

private:
  RuntimeScriptStatus Advance();
  bool BackOnMapWithNewTurn() const;
  bool AStepIsReady() const;

  // The modal we last confirmed, so the wait afterwards can tell "this one is gone" from
  // "the stack is empty" -- turn processing pops one dialog and pushes the next, so the depth
  // never reaches zero between them.
  TWindow* confirmedModal;
  short startingTurn;
  short endingTurn;
  bool rejectOffers;
  bool acceptOffers;
  bool expectExactlyOneTurn;
  bool leftDealBook;
  bool closedNewspaper;
  bool resubmittedDone;
  bool sawTurnAlert;
  bool sawDealBook;
  bool sawNewspaper;
  bool sawOfferDesk;
  bool started;
};

#endif
