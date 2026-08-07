#include "EndTurnFlow.h"

#include "RuntimeObservation.h"
#include "scenarios/RuntimeScriptMacros.h"
#include "screens/DealBookScreen.h"
#include "screens/ModalScreen.h"
#include "screens/NewspaperScreen.h"
#include "screens/OfferScreen.h"
#include "screens/StrategicMapScreen.h"

#include "game/core/global_data_tables.h"
#include "game/turn_event_codes.h"
#include "game/ui_core/TWindow.h"
#include "game/ui_screens/TSimMgr.h"

EndTurnFlow::EndTurnFlow()
    : confirmedModal(0), startingTurn(0), endingTurn(0), rejectOffers(false), acceptOffers(false),
      expectExactlyOneTurn(true), leftDealBook(false), closedNewspaper(false),
      resubmittedDone(false), sawTurnAlert(false), sawDealBook(false), sawNewspaper(false),
      sawOfferDesk(false), started(false) {}

EndTurnFlow& EndTurnFlow::RejectOffers() {
  rejectOffers = true;
  acceptOffers = false;
  return *this;
}

EndTurnFlow& EndTurnFlow::AcceptOffers() {
  acceptOffers = true;
  rejectOffers = false;
  return *this;
}

EndTurnFlow& EndTurnFlow::ExpectExactlyOneTurn() {
  expectExactlyOneTurn = true;
  return *this;
}

EndTurnFlow& EndTurnFlow::AllowAnyTurnAdvance() {
  expectExactlyOneTurn = false;
  return *this;
}

short EndTurnFlow::StartingTurn() const {
  return startingTurn;
}

short EndTurnFlow::EndingTurn() const {
  return endingTurn;
}

bool EndTurnFlow::SawTurnAlert() const {
  return sawTurnAlert;
}

bool EndTurnFlow::SawDealBook() const {
  return sawDealBook;
}

bool EndTurnFlow::SawNewspaper() const {
  return sawNewspaper;
}

bool EndTurnFlow::SawOfferDesk() const {
  return sawOfferDesk;
}

RuntimeScriptStatus EndTurnFlow::ToNextStrategicMap(RuntimeScriptScenario& scenario) {
  if (!started) {
    // Rewind, so a caller looping over several turns gets a fresh sequence each time rather
    // than resuming the previous one. The scenario object is a never-reconstructed singleton,
    // so this cannot be left to a constructor.
    BeginFragment(scenario);
    startingTurn = g_pSimMgr != 0 ? g_pSimMgr->economicTurn : -1;
    endingTurn = startingTurn;
    leftDealBook = false;
    closedNewspaper = false;
    resubmittedDone = false;
    sawTurnAlert = false;
    sawDealBook = false;
    sawNewspaper = false;
    sawOfferDesk = false;
    confirmedModal = 0;
    started = true;
  }
  RuntimeScriptStatus status = Advance();
  if (status != kRuntimeScriptRunning) {
    started = false;
  }
  return status;
}

bool EndTurnFlow::BackOnMapWithNewTurn() const {
  // StrategicMapScreen::IsCurrent includes the modal-empty check, which is the guard
  // PlayerBuyOnlyTradeTest omitted: without it the map can look like it has arrived while a
  // dialog is still up.
  return StrategicMapScreen::IsCurrent() && g_pSimMgr != 0 &&
         g_pSimMgr->economicTurn != startingTurn;
}

bool EndTurnFlow::AStepIsReady() const {
  // "One of the branches below would now do something", not "an expected screen is showing".
  // Awaiting the latter spins, because the screen does not change until the game gets a turn
  // to act on what was just done.
  if (BackOnMapWithNewTurn() || ModalScreen::AnyPresent()) {
    return true;
  }
  if (CurrentTurnEventForFragment() == kTurnEventOpeningCinematic) {
    return true;
  }
  if (OfferScreen::IsCurrent() && (rejectOffers || acceptOffers)) {
    return true;
  }
  if (DealBookScreen::IsCurrent() && !leftDealBook) {
    return true;
  }
  if (NewspaperScreen::IsCurrent() && !closedNewspaper) {
    return true;
  }
  // A turn alert means the game bounced back to the map without processing the turn, so Done
  // has to be re-submitted once.
  return sawTurnAlert && !resubmittedDone && StrategicMapScreen::IsCurrent() && g_pSimMgr != 0 &&
         g_pSimMgr->economicTurn == startingTurn;
}

RuntimeScriptStatus EndTurnFlow::Advance() {
  RT_FRAGMENT_BEGIN();

  RT_FRAGMENT_ACTION("end the turn", StrategicMap().EndTurn());

  while (!BackOnMapWithNewTurn()) {
    // Entering the opening cinematic means the turn ended the game; no caller wants that and
    // it would otherwise look like a stall.
    RT_FRAGMENT_REQUIRE(CurrentTurnEventForFragment() != kTurnEventOpeningCinematic);

    if (ModalScreen::AnyPresent()) {
      // Recorded before confirming, because a turn alert changes what happens next.
      if (Modal().IsTurnAlert()) {
        sawTurnAlert = true;
        RecordHandledModalForFragment("turn_alert");
      } else if (Modal().IsEndTurnWarning()) {
        RecordHandledModalForFragment("end_turn_warning");
      } else {
        RecordUnexpectedModalForFragment(Modal().Top());
      }
      confirmedModal = Modal().Top();
      RT_FRAGMENT_ACTION("confirm the turn-flow dialog", Modal().AcceptDefault());
      // Wait for *this* dialog to go, not for the stack to empty: turn processing pops one
      // dialog and pushes the next, so the depth stays at one and an "empty stack" wait would
      // never be satisfied. Re-dispatching per dialog is what the original handler did by
      // waiting on kObserveModalPopped and then re-testing every branch.
      RT_FRAGMENT_AWAIT(Modal().Top() != confirmedModal,
                        kObserveModalPopped | kObserveUiStateChanged);
    } else if (OfferScreen::IsCurrent() && (rejectOffers || acceptOffers)) {
      sawOfferDesk = true;
      RT_FRAGMENT_REQUIRE(OfferDesk().IsAddressedTo(g_pSimMgr != 0 ? g_pSimMgr->GetActiveNationId()
                                                                   : static_cast<short>(-1)));
      RT_FRAGMENT_AWAIT(OfferDesk().ResponseControlsAreReady(),
                        kObserveGameStateChanged | kObservePaintCompleted);
      if (rejectOffers) {
        RT_FRAGMENT_ACTION("reject the trade offer", OfferDesk().Reject());
      } else {
        RT_FRAGMENT_ACTION("accept the trade offer", OfferDesk().Accept());
      }
    } else if (DealBookScreen::IsCurrent() && !leftDealBook) {
      sawDealBook = true;
      // One-shot: starting the next phase twice would skip a phase.
      leftDealBook = true;
      RT_FRAGMENT_ACTION("leave the Deal Book", DealBook().Leave());
    } else if (NewspaperScreen::IsCurrent() && !closedNewspaper) {
      sawNewspaper = true;
      RT_FRAGMENT_AWAIT(Newspaper().EndControlIsReady(), kObservePaintCompleted |
                                                             kObserveInvalidationRequested |
                                                             kObserveGameStateChanged);
      closedNewspaper = true;
      RT_FRAGMENT_ACTION("close the newspaper", Newspaper().Close());
    } else if (sawTurnAlert && !resubmittedDone && StrategicMapScreen::IsCurrent()) {
      resubmittedDone = true;
      RT_FRAGMENT_ACTION("re-submit Done after the turn alert", StrategicMap().EndTurn());
    } else {
      RT_FRAGMENT_AWAIT(AStepIsReady(), kObserveUiStateChanged);
    }
  }

  endingTurn = g_pSimMgr != 0 ? g_pSimMgr->economicTurn : -1;
  if (expectExactlyOneTurn && endingTurn != startingTurn + 1) {
    RT_FRAGMENT_FAIL("ending one turn advanced the economic turn by more than one");
  }
  RT_FRAGMENT_DONE();

  RT_FRAGMENT_END();
}
