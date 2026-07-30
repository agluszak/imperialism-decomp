#pragma once

#ifndef IMPERIALISM_OFFER_SCREEN_H
#define IMPERIALISM_OFFER_SCREEN_H

#ifndef IMPERIALISM_RUNTIME_TESTS
#error OfferScreen is test-only and must not be included in the production build
#endif

#include "MainViewScreen.h"

class TOfferDeskPicture;

// The offer desk, shown when another nation puts a trade offer to the player during turn
// processing.
//
// Two scenarios handled this inline, and both checked the same thing first: that the offer is
// actually addressed to the player. Accepting an offer meant for someone else would corrupt the
// very trade history the test then asserts on, so IsAddressedTo() is part of the screen rather
// than something each caller remembers.
class OfferScreen : public MainViewScreen {
public:
  OfferScreen();

  static bool IsCurrent();

  TOfferDeskPicture* View() const;

  // The player is the responding nation and is not also the offering nation.
  bool IsAddressedTo(short nationSlot) const;
  short RespondingNationSlot() const;
  short OfferingNationSlot() const;

  // True once the accept/reject controls resolve; the desk is constructed before they do.
  bool ResponseControlsAreReady() const;

  RuntimeActionResult Accept();
  RuntimeActionResult Reject();

private:
  TOfferDeskPicture* offerDesk;
};

inline OfferScreen OfferDesk() {
  return OfferScreen();
}

#endif
