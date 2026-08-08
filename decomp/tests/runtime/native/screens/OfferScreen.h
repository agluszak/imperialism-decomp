#pragma once

#ifndef IMPERIALISM_OFFER_SCREEN_H
#define IMPERIALISM_OFFER_SCREEN_H

#ifndef IMPERIALISM_RUNTIME_TESTS
#error OfferScreen is test-only and must not be included in the production build
#endif

#include "MainViewScreen.h"

class TDealTabControl;
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

  // Raise the desk for a nation directly, through the game's own turn-event dispatch. Turn
  // processing normally raises it; a scenario that wants to inspect the desk outside a turn has
  // no control to click, and this is the entry point the game itself uses.
  static RuntimeActionResult OpenForNation(short nationSlot);
  // Put a fixed offer of `quantity` units of `resource` at `price` to the nation itself, which
  // is what makes the desk's contents deterministic across runs.
  static RuntimeActionResult PoseOfferToSelf(short nationSlot, short resource, short quantity,
                                             short price);

  // Presentation. The desk names the selling nation in its offer text and draws the season
  // label in white over the artwork; both were regressions once.
  bool OfferTextNamesNation(short nationSlot) const;
  bool SeasonLabelIsWhite() const;
  // The purchase field opens at the amount offered, bounded by it.
  bool PurchaseDefaultsTo(int amount) const;

  // The bookmark strip down the side of the sheet.
  bool HasRetailBookmarkCount() const;
  short BookmarkCount() const;
  short SelectedBookmark() const;
  RuntimeActionResult SelectBookmark(short row);

private:
  TDealTabControl* Bookmarks() const;

  TOfferDeskPicture* offerDesk;
};

inline OfferScreen OfferDesk() {
  return OfferScreen();
}

#endif
