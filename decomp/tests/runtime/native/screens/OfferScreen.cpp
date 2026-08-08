#include "OfferScreen.h"

#include "RuntimeUiDriver.h"

#include "game/globals/shared_globals.h"
#include "game/globals/ui_core_globals.h"
#include "game/trade_ui/TDealTabControl.h"
#include "game/trade_ui/TOfferDeskPicture.h"
#include "game/turn_event_codes.h"
#include "game/ui_core/TControl.h"
#include "game/ui_core/TNumberText.h"
#include "game/ui_core/TStaticText.h"
#include "game/ui_core/TViewMgr.h"
#include "game/ui_fourcc.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_tags_city.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_military.h"
#include "game/ui_widgets/TDropShadowText.h"

namespace {

// The desk's offer paragraph. Local to this screen -- no other subsystem addresses it, so it
// has never earned a place in the shared tag headers.
const int kControlTagOffe = IMPERIALISM_FOURCC('o', 'f', 'f', 'e');

// Palette index 0 is white, which is what the season label is drawn in over the artwork.
const COLORREF kSeasonLabelColor = PALETTEINDEX(0);

// The sheet carries one bookmark per commodity the player can be offered; more than that would
// mean the strip was built from the wrong table.
const short kMaxBookmarkCount = 17;

} // namespace

OfferScreen::OfferScreen()
    : MainViewScreen(RUNTIME_CLASS(TOfferDeskPicture), kTurnEventOfferSheet, "the offer desk"),
      offerDesk(0) {
  offerDesk = static_cast<TOfferDeskPicture*>(Root());
}

bool OfferScreen::IsCurrent() {
  return MainViewIsCurrent(RUNTIME_CLASS(TOfferDeskPicture), kTurnEventOfferSheet);
}

TOfferDeskPicture* OfferScreen::View() const {
  return offerDesk;
}

short OfferScreen::RespondingNationSlot() const {
  return offerDesk != 0 ? offerDesk->respondingNationSlot : -1;
}

short OfferScreen::OfferingNationSlot() const {
  return offerDesk != 0 ? offerDesk->offeringNationSlot : -1;
}

bool OfferScreen::IsAddressedTo(short nationSlot) const {
  return offerDesk != 0 && offerDesk->respondingNationSlot == nationSlot &&
         offerDesk->offeringNationSlot != nationSlot;
}

bool OfferScreen::ResponseControlsAreReady() const {
  return offerDesk != 0 &&
         RuntimeUiDriver::RequireControl(
             offerDesk, RuntimeControlSelector(kControlTagReje, RUNTIME_CLASS(TControl)), 0) != 0;
}

RuntimeActionResult OfferScreen::Accept() {
  return Activate(kControlTagAcce, "accept the trade offer");
}

RuntimeActionResult OfferScreen::Reject() {
  return Activate(kControlTagReje, "reject the trade offer");
}

RuntimeActionResult OfferScreen::OpenForNation(short nationSlot) {
  if (g_pViewMgr == 0) {
    return RuntimeActionResult::Failure("cannot open the offer desk: no view manager");
  }
  g_pViewMgr->DispatchTurnEvent(EncodeTurnEventCode(kTurnEventOfferSheet), nationSlot);
  return RuntimeActionResult::Success();
}

RuntimeActionResult OfferScreen::PoseOfferToSelf(short nationSlot, short resource, short quantity,
                                                 short price) {
  if (g_pViewMgr == 0) {
    return RuntimeActionResult::Failure("cannot pose an offer: no view manager");
  }
  // The dialog's main action control carries the offer. Its middle parameters are still
  // provisional in the recovered signature; what the desk does with them -- the quantity it
  // opens the purchase field at and the price it prints -- is what this scenario asserts on.
  g_pViewMgr->ShowOfferSheet(nationSlot, nationSlot, quantity, price, resource);
  return RuntimeActionResult::Success();
}

bool OfferScreen::OfferTextNamesNation(short nationSlot) const {
  TView* paragraph = offerDesk != 0 ? offerDesk->ResolveControlByTag(kControlTagOffe) : 0;
  if (paragraph == 0 || paragraph->IsKindOf(RUNTIME_CLASS(TStaticText)) == 0 || g_pSimMgr == 0) {
    return false;
  }
  CString displayed;
  static_cast<TStaticText*>(paragraph)->CopyTextTo(&displayed);
  CString sellerName = g_pSimMgr->LoadNormalizedCredentialName(nationSlot);
  return displayed.GetLength() != 0 && sellerName.GetLength() != 0 &&
         displayed.Find(static_cast<LPCSTR>(sellerName)) >= 0;
}

bool OfferScreen::SeasonLabelIsWhite() const {
  TView* season = offerDesk != 0 ? offerDesk->ResolveControlByTag(kControlTagSeas) : 0;
  return season != 0 && season->IsKindOf(RUNTIME_CLASS(TDropShadowText)) != 0 &&
         static_cast<TDropShadowText*>(season)->textStyle78.textColor == kSeasonLabelColor;
}

bool OfferScreen::PurchaseDefaultsTo(int amount) const {
  TView* purchase = offerDesk != 0 ? offerDesk->ResolveControlByTag(kControlTagPurc) : 0;
  if (purchase == 0 || purchase->IsKindOf(RUNTIME_CLASS(TNumberText)) == 0) {
    return false;
  }
  TNumberText* field = static_cast<TNumberText*>(purchase);
  // Opened at the offered amount and bounded by it: the player may buy less, never more.
  return field->value == amount && field->maximumValue == amount;
}

TDealTabControl* OfferScreen::Bookmarks() const {
  TView* strip = offerDesk != 0 ? offerDesk->ResolveControlByTag(kControlTagTabs) : 0;
  return strip != 0 && strip->IsKindOf(RUNTIME_CLASS(TDealTabControl)) != 0
             ? static_cast<TDealTabControl*>(strip)
             : 0;
}

bool OfferScreen::HasRetailBookmarkCount() const {
  TDealTabControl* strip = Bookmarks();
  return strip != 0 && strip->tabCount > 0 && strip->tabCount <= kMaxBookmarkCount;
}

short OfferScreen::BookmarkCount() const {
  TDealTabControl* strip = Bookmarks();
  return strip != 0 ? strip->tabCount : -1;
}

short OfferScreen::SelectedBookmark() const {
  TDealTabControl* strip = Bookmarks();
  return strip != 0 ? strip->selectedRow : -1;
}

RuntimeActionResult OfferScreen::SelectBookmark(short row) {
  TDealTabControl* strip = Bookmarks();
  if (strip == 0) {
    if (!IsValid()) {
      return InvalidScreen("select an offer-sheet bookmark");
    }
    return ScreenFailure("select an offer-sheet bookmark",
                         CString("the sheet has no bookmark strip"));
  }
  // The strip resolves a click to a row itself; ActivateRow is that resolution, not a shortcut
  // around it.
  if (!strip->ActivateRow(row)) {
    CString detail;
    detail.Format("bookmark row %d of %d did not accept the click", static_cast<int>(row),
                  static_cast<int>(strip->tabCount));
    return ScreenFailure("select an offer-sheet bookmark", detail);
  }
  return RuntimeActionResult::Success();
}
