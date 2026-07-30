#include "OfferScreen.h"

#include "RuntimeUiDriver.h"

#include "game/trade_ui/TOfferDeskPicture.h"
#include "game/turn_event_codes.h"
#include "game/ui_core/TControl.h"
#include "game/ui_tags_common.h"

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
