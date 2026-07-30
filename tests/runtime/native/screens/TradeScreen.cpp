#include "TradeScreen.h"

#include "game/globals/ui_widgets_globals.h"
#include "game/resource_domain_types.h"
#include "game/turn_event_codes.h"
#include "game/ui_core/TView.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_widgets.h"
#include "game/ui_widgets/TTradeCluster.h"
#include "game/ui_widgets/TTradeOrderPicture.h"
#include "game/ui_widgets/TTradeScreenPicture.h"

namespace {

// The card bitmap vocabulary. Two ids per state because the screen ships two art variants.
const short kBuyCardInactiveA = 0x840;
const short kBuyCardInactiveB = 0x84e;
const short kBuyCardSelected = 0x83f;
// The gold/specie row selects to a different bitmap than every other row.
const short kBuyCardSelectedGoldRow = 0x84d;
const short kOfferCardInactiveA = 0x842;
const short kOfferCardInactiveB = 0x850;

bool IsValidResource(short resource) {
  return resource >= 0 && resource < kResourceKindCount;
}

} // namespace

TradeScreen::TradeScreen()
    : MainViewScreen(RUNTIME_CLASS(TTradeScreenPicture), kTurnEventTradeOverview,
                     "the Board of Trade"),
      tradeView(0) {
  tradeView = static_cast<TTradeScreenPicture*>(Root());
}

bool TradeScreen::IsCurrent() {
  return MainViewIsCurrent(RUNTIME_CLASS(TTradeScreenPicture), kTurnEventTradeOverview);
}

TTradeScreenPicture* TradeScreen::View() const {
  return tradeView;
}

TTradeCluster* TradeScreen::Row(short resource) const {
  if (!IsValidResource(resource)) {
    return 0;
  }
  TView* row = Find(kTradeSellPropagationTags[resource]);
  return row != 0 && row->IsKindOf(RUNTIME_CLASS(TTradeCluster)) != 0
             ? static_cast<TTradeCluster*>(row)
             : 0;
}

TTradeOrderPicture* TradeScreen::BuyCard(short resource) const {
  TTradeCluster* row = Row(resource);
  TView* card = row != 0 ? row->ResolveControlByTag(kControlTagCard) : 0;
  return card != 0 && card->IsKindOf(RUNTIME_CLASS(TTradeOrderPicture)) != 0
             ? static_cast<TTradeOrderPicture*>(card)
             : 0;
}

TTradeOrderPicture* TradeScreen::OfferCard(short resource) const {
  TTradeCluster* row = Row(resource);
  TView* card = row != 0 ? row->ResolveControlByTag(kControlTagOffr) : 0;
  return card != 0 && card->IsKindOf(RUNTIME_CLASS(TTradeOrderPicture)) != 0
             ? static_cast<TTradeOrderPicture*>(card)
             : 0;
}

bool TradeScreen::HasBuyCard(short resource) const {
  return BuyCard(resource) != 0;
}

short TradeScreen::BuyCardBitmap(short resource) const {
  TTradeOrderPicture* card = BuyCard(resource);
  return card != 0 ? card->glyphBase84 : -1;
}

bool TradeScreen::BuyCardIsActionable(short resource) const {
  TTradeOrderPicture* card = BuyCard(resource);
  return card != 0 && card->IsActionable() != 0;
}

bool TradeScreen::BuyCardIsInactive(short resource) const {
  short bitmap = BuyCardBitmap(resource);
  return bitmap == kBuyCardInactiveA || bitmap == kBuyCardInactiveB;
}

bool TradeScreen::IsSelectedBuyBitmap(short resource, short bitmap) const {
  TTradeCluster* row = Row(resource);
  if (row != 0 && row->controlTag == kControlTagGd0Sp) {
    return bitmap == kBuyCardSelectedGoldRow;
  }
  return bitmap == kBuyCardSelected;
}

bool TradeScreen::BidSelected(short resource) const {
  // Both halves matter: the card shows the selected art *and* the row reports the selection as
  // allowed. Reading only the bitmap would accept a card drawn selected on a row that rejected
  // it.
  TTradeCluster* row = Row(resource);
  return row != 0 && IsSelectedBuyBitmap(resource, BuyCardBitmap(resource)) &&
         row->IsSelectionAllowed() != 0;
}

bool TradeScreen::OfferCardIsInactive(short resource) const {
  TTradeOrderPicture* card = OfferCard(resource);
  short bitmap = card != 0 ? card->glyphBase84 : -1;
  return bitmap == kOfferCardInactiveA || bitmap == kOfferCardInactiveB;
}

bool TradeScreen::SelectionAllowed(short resource) const {
  TTradeCluster* row = Row(resource);
  return row != 0 && row->IsSelectionAllowed() != 0;
}

RuntimeActionResult TradeScreen::SelectBid(short resource) {
  TTradeOrderPicture* card = BuyCard(resource);
  if (card == 0) {
    if (!IsValid()) {
      return InvalidScreen("select a trade bid");
    }
    CString detail;
    detail.Format("commodity %d has no buy card", static_cast<int>(resource));
    return ScreenFailure("select a trade bid", detail);
  }
  if (card->IsActionable() == 0) {
    CString detail;
    detail.Format("commodity %d's buy card is not actionable (bitmap 0x%03x)",
                  static_cast<int>(resource), static_cast<unsigned int>(card->glyphBase84));
    return ScreenFailure("select a trade bid", detail);
  }
  // A trade card is activated through its own semantic entry point rather than a generic
  // control event: the card owns the order-state transition.
  card->ActivateOrderSemantically();
  return RuntimeActionResult::Success();
}

RuntimeActionResult TradeScreen::SelectOffer(short resource) {
  TTradeOrderPicture* card = OfferCard(resource);
  if (card == 0) {
    if (!IsValid()) {
      return InvalidScreen("select a trade offer");
    }
    CString detail;
    detail.Format("commodity %d has no offer card", static_cast<int>(resource));
    return ScreenFailure("select a trade offer", detail);
  }
  if (card->IsActionable() == 0) {
    CString detail;
    detail.Format("commodity %d's offer card is not actionable (bitmap 0x%03x)",
                  static_cast<int>(resource), static_cast<unsigned int>(card->glyphBase84));
    return ScreenFailure("select a trade offer", detail);
  }
  card->ActivateOrderSemantically();
  return RuntimeActionResult::Success();
}

RuntimeActionResult TradeScreen::Close() {
  return Activate(kControlTagEnd, "leave the Board of Trade");
}
