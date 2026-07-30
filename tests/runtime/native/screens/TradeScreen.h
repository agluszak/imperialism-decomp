#pragma once

#ifndef IMPERIALISM_TRADE_SCREEN_H
#define IMPERIALISM_TRADE_SCREEN_H

#ifndef IMPERIALISM_RUNTIME_TESTS
#error TradeScreen is test-only and must not be included in the production build
#endif

#include "MainViewScreen.h"

class TTradeCluster;
class TTradeOrderPicture;
class TTradeScreenPicture;

// The Board of Trade.
//
// Each commodity is a row (TTradeCluster) addressed by kTradeSellPropagationTags[resource],
// holding a buy card ('card') and an offer card ('offr'), both TTradeOrderPicture. Whether a
// card is selected is readable only from its bitmap id, and the two scenarios that drive this
// screen each carried their own copies of those six magic values -- with one of them reading
// 0x83f/0x84d as "already selected" and the other as "active", from the same field. The bitmap
// vocabulary belongs here so a script can ask a question instead of comparing constants.
class TradeScreen : public MainViewScreen {
public:
  TradeScreen();

  static bool IsCurrent();

  TTradeScreenPicture* View() const;

  // Rows and cards. Public because some assertions legitimately need the widget itself; prefer
  // the predicates below.
  TTradeCluster* Row(short resource) const;
  TTradeOrderPicture* BuyCard(short resource) const;
  TTradeOrderPicture* OfferCard(short resource) const;

  // Actions.
  RuntimeActionResult SelectBid(short resource);
  RuntimeActionResult SelectOffer(short resource);
  RuntimeActionResult Close();

  // Predicates over the card bitmap state.
  bool HasBuyCard(short resource) const;
  bool BuyCardIsActionable(short resource) const;
  // Nothing requested yet for this commodity.
  bool BuyCardIsInactive(short resource) const;
  // A bid has been placed; the row also reports selection as allowed.
  bool BidSelected(short resource) const;
  bool OfferCardIsInactive(short resource) const;
  bool SelectionAllowed(short resource) const;
  // The raw bitmap, for a diagnostic or an unrecognised-state assertion.
  short BuyCardBitmap(short resource) const;

private:
  // A row's buy card uses a different selected bitmap when the row is the special
  // gold/specie row, which is why "selected" is a question about the row, not a constant.
  bool IsSelectedBuyBitmap(short resource, short bitmap) const;

  TTradeScreenPicture* tradeView;
};

inline TradeScreen Trade() {
  return TradeScreen();
}

#endif
