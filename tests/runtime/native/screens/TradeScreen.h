#pragma once

#ifndef IMPERIALISM_TRADE_SCREEN_H
#define IMPERIALISM_TRADE_SCREEN_H

#ifndef IMPERIALISM_RUNTIME_TESTS
#error TradeScreen is test-only and must not be included in the production build
#endif

#include "MainViewScreen.h"

class TAmtBar;
class TNumberText;
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
  // Give the player enough merchant capacity for the sell quantity to be adjustable in both
  // directions, and tell the row's bar about it. Without this a fresh game's capacity is often
  // one, where a decrease has nowhere to go.
  RuntimeActionResult SeedAdjustableCapacity(short resource);
  // The sell quantity's two arrows. They are not separate controls with their own commands:
  // the row itself handles the arrow's command, which is why these are row methods rather than
  // activations of the arrow.
  RuntimeActionResult DecreaseSell(short resource);
  RuntimeActionResult IncreaseSell(short resource);
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

  // The screen is not usable without its merchant-capacity readout, its commodity rows and the
  // way back.
  bool HasCapacityAndCommodityControls() const;
  // The price and availability cells are drawn per frame rather than baked into the background,
  // and their text is drawn transparently over it. Both counters come from the view's own draw
  // path, so a zero means the cells were never drawn -- not that they drew wrongly.
  bool RenderedDynamicCells() const;
  bool RenderedTransparentText() const;

  // How much of a commodity the player holds, which is what bounds a sell order.
  int AvailableStock(short resource) const;
  // A commodity other than `excludedResource` whose offer card can still be posted and which the
  // player holds more than one of, so its quantity can be adjusted afterwards. -1 when the
  // screen has no such row yet.
  short FirstSellableCommodityOtherThan(short excludedResource) const;

  // The sell quantity of a posted offer, and the width its bar is drawn to.
  int SellQuantity(short resource) const;
  short SellBarValue(short resource) const;
  // The row reports the quantity as adjustable and there is more than one unit to give up.
  bool SellRowIsAdjustable(short resource) const;
  // The quantity label keeps its own space inside the row: inside the row's frame, and left of
  // both arrows, which are themselves in order. A label that has drifted over an arrow is a
  // layout regression that the numbers alone would not catch.
  bool SellLabelHasOwnLayout(short resource) const;

private:
  // A row's buy card uses a different selected bitmap when the row is the special
  // gold/specie row, which is why "selected" is a question about the row, not a constant.
  bool IsSelectedBuyBitmap(short resource, short bitmap) const;

  TNumberText* SellLabel(short resource) const;
  TAmtBar* SellBar(short resource) const;
  RuntimeActionResult AdjustSell(short resource, int rowCommand, int arrowTag, const char* what);

  TTradeScreenPicture* tradeView;
};

inline TradeScreen Trade() {
  return TradeScreen();
}

#endif
