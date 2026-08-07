#include "TradeScreen.h"

#include "RuntimeUiDriver.h"

#include "game/core/global_data_tables.h"
#include "game/globals/nation_globals.h"
#include "game/globals/shared_globals.h"
#include "game/globals/ui_widgets_globals.h"
#include "game/nation/TGreatPower.h"
#include "game/resource_domain_types.h"
#include "game/turn_event_codes.h"
#include "game/ui_core/TNumberText.h"
#include "game/ui_core/TView.h"
#include "game/ui_screens/TSidewaysArrow.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_tags_common.h"
#include "game/ui_tags_widgets.h"
#include "game/ui_widgets/TAmtBar.h"
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

// The Board of Trade has one row per *traded* commodity, which is fewer than the resource kinds
// the game models: kTradeSellPropagationTags is declared [17] while kResourceKindCount is 23.
// Bounding a row lookup by the latter reads past the tag table.
const short kTradeRowCount = 17;

// Enough capacity for a quantity to be adjustable downwards and back without hitting either
// end. Three is what the scenario that needs it used; the real bound is the player's stock.
const int kMaxSeededCapacity = 3;

// The sell row, not the arrow, owns the quantity command: TSidewaysArrow's retail TrackMouse
// path forwards these to its owning cluster.
const int kSellDecreaseCommand = 101;
const int kSellIncreaseCommand = 100;

bool IsValidResource(short resource) {
  return resource >= 0 && resource < kTradeRowCount;
}

} // namespace

MainViewScreenIdentity TradeScreen::Identity() {
  return MainViewScreenIdentity(RUNTIME_CLASS(TTradeScreenPicture), kTurnEventTradeOverview,
                                "the Board of Trade");
}

TradeScreen::TradeScreen() : MainViewScreen(Identity()), tradeView(0) {
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

bool TradeScreen::HasCapacityAndCommodityControls() const {
  return Find(kControlTagMCap) != 0 && Find(kTradeSellPropagationTags[0]) != 0 &&
         Find(kControlTagEnd) != 0;
}

bool TradeScreen::RenderedDynamicCells() const {
  return RuntimeTradeDynamicDrawCount() != 0;
}

bool TradeScreen::RenderedTransparentText() const {
  return RuntimeTradeTransparentTextDrawCount() != 0;
}

namespace {

TGreatPower* ActiveNationState() {
  return g_pSimMgr != 0 ? g_apNationStates[g_pSimMgr->GetActiveNationId()] : 0;
}

} // namespace

int TradeScreen::AvailableStock(short resource) const {
  TTradeCluster* row = Row(resource);
  TGreatPower* player = ActiveNationState();
  // The row knows which of the nation's metric slots holds its commodity; the stock itself is
  // nation state, not screen state.
  return row != 0 && player != 0 ? player->GetStockpile(row->tradeMetricSlot) : -1;
}

short TradeScreen::FirstSellableCommodityOtherThan(short excludedResource) const {
  for (short resource = 0; resource < kTradeRowCount; ++resource) {
    if (resource == excludedResource) {
      continue;
    }
    TTradeOrderPicture* card = OfferCard(resource);
    // More than one in stock, so the quantity can be stepped down and back afterwards.
    if (card != 0 && card->IsActionable() != 0 && OfferCardIsInactive(resource) &&
        AvailableStock(resource) > 1) {
      return resource;
    }
  }
  return -1;
}

TNumberText* TradeScreen::SellLabel(short resource) const {
  TTradeCluster* row = Row(resource);
  TView* label = row != 0 ? row->ResolveControlByTag(kControlTagSell) : 0;
  return label != 0 && label->IsKindOf(RUNTIME_CLASS(TNumberText)) != 0
             ? static_cast<TNumberText*>(label)
             : 0;
}

TAmtBar* TradeScreen::SellBar(short resource) const {
  TTradeCluster* row = Row(resource);
  TView* bar = row != 0 ? row->ResolveControlByTag(kControlTagBar) : 0;
  return bar != 0 && bar->IsKindOf(RUNTIME_CLASS(TAmtBar)) != 0 ? static_cast<TAmtBar*>(bar) : 0;
}

int TradeScreen::SellQuantity(short resource) const {
  TNumberText* label = SellLabel(resource);
  // Read back through the control's own text rather than its cached value: the text is what the
  // player sees, and a refresh that updated one without the other is exactly the defect worth
  // catching.
  return label != 0 ? label->UpdateControlCachedIntFromWindowText() : -1;
}

short TradeScreen::SellBarValue(short resource) const {
  TAmtBar* bar = SellBar(resource);
  return bar != 0 ? bar->rangeOrMaxValue : -1;
}

bool TradeScreen::SellRowIsAdjustable(short resource) const {
  TTradeCluster* row = Row(resource);
  return row != 0 && row->GetBoolSlot1DC() != 0 && SellQuantity(resource) > 1;
}

bool TradeScreen::SellLabelHasOwnLayout(short resource) const {
  TTradeCluster* row = Row(resource);
  TNumberText* label = SellLabel(resource);
  TView* decrease = row != 0 ? row->ResolveControlByTag(kControlTagLeft) : 0;
  TView* increase = row != 0 ? row->ResolveControlByTag(kControlTagRght) : 0;
  if (row == 0 || label == 0 || decrease == 0 || increase == 0) {
    return false;
  }
  CRect labelBounds;
  CRect decreaseBounds;
  CRect increaseBounds;
  label->QueryBounds(&labelBounds);
  decrease->QueryBounds(&decreaseBounds);
  increase->QueryBounds(&increaseBounds);
  // The label sits inside the row and left of both arrows, and the arrows are in order. The
  // two-pixel slack at the top is the label's own ascent overhang in the retail layout.
  return labelBounds.left >= 0 && labelBounds.top >= -2 &&
         labelBounds.bottom <= row->frameHeight38 && labelBounds.right <= decreaseBounds.left &&
         decreaseBounds.right <= increaseBounds.left;
}

RuntimeActionResult TradeScreen::SeedAdjustableCapacity(short resource) {
  TTradeCluster* row = Row(resource);
  TGreatPower* player = ActiveNationState();
  TView* capacity = Find(kControlTagMCap);
  TAmtBar* bar = SellBar(resource);
  if (row == 0 || player == 0 || capacity == 0 || bar == 0 ||
      capacity->IsKindOf(RUNTIME_CLASS(TNumberText)) == 0) {
    if (!IsValid()) {
      return InvalidScreen("seed an adjustable merchant capacity");
    }
    CString detail;
    detail.Format("commodity %d is missing its row, capacity readout or bar",
                  static_cast<int>(resource));
    return ScreenFailure("seed an adjustable merchant capacity", detail);
  }
  const int available = AvailableStock(resource);
  const int seeded = available < kMaxSeededCapacity ? available : kMaxSeededCapacity;
  if (seeded <= 1) {
    CString detail;
    detail.Format("commodity %d has only %d to sell, which cannot be stepped down and back",
                  static_cast<int>(resource), available);
    return ScreenFailure("seed an adjustable merchant capacity", detail);
  }
  player->merchantCapacity = static_cast<short>(seeded);
  static_cast<TNumberText*>(capacity)->SetControlValue(seeded, 1);
  // The bar scales its fill against the capacity, so it has to be told the same number.
  bar->auxValueA = static_cast<short>(seeded);
  return RuntimeActionResult::Success();
}

RuntimeActionResult TradeScreen::AdjustSell(short resource, int rowCommand, int arrowTag,
                                            const char* what) {
  TTradeCluster* row = Row(resource);
  TView* arrow = row != 0 ? row->ResolveControlByTag(arrowTag) : 0;
  if (row == 0 || arrow == 0) {
    if (!IsValid()) {
      return InvalidScreen(what);
    }
    CString detail;
    detail.Format("commodity %d has no sell-quantity arrow", static_cast<int>(resource));
    return ScreenFailure(what, detail);
  }
  CString failure;
  if (RuntimeUiDriver::RequireControl(
          arrow, RuntimeControlSelector(arrow->controlTag, RUNTIME_CLASS(TSidewaysArrow)),
          &failure) == 0) {
    return ScreenFailure(what, failure);
  }
  row->HandleEvent(rowCommand, arrow, 0);
  return RuntimeActionResult::Success();
}

RuntimeActionResult TradeScreen::DecreaseSell(short resource) {
  return AdjustSell(resource, kSellDecreaseCommand, kControlTagLeft, "decrease the sell quantity");
}

RuntimeActionResult TradeScreen::IncreaseSell(short resource) {
  return AdjustSell(resource, kSellIncreaseCommand, kControlTagRght, "increase the sell quantity");
}
