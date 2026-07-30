#include "DealBookScreen.h"

#include "game/core/global_data_tables.h"
#include "game/trade_ui/TDealBookPicture.h"
#include "game/trade_ui/TDealTabControl.h"
// The page-mode predicates read ownerLocalX off the cached page views, so their layouts have to
// be complete here rather than just declared.
#include "game/trade_ui/TTradePageBuyView.h"
#include "game/trade_ui/TTradePageSellView.h"
#include "game/turn_event_codes.h"
#include "game/ui_core/TControl.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_tags_city.h"
#include "game/ui_tags_common.h"

namespace {

// The page-cache layout that tells the two modes apart. History mode parks the standalone
// bought/sold views at these owner-local X offsets; category mode parks the per-category ones.
const int kHistorySellPageX = 0x41;
const int kHistoryBuyPageX = 0x13a;
const short kHistoryModeBitmap = 0x2260;
const short kCategoryModeBitmap = 0x2263;

} // namespace

DealBookScreen::DealBookScreen()
    : MainViewScreen(RUNTIME_CLASS(TDealBookPicture), kTurnEventDealBook, "the Deal Book"),
      dealBook(0) {
  dealBook = static_cast<TDealBookPicture*>(Root());
}

bool DealBookScreen::IsCurrent() {
  return MainViewIsCurrent(RUNTIME_CLASS(TDealBookPicture), kTurnEventDealBook);
}

TDealBookPicture* DealBookScreen::View() const {
  return dealBook;
}

RuntimeActionResult DealBookScreen::Leave() {
  if (g_pSimMgr == 0) {
    return RuntimeActionResult::Failure("cannot leave the Deal Book: no simulation manager");
  }
  // Deliberately not gated on IsValid(): the Deal Book's turn event can already have been
  // superseded while its view is still up, and the caller (EndTurnFlow) owns the one-shot
  // guard that keeps this from advancing two phases.
  g_pSimMgr->StartNextPhase();
  return RuntimeActionResult::Success();
}

RuntimeActionResult DealBookScreen::ShowHistoryPages() {
  return Activate(kControlTagMark, "show the Deal Book history pages");
}

RuntimeActionResult DealBookScreen::ShowCategoryPages() {
  TView* strip = Find(kControlTagTabs);
  if (strip == 0 || strip->IsKindOf(RUNTIME_CLASS(TDealTabControl)) == 0) {
    if (!IsValid()) {
      return InvalidScreen("show the Deal Book category pages");
    }
    return ScreenFailure("show the Deal Book category pages",
                         CString("the book has no category strip"));
  }
  // A category page is chosen by clicking a row of the strip, not by activating the strip
  // itself: the strip's own command carries no row, so it would not select anything.
  if (!static_cast<TDealTabControl*>(strip)->ActivateRow(0)) {
    return ScreenFailure("show the Deal Book category pages",
                         CString("the first category row did not accept the click"));
  }
  return RuntimeActionResult::Success();
}

bool DealBookScreen::IsShowingHistoryPages() const {
  // History mode is also the mode flag being clear; the page identities below say which views
  // are parked, the flag says which mode the book thinks it is in.
  return dealBook != 0 && !dealBook->alternatePageMode &&
         dealBook->cachedSellPageView == dealBook->soldTradesView &&
         dealBook->cachedBuyPageView == dealBook->boughtTradesView &&
         dealBook->cachedSellPageView != 0 &&
         dealBook->cachedSellPageView->ownerLocalX == kHistorySellPageX &&
         dealBook->cachedBuyPageView != 0 &&
         dealBook->cachedBuyPageView->ownerLocalX == kHistoryBuyPageX &&
         dealBook->glyphBase84 == kHistoryModeBitmap;
}

bool DealBookScreen::IsShowingCategoryPages() const {
  return dealBook != 0 && dealBook->alternatePageMode &&
         dealBook->cachedSellPageView == dealBook->sellPageView &&
         dealBook->cachedBuyPageView == dealBook->buyPageView &&
         dealBook->glyphBase84 == kCategoryModeBitmap;
}
