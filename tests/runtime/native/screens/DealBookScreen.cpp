#include "DealBookScreen.h"

#include "game/core/global_data_tables.h"
#include "game/trade_ui/TDealBookPicture.h"
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
  return Activate(kControlTagTabs, "show the Deal Book category pages");
}

bool DealBookScreen::IsShowingHistoryPages() const {
  return dealBook != 0 && dealBook->cachedSellPageView == dealBook->soldTradesView &&
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
