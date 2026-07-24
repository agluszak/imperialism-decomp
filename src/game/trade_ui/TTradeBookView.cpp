#include "game/trade_ui/TTradeBookView.h"
#include "game/ui_tags_city.h"
#include "game/ui_tags_common.h"

#include "game/ui_widgets/TDropShadowText.h"
#include "game/ui_core/TEventHandler.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_core/TStaticText.h"
#include "game/trade_ui/TTradePageBuyView.h"
#include "game/trade_ui/TTradePageSellView.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/military/mapped_flavor_text.h"
#include "game/ui_core/quickdraw_rendering.h"
#include "game/ui_text_label_helpers_decls.h"

// SYNTHETIC: IMPERIALISM 0x00435690
// TTradeBookView::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x004356c0
TTradeBookView::~TTradeBookView() {}
// SYNTHETIC: IMPERIALISM 0x005bde30
// TTradeBookView::CreateObject

// SYNTHETIC: IMPERIALISM 0x005bded0
// TTradeBookView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTradeBookView, TView)

// NOOP: verified empty in original 0x005bde65 (no standalone TTradeBookView::TTradeBookView body exists: CreateObject 0x005bde30 inlines this default ctor, calling the TView base ctor directly at that site)
TTradeBookView::TTradeBookView() {}

// FUNCTION: IMPERIALISM 0x005bdef0
void TTradeBookView::DoPostCreate(int arg) {
  TView::DoPostCreate(arg);

  previousPageButton = static_cast<TControl*>(ResolveControlByTag(kControlTagLcor));
  nextPageButton = static_cast<TControl*>(ResolveControlByTag(kControlTagRcor));
  buyPanel = static_cast<TTradePageBuyView*>(ResolveControlByTag(kControlTagTbou));
  sellPanel = static_cast<TTradePageSellView*>(ResolveControlByTag(kControlTagTsol));

  TStaticText* rtilControl = static_cast<TStaticText*>(ResolveControlByTag(kControlTagRtil));
  rtilControl->AssertValid();
  TStaticText* titLControl = static_cast<TStaticText*>(ResolveControlByTag(kControlTagTitL));
  titLControl->AssertValid();

  ApplyUiTextStyleAndThemeFlags(static_cast<TDropShadowText*>(rtilControl), 0, 0x12, 0x2b6b,
                                0x2b6c);
  ApplyUiTextStyleAndThemeFlags(static_cast<TDropShadowText*>(titLControl), 0, 0x12, 0x2b6b,
                                0x2b6c);

  CString quarterText;
  CString formattedText;
  short quarterValue = static_cast<short>(g_pSimMgr->economicTurn / 4 + 0x717);
  formattedText.Format(g_szDecimalFormat, quarterValue);
  g_pSimMgr->GetSeason(&quarterText);

  CString combined;
  combined = quarterText + s_szSpaceSeparator_00695794 + formattedText;
  rtilControl->SetTextAndMaybeRefresh(&combined, 0);
  rtilControl->SetEnabled(1, 1);
}

// FUNCTION: IMPERIALISM 0x005be150
void TTradeBookView::SetItem(short categorySlot) {
  buyPanel->RebuildNationBidRowsForCategory(categorySlot);
  sellPanel->RebuildNationOfferRowsForCategory(categorySlot);

  if (categorySlot != -1) {
    pageCount =
        buyPanel->pageCount > sellPanel->pageCount ? buyPanel->pageCount : sellPanel->pageCount;

    TStaticText* title = static_cast<TStaticText*>(ResolveControlByTag(kControlTagTitL));
    title->AssertValid();

    CString composedTitle;
    CString categoryName;
    CString titleTemplate;
    g_pSimMgr->GetString(0x2741, 3, &titleTemplate);
    g_pSimMgr->GetString(0x2711, categorySlot, &categoryName);
    scanBracketExpressions(g_pSimMgr, &composedTitle, static_cast<LPCSTR>(titleTemplate),
                           static_cast<LPCSTR>(categoryName));
    title->SetTextAndMaybeRefresh(&composedTitle, 0);

    CRect titleBounds;
    title->QueryBounds(&titleBounds);
    InvalidateCityDialogRectRegion(&titleBounds, 1);
  } else {
    pageCount = 0;
  }

  currentPage = 0;
  ShowPage(1);
}

// FUNCTION: IMPERIALISM 0x005be370
void TTradeBookView::DoEvent(int commandId, TEventHandler* sourceHandler, TEvent* event) {
  if (commandId == 0xa) {
    if (sourceHandler->controlTag == kControlTagRcor) {
      ShowPage(currentPage + 1);
    } else if (sourceHandler->controlTag == kControlTagLcor) {
      ShowPage(currentPage - 1);
    }
  }
  TEventHandler::DoEvent(commandId, sourceHandler, event);
}

// FUNCTION: IMPERIALISM 0x005be3e0
void TTradeBookView::ShowPage(int page) {
  previousPageButton->SetState(page != 1, 0);
  previousPageButton->SetEnabled(page != 1, 1);
  bool hasMore = page + 2 <= pageCount;
  nextPageButton->SetState(hasMore, 0);
  nextPageButton->SetEnabled(hasMore, 1);
  buyPanel->ShowPage(static_cast<short>(page));
  sellPanel->ShowPage(static_cast<short>(page));
}
