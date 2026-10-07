#include "game/nation_domain_types.h"
#include "game/trade_ui/TTradePageBuyView.h"

#include "game/TList.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_screens/TTextLine.h"
#include "game/trade_ui/TTradeBidNationLine.h"
#include "game/ui_widgets/TTradeMgr.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/quickdraw_rendering.h" // BuildUiTextStyleDescriptor
#include "game/ui_text_label_helpers_decls.h"

// FUNCTION: IMPERIALISM 0x00435610
TTradePageBuyView::TTradePageBuyView() {
  lastBuiltCategorySlot = -1;
}

// FUNCTION: IMPERIALISM 0x00435670
TTradePageBuyView::~TTradePageBuyView() {}

IMPLEMENT_DYNCREATE(TTradePageBuyView, TPageView)

// FUNCTION: IMPERIALISM 0x005bd690
void TTradePageBuyView::SetItem(short categorySlot) {
  if (categorySlot == lastBuiltCategorySlot) {
    return;
  }
  lastBuiltCategorySlot = categorySlot;
  ResetPageLayout();

  if (categorySlot != -1) {
    if (g_pTradeMgr->DidBidOn(categorySlot, g_pSimMgr->GetPlayerCountry()) ||
        g_pTradeMgr->DidOffer(categorySlot, g_pSimMgr->GetPlayerCountry())) {
      TTextLine* headerRow = new TTextLine();
      int headerBounds[2];
      headerBounds[0] = 0x24;
      headerRow->ITextLine(0, 0, headerBounds, 0x2741, 3);
      headerRow->SetTheJustification(1);
      TextStyle headerStyle;
      BuildUiTextStyleDescriptor(&headerStyle, 4, 0xc, 0x2b6a);
      headerRow->SetTextLineStyleDescriptor(&headerStyle);
      orderedEntries->AddTail(headerRow);

      for (short nationSlot = 0; nationSlot < kNationSlotCount; ++nationSlot) {
        if (g_pTradeMgr->DidBidOn(nationSlot, categorySlot)) {
          TTradeBidNationLine* row = new TTradeBidNationLine();
          int rowBounds[2];
          row->ILineData(0, 0, rowBounds);
          row->nationSlot = nationSlot;
          row->categorySlot = categorySlot;
          orderedEntries->AddTail(row);
        }
      }
    }

    BuildPageLayout();
    ShowPage(1);
  }

  RefreshControl();
}
