#include "game/trade_ui/TTradePageSellView.h"

#include "game/TList.h"
#include "game/ui_screens/TSimMgr.h"
#include "game/ui_screens/TTextLine.h"
#include "game/ui_widgets/TTradeMgr.h"
#include "game/trade_ui/TTradeOfferNationLine.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/ui_core/quickdraw_rendering.h" // BuildUiTextStyleDescriptor
#include "game/ui_text_label_helpers_decls.h"

// SYNTHETIC: IMPERIALISM 0x004355c0
// TTradePageSellView::`scalar deleting destructor'
TTradePageSellView::~TTradePageSellView() {}
// SYNTHETIC: IMPERIALISM 0x005bcb90
// TTradePageSellView::CreateObject

// SYNTHETIC: IMPERIALISM 0x005bcc10
// TTradePageSellView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTradePageSellView, TPageView)

TTradePageSellView::TTradePageSellView() {}

// FUNCTION: IMPERIALISM 0x005bcc30
void TTradePageSellView::RebuildNationOfferRowsForCategory(short categorySlot) {
  if (categorySlot == lastBuiltCategorySlot84) {
    return;
  }
  lastBuiltCategorySlot84 = categorySlot;
  ResetPageLayout();

  bool buildGrid =
      categorySlot != -1 && (g_pNationInteractionStateManager->IsNationMetricCellNegative(
                                 categorySlot, g_pSimMgr->GetActiveNationId()) ||
                             g_pNationInteractionStateManager->IsNationMetricCellPositive(
                                 categorySlot, g_pSimMgr->GetActiveNationId()));

  if (buildGrid) {
    TTextLine* headerRow = new TTextLine();
    int headerBounds[2];
    headerBounds[0] = 0x30;
    headerRow->SetTextLineRowBoundsAndStyle(0, 0, headerBounds, 0x2741, 2);
    headerRow->SetField1E(1);
    TextStyle headerStyle;
    BuildUiTextStyleDescriptor(&headerStyle, 4, 0xc, 0x2b6a);
    headerRow->SetTextLineStyleDescriptor(&headerStyle);
    orderedEntries->AddTail(headerRow);

    for (short nationSlot = 0x16; nationSlot >= 0; --nationSlot) {
      if (g_pNationInteractionStateManager->IsNationMetricCellPositive(nationSlot, categorySlot)) {
        TTradeOfferNationLine* row = new TTradeOfferNationLine();
        int rowBounds[2];
        row->SetLineDataRowAndBounds(0, 0, rowBounds);
        row->nationSlot12 = nationSlot;
        row->categorySlot10 = categorySlot;
        orderedEntries->AddTail(row);
      }
    }
  } else {
    TTextLine* fallbackHeaderRow = new TTextLine();
    int fallbackBounds[2];
    fallbackBounds[0] = 0x30;
    fallbackHeaderRow->SetTextLineRowBoundsAndStyle(0, 0, fallbackBounds, 0x2741, 5);
    fallbackHeaderRow->SetField1E(1);
    TextStyle fallbackStyle;
    BuildUiTextStyleDescriptor(&fallbackStyle, 0, 0xe, 0x2b6a);
    fallbackHeaderRow->SetTextLineStyleDescriptor(&fallbackStyle);
    orderedEntries->AddTail(fallbackHeaderRow);
  }

  BuildPageLayout();
  ShowPage(1);
  RefreshControl();
}
