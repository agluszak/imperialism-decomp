#include "game/TTradePageBuyView.h"

#include "game/TList.h"
#include "game/TSimMgr.h"
#include "game/TTextLine.h"
#include "game/TTradeBidNationLine.h"
#include "game/TTradeMgr.h"
#include "game/global_data_tables.h"
#include "game/quickdraw_rendering.h" // BuildUiTextStyleDescriptor
#include "game/ui_text_label_helpers_decls.h"

// SYNTHETIC: IMPERIALISM 0x00435640
// TTradePageBuyView::`scalar deleting destructor'
TTradePageBuyView::~TTradePageBuyView() {}
// SYNTHETIC: IMPERIALISM 0x005bd5f0
// TTradePageBuyView::CreateObject

// SYNTHETIC: IMPERIALISM 0x005bd670
// TTradePageBuyView::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTradePageBuyView, TPageView)

TTradePageBuyView::TTradePageBuyView() {}

// FUNCTION: IMPERIALISM 0x005bd690
void TTradePageBuyView::RebuildNationBidRowsForCategory(short categorySlot) {
  if (categorySlot == lastBuiltCategorySlot84) {
    return;
  }
  lastBuiltCategorySlot84 = categorySlot;
  ResetPageLayout();

  if (categorySlot != -1) {
    if (g_pNationInteractionStateManager->IsNationMetricCellNegative(
            categorySlot, g_pSimMgr->GetActiveNationId()) ||
        g_pNationInteractionStateManager->IsNationMetricCellPositive(
            categorySlot, g_pSimMgr->GetActiveNationId())) {
      TTextLine* headerRow = new TTextLine();
      int headerBounds[2];
      headerBounds[0] = 0x24;
      headerRow->SetTextLineRowBoundsAndStyle(0, 0, headerBounds, 0x2741, 3);
      headerRow->SetField1E(1);
      TextStyle headerStyle;
      BuildUiTextStyleDescriptor(&headerStyle, 4, 0xc, 0x2b6a);
      headerRow->SetTextLineStyleDescriptor(&headerStyle);
      orderedEntries->AddTail(headerRow);

      for (short nationSlot = 0; nationSlot < 0x17; ++nationSlot) {
        if (g_pNationInteractionStateManager->IsNationMetricCellNegative(nationSlot,
                                                                         categorySlot)) {
          TTradeBidNationLine* row = new TTradeBidNationLine();
          int rowBounds[2];
          row->SetLineDataRowAndBounds(0, 0, rowBounds);
          row->nationSlot12 = nationSlot;
          row->categorySlot10 = categorySlot;
          orderedEntries->AddTail(row);
        }
      }
    }

    BuildPageLayout();
    ShowPage(1);
  }

  RefreshControl();
}
