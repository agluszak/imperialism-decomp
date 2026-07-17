#include "game/TTradePageBuyView.h"

#include "game/TList.h"
#include "game/TSimMgr.h"
#include "game/TTextLine.h"
#include "game/TTradeBidNationLine.h"
#include "game/TTradeMgr.h"
#include "game/global_data_tables.h"
#include "game/quickdraw_rendering.h" // BuildUiTextStyleDescriptor

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
  OrphanCallChain_C4_I18_0056ff90();

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
      TControlPictureRectState headerStyle;
      BuildUiTextStyleDescriptor(&headerStyle, 4, 0xc, 0x2b6a);
      headerRow->SetTextLineStyleDescriptor(&headerStyle);
      field_0x7c->AddTail(headerRow);

      for (short nationSlot = 0; nationSlot < 0x17; ++nationSlot) {
        if (g_pNationInteractionStateManager->IsNationMetricCellNegative(nationSlot,
                                                                         categorySlot)) {
          TTradeBidNationLine* row = new TTradeBidNationLine();
          int rowBounds[2];
          row->SetLineDataRowAndBounds(0, 0, rowBounds);
          row->nationSlot12 = nationSlot;
          row->categorySlot10 = categorySlot;
          field_0x7c->AddTail(row);
        }
      }
    }

    OrphanCallChain_C8_I82_0056fc80();
    OrphanCallChain_C8_I118_0056fdb0(1);
  }

  RefreshControl();
}
