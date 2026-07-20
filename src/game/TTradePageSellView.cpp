#include "game/TTradePageSellView.h"

#include "game/TList.h"
#include "game/TSimMgr.h"
#include "game/TTextLine.h"
#include "game/TTradeMgr.h"
#include "game/TTradeOfferNationLine.h"
#include "game/global_data_tables.h"
#include "game/quickdraw_rendering.h" // BuildUiTextStyleDescriptor
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
  OrphanCallChain_C4_I18_0056ff90();

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
    TUiTextStyleDescriptor headerStyle;
    BuildUiTextStyleDescriptor(&headerStyle, 4, 0xc, 0x2b6a);
    headerRow->SetTextLineStyleDescriptor(&headerStyle);
    field_0x7c->AddTail(headerRow);

    for (short nationSlot = 0x16; nationSlot >= 0; --nationSlot) {
      if (g_pNationInteractionStateManager->IsNationMetricCellPositive(nationSlot, categorySlot)) {
        TTradeOfferNationLine* row = new TTradeOfferNationLine();
        int rowBounds[2];
        row->SetLineDataRowAndBounds(0, 0, rowBounds);
        row->nationSlot12 = nationSlot;
        row->categorySlot10 = categorySlot;
        field_0x7c->AddTail(row);
      }
    }
  } else {
    TTextLine* fallbackHeaderRow = new TTextLine();
    int fallbackBounds[2];
    fallbackBounds[0] = 0x30;
    fallbackHeaderRow->SetTextLineRowBoundsAndStyle(0, 0, fallbackBounds, 0x2741, 5);
    fallbackHeaderRow->SetField1E(1);
    TUiTextStyleDescriptor fallbackStyle;
    BuildUiTextStyleDescriptor(&fallbackStyle, 0, 0xe, 0x2b6a);
    fallbackHeaderRow->SetTextLineStyleDescriptor(&fallbackStyle);
    field_0x7c->AddTail(fallbackHeaderRow);
  }

  OrphanCallChain_C8_I82_0056fc80();
  OrphanCallChain_C8_I118_0056fdb0(1);
  RefreshControl();
}
