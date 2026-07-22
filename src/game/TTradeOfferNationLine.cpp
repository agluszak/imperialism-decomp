#include "game/TTradeOfferNationLine.h"

#include "game/TSimMgr.h"
#include "game/TTradeMgr.h"
#include "game/TTradeOfferNationView.h"
#include "game/global_data_tables.h"
#include "game/ui_text_label_helpers_decls.h"

// SYNTHETIC: IMPERIALISM 0x005bcf70
// TTradeOfferNationLine::`scalar deleting destructor'
TTradeOfferNationLine::~TTradeOfferNationLine() {}
// SYNTHETIC: IMPERIALISM 0x005bcfc0
// TTradeOfferNationLine::CreateObject

// SYNTHETIC: IMPERIALISM 0x005bd030
// TTradeOfferNationLine::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTradeOfferNationLine, TLineData)

TTradeOfferNationLine::TTradeOfferNationLine() {}

// FUNCTION: IMPERIALISM 0x005bd090
void TTradeOfferNationLine::InstallViews(TView* panel, int* offsetLayout) {
  TTradeOfferNationView* view = new TTradeOfferNationView();
  view->InitializeUiResourceEntryFrameAndParent(panel->resourceContext, panel, offsetLayout,
                                                &field08, 5, 5, 0);
  view->categorySlot60 = categorySlot10;
  view->nationSlot62 = nationSlot12;

  if (g_pNationInteractionStateManager->IsNationMetricCellNegative(
          categorySlot10, g_pSimMgr->GetActiveNationId())) {
    LoadUiStringByGroupAndIndexToControlObject(0x2740, 3, view);
  }
}
