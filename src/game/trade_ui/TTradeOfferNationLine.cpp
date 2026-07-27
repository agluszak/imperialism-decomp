#include "game/trade_ui/TTradeOfferNationLine.h"

#include "game/ui_screens/TSimMgr.h"
#include "game/ui_widgets/TTradeMgr.h"
#include "game/trade_ui/TTradeOfferNationView.h"
#include "game/globals/prelude.h"
#include "game/globals/shared_globals.h"
#include "game/ui_text_label_helpers_decls.h"

// SYNTHETIC: IMPERIALISM 0x005bcf70
// TTradeOfferNationLine::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x005bcfa0
TTradeOfferNationLine::~TTradeOfferNationLine() {}
// SYNTHETIC: IMPERIALISM 0x005bcfc0
// TTradeOfferNationLine::CreateObject

// SYNTHETIC: IMPERIALISM 0x005bd030
// TTradeOfferNationLine::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTradeOfferNationLine, TLineData)

// FUNCTION: IMPERIALISM 0x005bd050
void TTradeOfferNationLine::ITradeOfferNationLine(short categorySlot, short nationSlot,
                                                  short rowArg, short colArg, int* bounds) {
  SetLineDataRowAndBounds(rowArg, colArg, bounds);
  nationSlot12 = nationSlot;
  categorySlot10 = categorySlot;
}

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
