#include "game/trade_ui/TTradeOfferNationLine.h"

#include "game/ui_screens/TSimMgr.h"
#include "game/ui_widgets/TTradeMgr.h"
#include "game/trade_ui/TTradeOfferNationView.h"
#include "game/globals/global_types.h"
#include "game/globals/shared_globals.h"
#include "game/ui_text_label_helpers_decls.h"

IMPLEMENT_DYNCREATE(TTradeOfferNationLine, TLineData)

// FUNCTION: IMPERIALISM 0x005bd050
void TTradeOfferNationLine::ITradeOfferNationLine(short categorySlot, short nationSlot,
                                                  short rowArg, short colArg, int* bounds) {
  ILineData(rowArg, colArg, bounds);
  this->nationSlot = nationSlot;
  this->categorySlot = categorySlot;
}

// FUNCTION: IMPERIALISM 0x005bd090
void TTradeOfferNationLine::InstallViews(TView* panel, int* offsetLayout) {
  TTradeOfferNationView* view = new TTradeOfferNationView();
  view->InitializeUiResourceEntryFrameAndParent(panel->resourceContext, panel, offsetLayout,
                                                &layoutWidth, 5, 5, 0);
  view->categorySlot = categorySlot;
  view->nationSlot = nationSlot;

  if (g_pTradeMgr->DidBidOn(categorySlot, g_pSimMgr->GetPlayerCountry())) {
    SetControlString(0x2740, 3, view);
  }
}
