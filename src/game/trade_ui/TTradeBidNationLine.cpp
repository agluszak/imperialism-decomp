#include "game/trade_ui/TTradeBidNationLine.h"

#include "game/trade_ui/TTradeBidNationView.h"

// SYNTHETIC: IMPERIALISM 0x005bd900
// TTradeBidNationLine::`scalar deleting destructor'
// SYNTHETIC: IMPERIALISM 0x005bd950
// TTradeBidNationLine::CreateObject

// SYNTHETIC: IMPERIALISM 0x005bd9c0
// TTradeBidNationLine::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTradeBidNationLine, TLineData)

// FUNCTION: IMPERIALISM 0x005bd9e0
void TTradeBidNationLine::ITradeBidNationLine(short categorySlot, short nationSlot, short rowArg,
                                              short colArg, int* bounds) {
  SetLineDataRowAndBounds(rowArg, colArg, bounds);
  this->nationSlot = nationSlot;
  this->categorySlot = categorySlot;
}

// FUNCTION: IMPERIALISM 0x005bda20
void TTradeBidNationLine::InstallViews(TView* panel, int* offsetLayout) {
  TTradeBidNationView* view = new TTradeBidNationView();
  view->InitializeUiResourceEntryFrameAndParent(panel->resourceContext, panel, offsetLayout,
                                                &layoutWidth, 5, 5, 0);
  view->categorySlot = categorySlot;
  view->nationSlot = nationSlot;
}
