#include "game/trade_ui/TTradeBidNationLine.h"

#include "game/trade_ui/TTradeBidNationView.h"

// SYNTHETIC: IMPERIALISM 0x005bd900
// TTradeBidNationLine::`scalar deleting destructor'
TTradeBidNationLine::~TTradeBidNationLine() {}
// SYNTHETIC: IMPERIALISM 0x005bd950
// TTradeBidNationLine::CreateObject

// SYNTHETIC: IMPERIALISM 0x005bd9c0
// TTradeBidNationLine::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTradeBidNationLine, TLineData)

TTradeBidNationLine::TTradeBidNationLine() {}

// FUNCTION: IMPERIALISM 0x005bda20
void TTradeBidNationLine::InstallViews(TView* panel, int* offsetLayout) {
  TTradeBidNationView* view = new TTradeBidNationView();
  view->InitializeUiResourceEntryFrameAndParent(panel->resourceContext, panel, offsetLayout,
                                                &field08, 5, 5, 0);
  view->categorySlot60 = categorySlot10;
  view->nationSlot62 = nationSlot12;
}
