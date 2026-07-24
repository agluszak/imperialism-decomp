#include "game/trade_ui/TTradeBidNationLine.h"

#include "game/trade_ui/TTradeBidNationView.h"

// SYNTHETIC: IMPERIALISM 0x005bd900
// TTradeBidNationLine::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x005bd930
TTradeBidNationLine::~TTradeBidNationLine() {}
// SYNTHETIC: IMPERIALISM 0x005bd950
// TTradeBidNationLine::CreateObject

// SYNTHETIC: IMPERIALISM 0x005bd9c0
// TTradeBidNationLine::GetRuntimeClass

IMPLEMENT_DYNCREATE(TTradeBidNationLine, TLineData)

// NOOP: verified empty in original 0x005bd983 (no standalone TTradeBidNationLine::TTradeBidNationLine body exists: CreateObject 0x005bd950 inlines this default ctor, calling the TLineData base ctor directly at that site)
TTradeBidNationLine::TTradeBidNationLine() {}

// FUNCTION: IMPERIALISM 0x005bda20
void TTradeBidNationLine::InstallViews(TView* panel, int* offsetLayout) {
  TTradeBidNationView* view = new TTradeBidNationView();
  view->InitializeUiResourceEntryFrameAndParent(panel->resourceContext, panel, offsetLayout,
                                                &field08, 5, 5, 0);
  view->categorySlot60 = categorySlot10;
  view->nationSlot62 = nationSlot12;
}
