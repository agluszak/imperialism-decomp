#include "game/navy_ui/TMiniShipLine.h"

#include "game/navy_ui/TMiniShipView.h"

// SYNTHETIC: IMPERIALISM 0x00569b60
// TMiniShipLine::`scalar deleting destructor'
// FUNCTION: IMPERIALISM 0x00569b90
TMiniShipLine::~TMiniShipLine() {}
// SYNTHETIC: IMPERIALISM 0x00569bb0
// TMiniShipLine::CreateObject

// SYNTHETIC: IMPERIALISM 0x00569c20
// TMiniShipLine::GetRuntimeClass

IMPLEMENT_DYNCREATE(TMiniShipLine, TLineData)

// NOOP: verified empty in original 0x00569be3 (no standalone TMiniShipLine::TMiniShipLine body exists: CreateObject 0x00569bb0 inlines this default ctor, calling the TLineData base ctor directly at that site)
TMiniShipLine::TMiniShipLine() {}

// FUNCTION: IMPERIALISM 0x00569c80
void TMiniShipLine::InstallViews(TView* panel, int* offsetLayout) {
  TMiniShipView* view = new TMiniShipView();
  view->InitializeUiResourceEntryFrameAndParent(nullptr, panel, offsetLayout, &field08, 5, 5, 0);
  view->shipNode84 = field10;
  view->eventNumber60 = 0x22;
}
