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

// FUNCTION: IMPERIALISM 0x00569c40
void TMiniShipLine::IMiniShipLine(short rowArg, short colArg, int* bounds, TShip* item) {
  SetLineDataRowAndBounds(rowArg, colArg, bounds);
  field10 = item;
}

// FUNCTION: IMPERIALISM 0x00569c80
void TMiniShipLine::InstallViews(TView* panel, int* offsetLayout) {
  TMiniShipView* view = new TMiniShipView();
  view->InitializeUiResourceEntryFrameAndParent(nullptr, panel, offsetLayout, &field08, 5, 5, 0);
  view->shipNode84 = field10;
  view->eventNumber60 = 0x22;
}
