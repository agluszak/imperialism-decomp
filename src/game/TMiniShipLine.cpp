#include "game/TMiniShipLine.h"

#include "game/TMiniShipView.h"

// SYNTHETIC: IMPERIALISM 0x00569b60
// TMiniShipLine::`scalar deleting destructor'
TMiniShipLine::~TMiniShipLine() {}
// SYNTHETIC: IMPERIALISM 0x00569bb0
// TMiniShipLine::CreateObject

// SYNTHETIC: IMPERIALISM 0x00569c20
// TMiniShipLine::GetRuntimeClass

IMPLEMENT_DYNCREATE(TMiniShipLine, TLineData)

TMiniShipLine::TMiniShipLine() {}

// FUNCTION: IMPERIALISM 0x00569c80
void TMiniShipLine::CreateLineItemView(TView* panel, int* offsetLayout) {
  TMiniShipView* view = new TMiniShipView();
  view->InitializeUiResourceEntryFrameAndParent(nullptr, panel, offsetLayout, &field08, 5, 5, 0);
  view->shipNode84 = field10;
  view->eventNumber60 = 0x22;
}
