#include "game/TMiniCivLine.h"

#include "game/TMiniCivView.h"

// SYNTHETIC: IMPERIALISM 0x004ab620
// TMiniCivLine::`scalar deleting destructor'
TMiniCivLine::~TMiniCivLine() {}
// SYNTHETIC: IMPERIALISM 0x004ab670
// TMiniCivLine::CreateObject

// SYNTHETIC: IMPERIALISM 0x004ab6e0
// TMiniCivLine::GetRuntimeClass

IMPLEMENT_DYNCREATE(TMiniCivLine, TLineData)

TMiniCivLine::TMiniCivLine() {}

// FUNCTION: IMPERIALISM 0x004ab740
void TMiniCivLine::CreateLineItemView(TView* panel, int* offsetLayout) {
  TMiniCivView* view = new TMiniCivView();
  view->ConstructTMiniCivViewBaseState(panel, offsetLayout, &field08, civUnit10);
}
